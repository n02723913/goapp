package main

import "encoding/json"
import "net/http"
import "net/http/httputil"
import "database/sql"
import _"github.com/go-sql-driver/mysql"
import "github.com/dgrijalva/jwt-go"
import "github.com/gorilla/context"
import "github.com/gorilla/mux"
import "golang.org/x/crypto/bcrypt"
import "strings"
import "fmt"
import "time"
import "log"

var db *sql.DB

type UserRegistration struct {
	username string `json:"username"`
	password string `json:"password"`
	email    string `json:"email"`
}

type UserLogin struct {
	email    string `json:"email"`
	password string `json:"password"`
}

type JwtToken struct {
    Token string `json:"token"`
}

type Exception struct {
    Message string `json:"message"`
}

func initCustomDB(username string, password string, ip string, dbname string) {
	//"admin:admin@tcp(127.0.0.1:3306)/"
	db, err := sql.Open("mysql", username + ":" + password + "@tcp(" + ip + ":3306)/" + dbname)
	if err != nil {
		panic(err.Error())
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		_,err = db.Exec("CREATE DATABASE "+dbname)
		if err != nil {
			panic(err)
		}
		_,err = db.Exec("USE " + dbname)
		if err != nil {
			panic(err)
		}

		_,err = db.Exec("CREATE TABLE accounts ( id INT NOT NULL AUTO_INCREMENT, username VARCHAR(32) NOT NULL UNIQUE, email VARCHAR(64) NOT NULL UNIQUE, password VARCHAR(128) NOT NULL, created DATETIME, PRIMARY KEY id, UNIQUE KEY email (email))")
		if err != nil {
			panic(err)
		}
	}
	fmt.Printf("INIT Database Success\n\n")
}

func signupAPI(w http.ResponseWriter, req * http.Request ){
	var newuser UserRegistration
	var count   int
	_=json.NewDecoder(req.Body).Decode(&newuser)
	
	rows, _ := db.Query("SELECT COUNT(*) FROM accounts WHERE email=?", newuser.email)
	rows.Scan(&count)
		//Username is available
	if count > 0 {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newuser.password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		creationTime := time.Now().UTC()
		_, err = db.Exec("INSERT INTO accounts(username, password, email, created) VALUES(?, ?)", newuser.username, hashedPassword, newuser.email, creationTime)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}

	http.Error(w,"email taken", http.StatusForbidden)
}

func loginAPI(w http.ResponseWriter, req * http.Request ){
	var user UserLogin
	_=json.NewDecoder(req.Body).Decode(&user)
	var databaseEmail string
	var databasePassword string

	err := db.QueryRow("SELECT email, password FROM accounts WHERE email=?", user.email).Scan(databaseEmail, databasePassword)
	if err != nil {
		http.Redirect(w, req, "/login", 301)
		return
	}

	//validate the password
	err = bcrypt.CompareHashAndPassword([]byte(databasePassword), []byte(user.password))
	//if the password is wrong
	if err != nil {
		http.Redirect(w, req, "/login", 301)
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username":user.email,
		"password":user.password,
		"exp":time.Now().Add(time.Hour * 72).Unix(),
	})

	tokenString, error := token.SignedString([]byte("secret"))

	if error != nil {
		fmt.Println(error)
	}

	json.NewEncoder(w).Encode(JwtToken{Token: tokenString})
}

func ValidateTokenMiddleware( next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request){
			authorizationHeader := req.Header.Get("authorization")
			if authorizationHeader != "" {
				bearerToken := strings.Split(authorizationHeader, " ")
				if len(bearerToken) == 3 {
						token, error := jwt.Parse(bearerToken[1], func(token *jwt.Token) (interface{}, error) {
						if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
								return nil, fmt.Errorf("There was an error")
						}
						return []byte("secret"), nil
					})
					if error != nil {
							json.NewEncoder(w).Encode(Exception{Message: error.Error()})
							return
					}
					if token.Valid {
							context.Set(req, "decoded", token.Claims)
							next(w, req)
					} else {
							json.NewEncoder(w).Encode(Exception{Message: "Invalid authorization token"})
					}
				}
			} else {
				json.NewEncoder(w).Encode(Exception{Message: "An authorization header is required"})
			}
	})
}

func DumpReqAPI(req * http.Request ){
	reqDump, err := httputil.DumpRequest(req, true)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(string(reqDump))
}

func UpdateProfileAPI(w http.ResponseWriter, req * http.Request ){
	DumpReqAPI(req)
}

func MatchesAPI(w http.ResponseWriter, req * http.Request ){
	DumpReqAPI(req)
}

func LookupUserAPI(w http.ResponseWriter, req * http.Request ){
	DumpReqAPI(req)
}

func main() {
	router := mux.NewRouter()
	fmt.Println("Starting the application...")
	router.HandleFunc("/login", loginAPI).Methods("POST")
	router.HandleFunc("/signup", signupAPI).Methods("POST")
	router.HandleFunc("/updateProfile", ValidateTokenMiddleware(UpdateProfileAPI)).Methods("POST")
	router.HandleFunc("/profile/{user}", ValidateTokenMiddleware(LookupUserAPI)).Methods("GET")
	router.HandleFunc("/match", ValidateTokenMiddleware(MatchesAPI)).Methods("GET")
	log.Fatal(http.ListenAndServe(":5050", router))
}