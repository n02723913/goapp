// Mobile  App Server
// the following commands are required to run this script
//go get github.com/gorilla/mux
//go get github.com/gorilla/mux
//go get github.com/gorilla/context
//go get github.com/mitchellh/mapstructure
//go get github.com/dgrijalva/jwt-go
//go get github.com/go-sql-driver/mysql
//go get golang.org/x/crypto/bcrypt
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
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

type UserLogin struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type JwtToken struct {
    Token string `json:"token"`
}

type Exception struct {
    Message string `json:"message"`
}

func initCustomDB(username string, password string, ip string, dbname string) {
	var err error
	//"admin:admin@tcp(127.0.0.1:3306)/"
	db, err = sql.Open("mysql", username + ":" + password + "@tcp(" + ip + ":3306)/" + dbname)
	if err != nil {
		panic(err.Error())
	}

	err = db.Ping()
	if err != nil {
		fmt.Println("\tCreating Database...")

		db, err = sql.Open("mysql", username + ":" + password + "@tcp(" + ip + ":3306)/")
		if err != nil {
			panic(err.Error())
		}

		_,err = db.Exec("CREATE DATABASE "+dbname)
		if err != nil {
			panic(err)
		}
		_,err = db.Exec("USE " + dbname)
		if err != nil {
			panic(err)
		}

		_,err = db.Exec("CREATE TABLE accounts ( id INT NOT NULL AUTO_INCREMENT, username VARCHAR(32) NOT NULL, email VARCHAR(64) NOT NULL, password VARCHAR(128) NOT NULL, created DATETIME, PRIMARY KEY (id), UNIQUE(email))")
		if err != nil {
			panic(err)
		}
		
		_,err = bd.Exec("CREATE TABLE profile (id INT NOT NULL AUTO_INCREMENT, Profile_id INT , name VARCHAR(32))")
		if err != nil {
			panic(err)
		}
		
		
	}
	fmt.Println("INIT Database Success")
}

func signupAPI(w http.ResponseWriter, req * http.Request ){
	fmt.Println("SIGNUP API Handler running...")

	var newuser UserRegistration
	var isCopy bool
	jsonErr :=json.NewDecoder(req.Body).Decode(&newuser)
	
	if jsonErr != nil {
		panic(jsonErr)
	}

	fmt.Println("\t Decoded JSON")
	fmt.Println("\t Checking if user exist: " + newuser.Email)

	checkErr := db.QueryRow("SELECT IF(COUNT(*),'true','false') FROM accounts WHERE email = ?", newuser.Email).Scan(&isCopy)

	if checkErr != nil {
		panic(checkErr)
	}

	fmt.Println("\tisCopy: ", isCopy)
	//Username is available
	if isCopy == false {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newuser.Password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		creationTime := time.Now().UTC()
		_, err = db.Exec("INSERT INTO accounts(username, password, email, created) VALUES(?, ?, ?, ?)", newuser.Username, hashedPassword, newuser.Email, creationTime)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		fmt.Println("\tSIGNUP API Handler successful")
		w.WriteHeader(http.StatusOK)
		return
	}

	http.Error(w,"email taken", http.StatusForbidden)
}

func loginAPI(w http.ResponseWriter, req * http.Request ){
	fmt.Println("LOGIN API Handler running...")
	var user UserLogin
	_=json.NewDecoder(req.Body).Decode(&user)
	var databaseEmail string
	var databasePassword string
	var databaseiId int
	var databaseName string
	var confirm string

	err := db.QueryRow("SELECT email, password, id, username  FROM accounts WHERE email=?", user.Email).Scan(&databaseEmail, &databasePassword, &databaseId, &databaseName)
	if err != nil {
		http.Redirect(w, req, "/login", 301)
		return
	}
	_, err = db.Exec("SELECT id FROM accounts WHERE profile_id=?", id),Scan(&confirm)
	if confirm == nil {
		_, err = db.Exec("INSERT INTO profile (profile_id, name) VALUES(?, ?)", id, "")
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
	}

	

	//validate the password
	err = bcrypt.CompareHashAndPassword([]byte(databasePassword), []byte(user.Password))
	//if the password is wrong
	if err != nil {
		http.Redirect(w, req, "/login", 301)
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username":user.Email,
		"password":user.Password,
		"exp":time.Now().Add(time.Hour * 72).Unix(),
	})

	tokenString, error := token.SignedString([]byte("secret"))

	if error != nil {
		fmt.Println(error)
	}

	fmt.Println("\tLOGIN API Handler successful")
	json.NewEncoder(w).Encode(JwtToken{Token: tokenString})
}

func ValidateTokenMiddleware( next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request){
		fmt.Println("Validate Token API Handler running...")
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
						fmt.Println("\tValidate Token API successful")
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

    fmt.Println("Starting the application...")
	initCustomDB("root","jukjukY1", "127.0.0.1", "test")
	defer db.Close()

	fmt.Println("Starting Router")
	router := mux.NewRouter()
	router.HandleFunc("/login", loginAPI).Methods("POST")
	router.HandleFunc("/signup", signupAPI).Methods("POST")
	router.HandleFunc("/updateProfile", ValidateTokenMiddleware(UpdateProfileAPI)).Methods("POST")
	router.HandleFunc("/profile/{user}", ValidateTokenMiddleware(LookupUserAPI)).Methods("GET")
	router.HandleFunc("/match", ValidateTokenMiddleware(MatchesAPI)).Methods("GET")
	log.Fatal(http.ListenAndServe(":5050", router))
}
