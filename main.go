package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"database/sql"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/pat"
	"github.com/joho/godotenv"
	"github.com/twinj/uuid"
	"github.com/unrolled/render"
	"github.com/urfave/negroni"
)

var rd *render.Render

var db *sql.DB

var client *redis.Client

type TokenDetails struct {
	AccessToken  string
	RefreshToken string
	AccessUuid   string
	RefreshUuid  string
	AtExpires    int64
	RtExpires    int64
}

// Redis 클라이언트는 init()함수에서 초기화 합니다. 이렇게 하면 main.go 파일을 실행할 때마다 redis가 연결됩니다.
func init() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal(err)
	}

	//Initializing redis
	dsn := os.Getenv("REDIS_DSN")
	if len(dsn) == 0 {
		dsn = "localhost:6379"
	}
	client = redis.NewClient(&redis.Options{
		Addr:     dsn,
		Password: os.Getenv("REDIS_PASSWORD"),
	})
	_, err = client.Ping().Result()
	if err != nil {
		panic(err)
	}
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	cors(w)
	fmt.Fprint(w, "Hello World")
}

func cors(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
}

func makeUser(w http.ResponseWriter, r *http.Request) {
	cors(w)

	var name = r.FormValue("name")
	var email = r.FormValue("email")
	var password = r.FormValue("password")

	var emailInDB string

	// DB에 해당 계정이 없다면 유저 생성
	err := db.QueryRow("select email from UserInfo where email = ?", email).Scan(&emailInDB)
	if err != nil {

		if err == sql.ErrNoRows {
			err := db.QueryRow("insert into UserInfo(name, email, password) values(?, ?, ?)", name, email, password)
			if err != nil {
				fmt.Println(err)
			}
			rd.JSON(w, http.StatusOK, "success")
		} else {
			fmt.Println(err)
		}
	} else {
		rd.JSON(w, http.StatusOK, "fail")
	}
}

func login(w http.ResponseWriter, r *http.Request) {
	cors(w)
	var email = r.FormValue("email")
	var password = r.FormValue("password")

	var emailInDB string
	var passwordInDB string

	// DB에 해당 계정이 없다면 유저 생성
	err := db.QueryRow("select email, password from UserInfo where email = ?", email).Scan(&emailInDB, &passwordInDB)
	if err != nil {
		// DB에 해당 이메일이 없으면 클라이언트에게 해당 이메일이 존재하지 않음을 알림
		if err == sql.ErrNoRows {
			rd.JSON(w, http.StatusOK, "wrong email")
		} else {
			fmt.Println(err)
		}
	} else {
		// DB에 해당 이메일이 있으면 비밀번호 비교
		if passwordInDB == password {
			// 로그인 성공 -> jwt 생성하여
			token, err := CreateToken(email)
			if err != nil {
				rd.JSON(w, http.StatusUnprocessableEntity, err.Error())
				return
			}
			saveErr := CreateAuth(email, token)
			if saveErr != nil {
				rd.JSON(w, http.StatusUnprocessableEntity, saveErr.Error())
			}

			tokens := map[string]string{
				"access_token":  token.AccessToken,
				"refresh_token": token.RefreshToken,
			}
			rd.JSON(w, http.StatusOK, tokens)
		} else {
			rd.JSON(w, http.StatusOK, "wrong password")
		}
	}
}

func CreateToken(email string) (*TokenDetails, error) {
	td := &TokenDetails{}
	td.AtExpires = time.Now().Add(time.Minute * 1).Unix()
	td.AccessUuid = uuid.NewV4().String()

	td.RtExpires = time.Now().Add(time.Hour * 24 * 7).Unix()
	td.RefreshUuid = uuid.NewV4().String()

	var err error
	//Creating Access Token

	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["access_uuid"] = td.AccessUuid
	atClaims["email"] = email
	atClaims["exp"] = td.AtExpires
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	td.AccessToken, err = at.SignedString([]byte(os.Getenv("ACCESS_SECRET")))
	if err != nil {
		return nil, err
	}
	//Creating Refresh Token

	rtClaims := jwt.MapClaims{}
	rtClaims["authorized"] = true
	rtClaims["refresh_uuid"] = td.RefreshUuid
	rtClaims["email"] = email
	rtClaims["exp"] = td.RtExpires
	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)
	td.RefreshToken, err = rt.SignedString([]byte(os.Getenv("REFRESH_SECRET")))
	if err != nil {
		return nil, err
	}
	return td, nil
}

// JWT 매타데이터를 저장
func CreateAuth(email string, td *TokenDetails) error {
	at := time.Unix(td.AtExpires, 0) //converting Unix to UTC
	rt := time.Unix(td.RtExpires, 0)
	now := time.Now()

	errAccess := client.Set(td.AccessUuid, email, at.Sub(now)).Err()
	if errAccess != nil {
		return errAccess
	}
	errRefresh := client.Set(td.RefreshUuid, email, rt.Sub(now)).Err()
	if errRefresh != nil {
		return errRefresh
	}
	return nil
}

// 유저 토큰 인증 및 액세스 토큰 재발급
func accessAuth(w http.ResponseWriter, r *http.Request) {
	cors(w)

	// 액세스 토큰 검증
	err := TokenValid(r.FormValue("access_token"), r, "access")
	if err != nil {
		// 액세스 토큰이 만료된 경우
		// 리프레쉬 토큰 요청
		rd.JSON(w, http.StatusOK, "expired")

	} else {
		// 액세스 토큰이 유효한 경우
		rd.JSON(w, http.StatusOK, "good")
	}
}

func refreshAuth(w http.ResponseWriter, r *http.Request) {
	cors(w)
	err := TokenValid(r.FormValue("refresh_token"), r, "refresh")
	if err != nil {
		// 리프레쉬 토큰도 만료된 경우 -> 재 로그인 필요
		fmt.Println(err)
		rd.JSON(w, http.StatusOK, "you need to login")
	} else {
		// 리프레쉬 토큰은 살아있는 경우 -> 액세스 토큰 재발급
		fmt.Println("액세스 토큰이 재발급 됩니다.")
		// 리프레쉬 토큰에서 이메일 및 uuid 추출
		ad, err := ExtractTokenMetadata(r.FormValue("refresh_token"), r, "refresh")
		if err != nil {
			fmt.Println(err)
		}
		// 추출된 uuid로 redis에서 이메일 가져와서 토큰의 이메일과 비교
		emailFromRedis, err := FetchAuth(ad)
		if err != nil {
			fmt.Println(err)
		}

		if ad.email == emailFromRedis {
			// 같다면 액세스 토큰 재발급
			td, err := CreatAccessToken(emailFromRedis)
			if err != nil {
				fmt.Println(err)
			}
			// 액세스 토큰 redis에 저장
			err = SaveAccessToken(emailFromRedis, td)
			if err != nil {
				fmt.Println(err)
			}
			// 클라이언트에게 액세스 토큰 재전송
			rd.JSON(w, http.StatusOK, td.AccessToken)
		} else {
			rd.JSON(w, http.StatusOK, "interner server error: email and emailFromRedis is not same")

		}

	}
}

// 액세스 토큰 재발급
func CreatAccessToken(email string) (*TokenDetails, error) {
	td := &TokenDetails{}
	td.AtExpires = time.Now().Add(time.Minute * 1).Unix()
	td.AccessUuid = uuid.NewV4().String()

	var err error
	//Creating Access Token

	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["access_uuid"] = td.AccessUuid
	atClaims["email"] = email
	atClaims["exp"] = td.AtExpires
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	td.AccessToken, err = at.SignedString([]byte(os.Getenv("ACCESS_SECRET")))
	if err != nil {
		return nil, err
	}

	return td, nil
}

func SaveAccessToken(email string, td *TokenDetails) error {
	at := time.Unix(td.AtExpires, 0) //converting Unix to UTC
	now := time.Now()

	errAccess := client.Set(td.AccessUuid, email, at.Sub(now)).Err()
	if errAccess != nil {
		return errAccess
	}
	return nil
}

// 토큰 검증
func VerifyToken(tokenString string, r *http.Request, tokenKind string) (*jwt.Token, error) {

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		//Make sure that the token method conform to "SigningMethodHMAC"
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		if tokenKind == "refresh" {
			return []byte(os.Getenv("REFRESH_SECRET")), nil
		} else {
			return []byte(os.Getenv("ACCESS_SECRET")), nil
		}

	})

	if err != nil {
		return nil, err
	}
	return token, nil
}

// 토큰 만료 여부 검사
func TokenValid(tokenString string, r *http.Request, tokenKind string) error {
	token, err := VerifyToken(tokenString, r, tokenKind)
	if err != nil {
		return err
	}
	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		return err
	}
	return nil
}

type AccessDetails struct {
	uuid  string
	email string
}

// Redis 저장소에서 조회할 토큰 메타데이터를 추출
func ExtractTokenMetadata(tokenString string, r *http.Request, tokenKind string) (*AccessDetails, error) {
	token, err := VerifyToken(tokenString, r, tokenKind)
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)

	if ok && token.Valid {
		var uuid string

		if tokenKind == "access" {
			uuid, ok = claims["access_uuid"].(string)
			if !ok {
				return nil, err
			}
		} else {
			uuid, ok = claims["refresh_uuid"].(string)
			if !ok {
				return nil, err
			}
		}

		email, ok := claims["email"].(string)
		if !ok {
			return nil, err
		}
		return &AccessDetails{
			uuid:  uuid,
			email: email,
		}, nil
	}
	return nil, err
}

// 토큰에 저장된 uuid를 Redis에서 찾기
func FetchAuth(authD *AccessDetails) (string, error) {
	email, err := client.Get(authD.uuid).Result()
	if err != nil {
		return "", err
	}

	return email, nil
}

func userInfo(w http.ResponseWriter, r *http.Request) {
	cors(w)
	access_token := r.FormValue("access_token")
	ad, err := ExtractTokenMetadata(access_token, r, "access")

	if err != nil {
		fmt.Println(err)
	}

	var name string

	// DB에 해당 계정이 없다면 유저 생성
	err = db.QueryRow("select name from UserInfo where email = ?", ad.email).Scan(&name)
	if err != nil {
		fmt.Println(err)
	}

	user := map[string]string{"email": ad.email, "name": name}

	rd.JSON(w, http.StatusOK, user)
}

func DeleteAuth(givenUuid string) (int64, error) {
	deleted, err := client.Del(givenUuid).Result()
	if err != nil {
		return 0, err
	}
	return deleted, nil
}

func logout(w http.ResponseWriter, r *http.Request) {
	cors(w)
	refreshToken := r.FormValue("refresh_token")

	ad, err := ExtractTokenMetadata(refreshToken, r, "refresh")

	if err != nil {
		rd.JSON(w, http.StatusBadRequest, "인증되지 않은 상태입니다")
	}

	deleted, delErr := DeleteAuth(ad.uuid)
	if delErr != nil || deleted == 0 {
		rd.JSON(w, http.StatusUnauthorized, "인증되지 않은 상태입니다")
		return
	}
	rd.JSON(w, http.StatusOK, "로그아웃 성공")
}

func main() {
	// .env 파일에서 환경변수 불러오기 - 시크릿 키 보안을 위함.
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal(err)
	}

	rd = render.New()
	mux := pat.New()
	n := negroni.Classic()
	n.UseHandler(mux)

	// mysql 연결
	db, _ = sql.Open("mysql", "root:Digital73@@tcp(127.0.0.1:3306)/User")

	defer db.Close()

	mux.HandleFunc("/", indexHandler)
	mux.Post("/make_user", makeUser)
	mux.Post("/login", login)
	mux.Post("/logout", logout)
	// 토큰 검증 및 재발급을 위한 api
	mux.Post("/access_auth", accessAuth)
	mux.Post("/refresh_auth", refreshAuth)
	mux.Post("/user_info", userInfo)

	http.ListenAndServe(":3001", n)
}
