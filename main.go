package main

import (
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"

	"database/sql"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/dgrijalva/jwt-go"

	"context"

	"github.com/go-redis/redis/v8"
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

var ctx = context.Background()

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
	_, err = client.Ping(ctx).Result()
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
	var rrn1 = r.FormValue("rrn1")
	var rrn2 = r.FormValue("rrn2")

	fmt.Println(rrn1)
	fmt.Println(rrn2)

	var emailInDB string

	// DB에 해당 계정이 없다면 유저 생성
	err := db.QueryRow("select email from UserInfo where email = ?", email).Scan(&emailInDB)
	if err != nil {

		if err == sql.ErrNoRows {
			err := db.QueryRow("insert into UserInfo(name, email, password, rrn1, rrn2) values(?, ?, ?, ?, ?)", name, email, password, rrn1, rrn2)
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

	errAccess := client.Set(ctx, td.AccessUuid, email, at.Sub(now)).Err()
	if errAccess != nil {
		return errAccess
	}
	errRefresh := client.Set(ctx, td.RefreshUuid, email, rt.Sub(now)).Err()
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

	errAccess := client.Set(ctx, td.AccessUuid, email, at.Sub(now)).Err()
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
	email, err := client.Get(ctx, authD.uuid).Result()
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
	var rrn1 string

	// DB에 해당 계정이 없다면 유저 생성
	err = db.QueryRow("select name, rrn1 from UserInfo where email = ?", ad.email).Scan(&name, &rrn1)
	if err != nil {
		fmt.Println(err)
	}

	user := map[string]string{"email": ad.email, "name": name, "rrn1": rrn1}

	rd.JSON(w, http.StatusOK, user)
}

func DeleteAuth(givenUuid string) (int64, error) {
	deleted, err := client.Del(ctx, givenUuid).Result()
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

func getEmail(w http.ResponseWriter, r *http.Request) {
	cors(w)
	name := r.FormValue("name")
	rrn1 := r.FormValue("rrn1")
	rrn2 := r.FormValue("rrn2")

	var email string

	err := db.QueryRow("select email from UserInfo where name = ? and rrn1 = ? and rrn2 = ?", name, rrn1, rrn2).Scan(&email)
	if err != nil {
		fmt.Println(err)
		// 해당 이메일이 없다면 오류 전송
		rd.JSON(w, http.StatusBadRequest, "no email")
	} else {
		// 해당 이메일이 있다면 그대로 전송
		fmt.Println("get email")
		rd.JSON(w, http.StatusOK, email)
	}

}

const (
	// Gmail SMTP Server
	GoogleSMTPServer = "smtp.gmail.com"
)

type smtpSender struct {
	senderEmail string
	password    string
}

func NewSender(senderEmail string, password string) smtpSender {
	return smtpSender{senderEmail: senderEmail, password: password}
}

func (sender *smtpSender) SendMail(Dest []string, Subject string, Message string) error {
	msg := "From: " + sender.senderEmail + "\n" +
		"To: " + strings.Join(Dest, ",") + "\n" +
		"Subject: " + Subject + "\n" + Message

	err := smtp.SendMail(GoogleSMTPServer+":587",
		smtp.PlainAuth("", sender.senderEmail, sender.password, GoogleSMTPServer),
		sender.senderEmail, Dest, []byte(msg))

	if err != nil {
		fmt.Printf("smtp error: %s", err)
		return err
	}

	fmt.Println("Mail sent successfully!")
	return nil
}

var code int

func sendEmailToUser(w http.ResponseWriter, r *http.Request) {
	cors(w)

	senderEmail := os.Getenv("SENDER_EMAIL")
	password := os.Getenv("SENDER_PASSWORD")

	email := r.FormValue("email")
	rrn1 := r.FormValue("rrn1")
	rrn2 := r.FormValue("rrn2")

	var rrn1FromDB string
	var rrn2FromDB string

	// 데이터베이스에서 해당 이메일에 대한 주민등록번호가 일치하면 해당 이메일로 인증코드를 전송한다.
	err := db.QueryRow("select rrn1, rrn2 from UserInfo where email = ?", email).Scan(&rrn1FromDB, &rrn2FromDB)
	if err != nil {
		fmt.Println(err)
		rd.JSON(w, http.StatusBadRequest, "존재하지 않은 이메일입니다.")
	} else {
		if rrn1FromDB == rrn1 && rrn2FromDB == rrn2 {
			// 일치할 때 -> 인증코드 전송

			// 난수코드 생성해서 제한시간 3분으로 레디스에 저장
			code = rand.Intn(1000000)
			// 이메일을 키로해서 저장
			errAccess := client.Set(ctx, email, code, time.Unix(time.Now().Add(time.Minute*2).Unix(), 0).Sub(time.Now())).Err()
			if errAccess != nil {
				fmt.Println(errAccess)
			}

			//난수코드를 메일로 전송
			receiver := []string{email}
			subject := "OPENIT 인증코드"
			message := code

			smtpSender := NewSender(senderEmail, password)
			if err := smtpSender.SendMail(receiver, subject, strconv.Itoa(message)); err != nil {
				fmt.Println("smtp send error: ", err)
				rd.JSON(w, http.StatusInternalServerError, "메일을 발송하는 데 오류가 발생하였습니다.")
			} else {
				fmt.Println("smtp send ok")
				rd.JSON(w, http.StatusOK, "해당 메일로 인증코드가 전송되었습니다.")
			}
		} else {
			rd.JSON(w, http.StatusBadRequest, "주민등록번호가 일치하지 않습니다. ")
		}
	}

}

func verifyCode(w http.ResponseWriter, r *http.Request) {
	cors(w)

	code := r.FormValue("code")
	email := r.FormValue("email")
	fmt.Println(email)

	codeFromRedis, err := client.Get(ctx, email).Result()
	if err != nil {
		// 인증코드가 만료된 경우
		fmt.Println(err)
		rd.JSON(w, http.StatusBadRequest, "인증코드가 만료되었습니다.")
	} else {
		// 클라이언트가 입력한 인증코드와 redis의 인증코드가 일치하는지 확인
		if code == codeFromRedis {
			// 일치
			rd.JSON(w, http.StatusOK, "인증코드가 일치합니다.")
		} else {
			// 다를 때
			rd.JSON(w, http.StatusBadRequest, "인증코드가 일치하지 않습니다.")
		}
	}

}

func setPassword(w http.ResponseWriter, r *http.Request) {
	cors(w)

	password := r.FormValue("password")
	email := r.FormValue("email")

	fmt.Println(password, email)

	err := db.QueryRow("update UserInfo set password = ? where email = ?", password, email).Err()
	if err != nil {
		fmt.Println(err)
		rd.JSON(w, http.StatusInternalServerError, "서버 내부 에러로 비밀번호를 재설정할 수 없습니다.")
	} else {
		rd.JSON(w, http.StatusOK, "비밀번호가 변경되었습니다.")
	}
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

	mux.Post("/get_email", getEmail)
	mux.Post("/send_email_to_user", sendEmailToUser)
	mux.Post("/verify_code", verifyCode)
	mux.Post("/set_password", setPassword)

	http.ListenAndServe(":3001", n)
}
