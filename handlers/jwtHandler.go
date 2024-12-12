package handlers

import (
	"crypto/sha1"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"server/models"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/lib/pq"
)

// для тестов
var privateKey string = `-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQCEeKZ+5+Nny+hSeaQH0fVZEM9aFjfXdlAedkxZ2WRMwVE/h/H3
/zJNkfJ1PaW2U/P2jQQbeDO0N4ayh2No8N87qK/2fGv5UcwEYLJUtYpIyg+Axb5r
8lW2q4VEWIk9ZnvUMxj/n+K4sbi4QL4sFGX+Rd9iI/opFFia5gZq3Ih0TQIDAQAB
AoGAUSsL+V5kfEj4hPB7jT8csgIWywAqHx8jYEbj6XnGdzFMczz9ChOX4ue2RBgN
3XX7Wep1xc8U/yu2oNVMGBTe8m2JfwXmCyUCyIiSN38/1kb0+tX3BV30Qb+ZM2Ds
prISxE7V3ERmq+ZeQ5ANJWtCA1PIoZ1aXTJawukSJlZn/RECQQDdv3hWTbkFxJ8K
141Gvor3Zv5OB966sBP8ezAnfnbb5NFa95CcltjLQrlDB2D6w4THUArdxBCqrbfR
joiY8UbvAkEAmO7vBKeXKGr3M97OxIHoXZCAj9MkWlfIwcn6HdCCXGywxfXb4sOz
I+DBKbk037N3i30s9MnHPWyh0zsrukFYgwJBAKE//9j6ceZg4ap3rrNYEiPwUFMb
4/pr2kzKo+zESNiEnz0AM7e69fFxFtlIP1x62044xX4YemozIy2O8YQOSB8CQQCY
W2EPmA6FG5tOt6fyKSFfJTiPEGBlCJNeTGO7FCDrBvVNIlR/I0vycFS/xl0gh2CP
PJNvAx5U2UaWc5pqofMVAkAp5lXWLXrzj47S3XY/YGEv5eZV5cZe4jFchH2Ydeip
XUQD8iUUrQNbAfEXOxvify4Knnjsdr+uKcva2bEbq8xD
-----END RSA PRIVATE KEY-----`

var publicKey string = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCEeKZ+5+Nny+hSeaQH0fVZEM9a
FjfXdlAedkxZ2WRMwVE/h/H3/zJNkfJ1PaW2U/P2jQQbeDO0N4ayh2No8N87qK/2
fGv5UcwEYLJUtYpIyg+Axb5r8lW2q4VEWIk9ZnvUMxj/n+K4sbi4QL4sFGX+Rd9i
I/opFFia5gZq3Ih0TQIDAQAB
-----END PUBLIC KEY-----`

const AccessTokenLifeSpanInHours = 1
const RefreshTokenLifeSpanInHours = 10

type JwtHandler struct {
	DB *sql.DB
}

type Tokens struct {
	AccessToken  string
	RefreshToken string
}

type GetTokensBody struct {
	GUID string
}

type JWTClaim struct {
	ip string
	jwt.RegisteredClaims
}

func sendEmail() {
	log.Printf("Email sended")
}

func validateToken(token string) (*JWTClaim, error) {
	parsedToken, err := jwt.ParseWithClaims(token, &JWTClaim{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(publicKey), nil
	})

	fmt.Println(parsedToken.Claims)

	return parsedToken.Claims.(*JWTClaim), err
}

func hashData(data string) string {
	hasher := sha1.New() //можно выбрать другой алгоритм исходя из требований безопасности
	_, err := hasher.Write([]byte(data))

	if err != nil { // переделать на !ok?
		log.Fatalf("Something went wrong while hashing data: %v", err)
	}

	return base64.URLEncoding.EncodeToString(hasher.Sum(nil))
}

func (tokens *Tokens) getTokensHash() string {
	return hashData(tokens.AccessToken + tokens.RefreshToken)
}

func generateTokens(writer http.ResponseWriter, requestIpAddr string) (string, string) {
	writer.Header().Set("Content-Type", "application/json")

	accessToken := getJwt(requestIpAddr, AccessTokenLifeSpanInHours)
	refreshToken := getJwt(requestIpAddr, RefreshTokenLifeSpanInHours)

	tokens := Tokens{accessToken, refreshToken}

	combinedHash := tokens.getTokensHash()
	base64Token := base64.URLEncoding.EncodeToString([]byte(refreshToken))

	accessCookie := &http.Cookie{
		Name:     "accessToken",
		Value:    accessToken,
		Expires:  time.Now().Add(AccessTokenLifeSpanInHours),
		HttpOnly: true,
		//Secure:   true, для https
	}

	http.SetCookie(writer, accessCookie)

	refreshCookie := &http.Cookie{
		Name:     "refreshToken",
		Value:    base64Token,
		Expires:  time.Now().Add(AccessTokenLifeSpanInHours),
		HttpOnly: true,
		//Secure:   true, для https
	}

	http.SetCookie(writer, refreshCookie)

	return base64Token, combinedHash
}

func (handler *JwtHandler) GetTokens(writer http.ResponseWriter, request *http.Request) {
	var requestIpAddr string

	accessCookie, err := request.Cookie("accessToken")

	if err != nil {
		requestIpAddr = request.Header.Get("X-Forwarded-For") //помним что пользователь может установить любой ip тут
	} else {
		validateToken(accessCookie.Value)
	}

	body := GetTokensBody{}
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&body)

	if err != nil {
		log.Fatalf("Something went wrong: %v", err) //переделать фаталы на респонсы
	}

	user := models.User{}
	row := handler.DB.QueryRow(`SELECT * FROM "Users" WHERE "Users"."GUID" = $1`, body.GUID)
	err = row.Scan(&user.GUID, &user.RefreshToken, &user.CombinedTokensHash, &user.IpHash, &user.Email)

	if err != nil {
		if err == sql.ErrNoRows {
			log.Fatalf("User with such GUID not found")
		}

		log.Fatalf("Something went wrong while sql request: %v", err)
	}

	currIpHash := hashData(requestIpAddr)

	if user.IpHash != "" && currIpHash != user.IpHash && user.Email != "" {
		go sendEmail()
	}

	refreshToken, combinedTokensHash := generateTokens(writer, requestIpAddr)

	_, err = handler.DB.Exec(`UPDATE "Users" SET
		"RefreshToken" = $1,
		"CombinedTokensHash" = $2,
		"IpHash" = $3
		WHERE "GUID" = $4`, refreshToken, combinedTokensHash, currIpHash, user.GUID)

	if err != nil {
		log.Fatalf("Something went wrong while sql request: %v", err)
	}
}

func (handler *JwtHandler) RefreshTokens(writer http.ResponseWriter, request *http.Request) {
	tokens := Tokens{}

	decoder := json.NewDecoder(request.Body) //в тз сказано про пару токенов, хотя зачем нам тут access непонятно
	decoder.DisallowUnknownFields()
	decodeErr := decoder.Decode(&tokens)

	if decodeErr != nil {
		log.Fatalf("Something went wrong: %v", decodeErr) //переделать фаталы на респонсы
	}

	decodedToken, err := base64.URLEncoding.DecodeString(tokens.RefreshToken)

	if err != nil {
		log.Fatalf("Something went wrong: %v", err) //переделать фаталы на респонсы
	}

	_, err1 := validateToken(string(decodedToken))

	if err1 != nil {
		log.Fatalf("Something went wrong: %v", err1) //переделать фаталы на респонсы
	}

	// + читаем из базы, сравниваем с хэшем, выкидываем ошибку или выдаем новые токены

	requestIpAddr := request.Header.Get("X-Forwarded-For") //можно ли переделать

	generateTokens(writer, requestIpAddr)
}

func getJwt(requestIpAddr string, hours int) string {
	block, _ := pem.Decode([]byte(privateKey))
	key, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

	expirationTime := jwt.NewNumericDate(time.Now().Add(time.Hour * time.Duration(hours)))

	claims := &JWTClaim{
		ip: requestIpAddr,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: expirationTime,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)

	result, err := token.SignedString(key)

	if err != nil {
		log.Fatalf("Error while generating accessToken: %v", err)
	}

	return result
}
