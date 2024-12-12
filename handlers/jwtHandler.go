package handlers

import (
	"crypto/sha1"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"log"
	"net/http"
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

func (tokens *Tokens) getTokensHash() string {
	hasher := sha1.New() //можно выбрать другой алгоритм исходя из требований безопасности
	hasher.Write([]byte(tokens.AccessToken + tokens.RefreshToken))

	return string(hasher.Sum(nil))
}

func (handler *JwtHandler) GetTokens(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "application/json")

	//requestIpAddr := request.RemoteAddr //loopback
	requestIpAddr := request.Header.Get("X-Forwarded-For") //пользователь может установить любой header

	//тут проверка на ip из базы, вынести в отдельную горутину

	accessToken := getJwt(requestIpAddr, AccessTokenLifeSpanInHours)
	refreshToken := getJwt(requestIpAddr, RefreshTokenLifeSpanInHours)

	tokens := Tokens{accessToken, refreshToken}

	coupledHash := tokens.getTokensHash() // + запись в бд
	log.Printf("%x", coupledHash)

	base64Token := base64.URLEncoding.EncodeToString([]byte(refreshToken)) // + запись в бд

	responseBody := Tokens{accessToken, base64Token}

	json.NewEncoder(writer).Encode(responseBody)
}

func (handler *JwtHandler) RefreshTokens(writer http.ResponseWriter, request *http.Request) {
	var tokens Tokens

	decoder := json.NewDecoder(request.Body) //в тз сказано про пару токенов, хотя зачем нам тут access непонятно
	decoder.DisallowUnknownFields()
	decodeErr := decoder.Decode(&tokens)

	if decodeErr != nil {
		log.Fatalf("Something went wrong: %v", decodeErr) //переделать фаталы на респонсы
	}

	_, parseError := jwt.Parse(tokens.AccessToken, func(*jwt.Token) (interface{}, error) {
		return []byte(publicKey), nil
	})

	if parseError != nil {
		log.Fatalf("Token is wrong: %v", parseError)
	}

}

func getJwt(requestIpAddr string, hours int) string {
	block, _ := pem.Decode([]byte(privateKey))
	key, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

	claims := jwt.MapClaims{}

	claims["ip"] = requestIpAddr
	claims["exp"] = time.Now().Add(time.Hour * time.Duration(hours)).Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)

	result, err := token.SignedString(key)

	if err != nil {
		log.Fatalf("Error while generating accessToken: %v", err)
	}

	return result
}
