package handlers

import (
	"crypto/sha1"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"server/httpResponse"
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

func (handler *JwtHandler) getUser(request *http.Request) (models.User, error) {
	body := GetTokensBody{}
	defer request.Body.Close()
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	err := decoder.Decode(&body)

	if err != nil {
		return models.User{}, err
	}

	user := models.User{}
	row := handler.DB.QueryRow(`SELECT * FROM "Users" WHERE "Users"."GUID" = $1`, body.GUID)
	err = row.Scan(&user.GUID, &user.RefreshToken, &user.CombinedTokensHash, &user.IpHash, &user.Email)

	if err != nil {
		return models.User{}, err
	}

	return user, nil
}

func (handler *JwtHandler) GetTokens(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "application/json")

	requestIpAddr := request.Header.Get("X-Forwarded-For") //может установить любой ip в этом заголовке на своей стороне

	requestIpHash, err := hashData(requestIpAddr)

	if err != nil {
		httpResponse.SendResponse(writer, "Something went wrong while hashing data", http.StatusBadRequest)
		log.Println(err)
		return
	}

	requestIpHashDiff := false

	accessCookie, err := request.Cookie("accessToken")

	if err == nil {
		claims, parsedToken, err := validateToken(accessCookie.Value)

		if err != nil {
			httpResponse.SendResponse(writer, "Something went wrong while validating token", http.StatusBadRequest)
			log.Println(err)
			return
		}

		if !parsedToken.Valid {
			httpResponse.SendResponse(writer, "Token is invalid", http.StatusBadRequest)
			return
		}

		cookieIpAddr := claims.ip
		cookieIpHash, err := hashData(cookieIpAddr)

		if err != nil {
			httpResponse.SendResponse(writer, "Something went wrong while hashing data", http.StatusBadRequest)
			log.Println(err)
			return
		}

		requestIpHashDiff = requestIpHash != cookieIpHash
	}

	user, err := handler.getUser(request)

	if err != nil {
		if err == sql.ErrNoRows {
			httpResponse.SendResponse(writer, "User with such GUID not found", http.StatusBadRequest)
			return
		}

		httpResponse.SendResponse(writer, "", http.StatusBadRequest)
		log.Println(err)
		return
	}

	userIpHashDiff := user.IpHash != "" && requestIpHash != user.IpHash

	if (requestIpHashDiff || userIpHashDiff) && user.Email != "" {
		go sendEmail()
	}

	refreshToken, combinedTokensHash, err := generateTokens(writer, requestIpAddr)

	if err != nil {
		httpResponse.SendResponse(writer, "Something went wrong while generating access token", http.StatusBadRequest)
		log.Println(err)
		return
	}

	_, err = handler.DB.Exec(`UPDATE "Users" SET
		"RefreshToken" = $1,
		"CombinedTokensHash" = $2,
		"IpHash" = $3
		WHERE "GUID" = $4`, refreshToken, combinedTokensHash, requestIpHash, user.GUID)

	if err != nil {
		httpResponse.SendResponse(writer, "", http.StatusBadRequest)
		log.Println(err)
		return
	}

	httpResponse.SendResponse(writer, "Your cookies are successfully set to http only", http.StatusOK)
}

func (handler *JwtHandler) RefreshTokens(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "application/json")

	accessCookie, errAccessToken := request.Cookie("accessToken")
	refreshCookie, errRefreshToken := request.Cookie("refreshToken")

	if errAccessToken != nil || errRefreshToken != nil {
		httpResponse.SendResponse(writer, "Can't get cookies from request", http.StatusBadRequest)
		return
	}

	decodedToken, err := base64.URLEncoding.DecodeString(refreshCookie.Value)

	if err != nil {
		httpResponse.SendResponse(writer, "", http.StatusBadRequest)
		log.Println(err)
		return
	}

	refreshToken := string(decodedToken)
	tokens := Tokens{accessCookie.Value, refreshToken}
	combinedHash, err := tokens.getTokensHash()

	if err != nil {
		httpResponse.SendResponse(writer, "Something went wrong while hashing tokens", http.StatusBadRequest)
		log.Println(err)
		return
	}

	user, err := handler.getUser(request)

	if err != nil {
		if err == sql.ErrNoRows {
			httpResponse.SendResponse(writer, "User with such GUID not found", http.StatusBadRequest)
			return
		}

		httpResponse.SendResponse(writer, "", http.StatusBadRequest)
		log.Println(err)
		return
	}

	claims, parsedToken, err := validateToken(refreshToken)

	if err != nil {
		httpResponse.SendResponse(writer, "Something went wrong while validating token", http.StatusBadRequest)
		log.Println(err)
		return
	}

	if parsedToken.Valid {
		httpResponse.SendResponse(writer, "Token is invalid", http.StatusBadRequest)
		return
	}

	if combinedHash != user.CombinedTokensHash {
		httpResponse.SendResponse(writer, "Wrong token provided", http.StatusBadRequest)
		return
	}

	currHashedIp, err := hashData(claims.ip)

	if err != nil {
		httpResponse.SendResponse(writer, "Something went wrong while hashing data", http.StatusBadRequest)
		log.Println(err)
		return
	}

	if currHashedIp != user.IpHash && user.Email != "" {
		go sendEmail()
	}

	requestIpAddr := request.Header.Get("X-Forwarded-For")

	generateTokens(writer, requestIpAddr)
}

func sendEmail() {
	log.Println("Email sended")
}

func validateToken(token string) (*JWTClaim, *jwt.Token, error) {
	claims := &JWTClaim{}

	publicKeyInterface, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(publicKey))

	parsedToken, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return publicKeyInterface, nil
	})

	if err != nil {
		return claims, parsedToken, err
	}

	return claims, parsedToken, nil
}

func hashData(data string) (string, error) {
	hasher := sha1.New() //можно выбрать другой алгоритм исходя из требований безопасности
	_, err := hasher.Write([]byte(data))

	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(hasher.Sum(nil)), nil
}

func (tokens *Tokens) getTokensHash() (string, error) {
	return hashData(tokens.AccessToken + tokens.RefreshToken)
}

func generateTokens(writer http.ResponseWriter, requestIpAddr string) (string, string, error) {
	accessToken, err := generateJWT(requestIpAddr, AccessTokenLifeSpanInHours)

	if err != nil {
		return "", "", err
	}

	refreshToken, err := generateJWT(requestIpAddr, RefreshTokenLifeSpanInHours)

	if err != nil {
		return "", "", err
	}

	tokens := Tokens{accessToken, refreshToken}

	combinedHash, err := tokens.getTokensHash()

	if err != nil {
		return "", "", err
	}

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

	return base64Token, combinedHash, nil
}

func generateJWT(requestIpAddr string, hours int) (string, error) {
	key, _ := jwt.ParseRSAPrivateKeyFromPEM([]byte(privateKey))

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
		return "", err
	}

	return result, nil
}
