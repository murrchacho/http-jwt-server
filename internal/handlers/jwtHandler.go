package handlers

import (
	"crypto/sha1"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"server/internal/config"
	"server/internal/httpResponse"
	"server/internal/models"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var configInfo = config.LoadConfig()

var privateKey, publicKey = configInfo.PrivateKey, configInfo.PublicKey

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
	Ip string
	jwt.RegisteredClaims
}

func (handler *JwtHandler) GetTokens(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		httpResponse.SendResponse(writer, "Incorrect HTTP-method", http.StatusBadRequest)
		return
	}

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

		cookieIpAddr := claims.Ip
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

	bcryptRefreshToken, err := generateTokens(writer, requestIpAddr)

	if err != nil {
		httpResponse.SendResponse(writer, "Something went wrong while generating access token", http.StatusBadRequest)
		log.Println(err)
		return
	}

	_, err = handler.DB.Exec(`UPDATE "users" SET
		"refresh_token" = $1,
		"ip_hash" = $2
		WHERE "guid" = $3`, bcryptRefreshToken, requestIpHash, user.GUID)

	if err != nil {
		httpResponse.SendResponse(writer, "", http.StatusBadRequest)
		log.Println(err)
		return
	}

	httpResponse.SendResponse(writer, "Your cookies are successfully set to http only", http.StatusOK)
}

func (handler *JwtHandler) RefreshTokens(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		httpResponse.SendResponse(writer, "Incorrect HTTP-method", http.StatusBadRequest)
		return
	}

	accessCookie, errAccessCookie := request.Cookie("accessToken")
	refreshCookie, errRefreshCookie := request.Cookie("refreshToken")

	if errAccessCookie != nil || errRefreshCookie != nil {
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

	if !parsedToken.Valid {
		httpResponse.SendResponse(writer, "Token is invalid", http.StatusBadRequest)
		return
	}

	hashedKey, _ := hashData(tokens.AccessToken + tokens.RefreshToken)
	err = bcrypt.CompareHashAndPassword([]byte(user.RefreshToken), []byte(hashedKey))

	if err != nil {
		httpResponse.SendResponse(writer, "Wrong token provided", http.StatusBadRequest)
		return
	}

	currHashedIp, err := hashData(claims.Ip)

	if err != nil {
		httpResponse.SendResponse(writer, "Something went wrong while hashing data", http.StatusBadRequest)
		log.Println(err)
		return
	}

	if currHashedIp != user.IpHash && user.Email != "" {
		go sendEmail()
	}

	requestIpAddr := request.Header.Get("X-Forwarded-For")

	_, err = generateTokens(writer, requestIpAddr)

	if err != nil {
		httpResponse.SendResponse(writer, "Something went wrong while generating tokens", http.StatusBadRequest)
		log.Println(err)
		return
	}
}

func (handler *JwtHandler) getUser(request *http.Request) (user models.User, err error) {
	body := GetTokensBody{}
	user = models.User{}
	defer request.Body.Close()
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&body)

	if err != nil {
		return
	}

	row := handler.DB.QueryRow(`SELECT * FROM "users" WHERE "users"."guid" = $1`, body.GUID)
	err = row.Scan(&user.GUID, &user.RefreshToken, &user.IpHash, &user.Email)

	if err != nil {
		return
	}

	return user, nil
}

func validateToken(token string) (claims *JWTClaim, parsedToken *jwt.Token, err error) {
	claims = &JWTClaim{}

	publicKeyInterface, err := jwt.ParseRSAPublicKeyFromPEM([]byte(publicKey))

	if err != nil {
		return nil, nil, err
	}

	parsedToken, err = jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return publicKeyInterface, nil
	})

	return claims, parsedToken, err
}

func hashData(data string) (hash string, err error) {
	hasher := sha1.New() //можно выбрать другой алгоритм исходя из требований безопасности

	_, err = hasher.Write([]byte(data + configInfo.ServerSalt))

	return base64.URLEncoding.EncodeToString(hasher.Sum(nil)), err
}

func (tokens *Tokens) getBcryptRefreshToken() (bcryptRefreshToken string, err error) {
	hashedKey, err := hashData(tokens.AccessToken + tokens.RefreshToken)

	if err != nil {
		return
	}

	refreshToken, err := bcrypt.GenerateFromPassword([]byte(hashedKey), bcrypt.DefaultCost)

	if err != nil {
		return
	}

	return string(refreshToken), nil
}

func generateTokens(writer http.ResponseWriter, requestIpAddr string) (combinedTokensHash string, err error) {
	accessToken, err := generateJWT(requestIpAddr, AccessTokenLifeSpanInHours)

	if err != nil {
		return
	}

	refreshToken, err := generateJWT(requestIpAddr, RefreshTokenLifeSpanInHours)

	if err != nil {
		return
	}

	tokens := Tokens{accessToken, refreshToken}

	bcryptRefreshToken, err := tokens.getBcryptRefreshToken()

	if err != nil {
		return
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

	return bcryptRefreshToken, nil
}

func generateJWT(requestIpAddr string, hours int) (result string, err error) {
	expirationTime := jwt.NewNumericDate(time.Now().Add(time.Hour * time.Duration(hours)))

	claims := JWTClaim{
		Ip: requestIpAddr,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: expirationTime,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)
	key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(privateKey))

	if err != nil {
		return
	}

	result, err = token.SignedString(key)

	return result, err
}

func sendEmail() {
	log.Println("Email sended")
}
