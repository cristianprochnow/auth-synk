package controller

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"synk/gateway/app/model"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type Users struct {
	model *model.Users
}

type HandleShowResponse struct {
	Resource ResponseHeader    `json:"resource"`
	Data     []model.UsersList `json:"user"`
}

type HandleUserRegisterResponse struct {
	Resource ResponseHeader           `json:"resource"`
	Data     UserRegisterDataResponse `json:"user"`
}

type UserRegisterDataResponse struct {
	UserId int    `json:"user_id"`
	Token  string `json:"token"`
}

type HandleUserLoginResponse struct {
	Resource ResponseHeader        `json:"resource"`
	Data     UserLoginDataResponse `json:"user"`
}

type HandleUserCheckResponse struct {
	Resource ResponseHeader `json:"resource"`
}

type UserLoginDataResponse struct {
	UserId    int    `json:"user_id"`
	UserName  string `json:"user_name"`
	UserEmail string `json:"user_email"`
	Token     string `json:"token"`
}

type HandleUserRegisterRequest struct {
	UserName  string `json:"user_name"`
	UserEmail string `json:"user_email"`
	UserPass  string `json:"user_pass"`
}

type HandleUserLoginRequest struct {
	UserEmail string `json:"user_email"`
	UserPass  string `json:"user_pass"`
}

type AccessTokenClaims struct {
	User struct {
		UserId int `json:"user_id"`
	} `json:"user"`
	jwt.RegisteredClaims
}

type RefreshTokenClaims struct {
	User struct {
		UserId int `json:"user_id"`
	} `json:"user"`
	jwt.RegisteredClaims
}

func NewUsers(db *sql.DB) *Users {
	users := Users{
		model: model.NewUsers(db),
	}

	return &users
}

const ACCESS_TOKEN_EXPIRY = time.Minute * 15
const REFRESH_TOKEN_EXPIRY = time.Hour * 24 * 7

func (u *Users) HandleShow(w http.ResponseWriter, r *http.Request) {
	SetJsonContentType(w)

	var user []model.UsersList

	userId := r.URL.Query().Get("user_id")

	response := HandleShowResponse{
		Resource: ResponseHeader{
			Ok: true,
		},
		Data: user,
	}

	if userId == "" {
		response.Resource.Ok = false
		response.Resource.Error = "fields user_id into query string is required"

		WriteErrorResponse(w, response, "/users", response.Resource.Error, http.StatusBadRequest)

		return
	}

	userList, userErr := u.model.List(userId)

	if userErr != nil {
		response.Resource.Ok = false
		response.Resource.Error = userErr.Error()

		WriteErrorResponse(w, response, "/users", "error on user show", http.StatusInternalServerError)

		return
	}

	if len(userList) > 0 {
		user = userList
	}

	response.Data = user

	WriteSuccessResponse(w, response)
}

func (u *Users) HandleRegister(w http.ResponseWriter, r *http.Request) {
	SetJsonContentType(w)

	response := HandleUserRegisterResponse{
		Resource: ResponseHeader{
			Ok: true,
		},
		Data: UserRegisterDataResponse{},
	}

	bodyContent, bodyErr := io.ReadAll(r.Body)

	if bodyErr != nil {
		response.Resource.Ok = false
		response.Resource.Error = "error on read creation body"

		WriteErrorResponse(w, response, "/users", response.Resource.Error, http.StatusBadRequest)

		return
	}

	var user HandleUserRegisterRequest

	jsonErr := json.Unmarshal(bodyContent, &user)

	if jsonErr != nil {
		response.Resource.Ok = false
		response.Resource.Error = "some fields can be in invalid format"

		WriteErrorResponse(w, response, "/users", response.Resource.Error, http.StatusBadRequest)

		return
	}

	user.UserEmail = strings.TrimSpace(user.UserEmail)
	user.UserName = strings.TrimSpace(user.UserName)

	hasAllData := user.UserEmail != "" &&
		user.UserName != "" &&
		user.UserPass != ""

	if !hasAllData {
		response.Resource.Ok = false
		response.Resource.Error = "fields user_name, user_email and user_pass are required"

		WriteErrorResponse(w, response, "/users", response.Resource.Error, http.StatusBadRequest)

		return
	}

	userInfo, userInfoErr := u.model.ByEmail(user.UserEmail)

	if userInfoErr != nil {
		response.Resource.Ok = false
		response.Resource.Error = "error while searching user with same email"

		WriteErrorResponse(w, response, "/users", response.Resource.Error, http.StatusBadRequest)

		return
	}

	if userInfo.UserId != 0 {
		response.Resource.Ok = false
		response.Resource.Error = "user with same email already exists"

		WriteErrorResponse(w, response, "/users", response.Resource.Error, http.StatusBadRequest)

		return
	}

	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		response.Resource.Ok = false
		response.Resource.Error = "JWT secret is not set"

		WriteErrorResponse(w, response, "/users", response.Resource.Error, http.StatusBadRequest)

		return
	}
	jwtSecret := []byte(secret)

	refreshSecret := os.Getenv("JWT_REFRESH_SECRET")
	if refreshSecret == "" {
		response.Resource.Ok = false
		response.Resource.Error = "JWT refresh secret is not set"

		WriteErrorResponse(w, response, "/users", response.Resource.Error, http.StatusBadRequest)

		return
	}
	jwtRefreshSecret := []byte(refreshSecret)

	hashedPassword, hashErr := bcrypt.GenerateFromPassword([]byte(user.UserPass), bcrypt.DefaultCost)
	if hashErr != nil {
		response.Resource.Ok = false
		response.Resource.Error = "error while generating password hash"

		WriteErrorResponse(w, response, "/users", response.Resource.Error, http.StatusBadRequest)

		return
	}

	newUserId, newUserErr := u.model.Add(model.UserRegisterData{
		UserName:  user.UserName,
		UserEmail: user.UserEmail,
		UserPass:  string(hashedPassword),
	})

	if newUserErr != nil {
		response.Resource.Ok = false
		response.Resource.Error = "error while registering new user"

		WriteErrorResponse(w, response, "/users", response.Resource.Error, http.StatusBadRequest)

		return
	}

	claims := AccessTokenClaims{
		User: struct {
			UserId int `json:"user_id"`
		}{
			UserId: newUserId,
		},
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ACCESS_TOKEN_EXPIRY)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	accessTokenString, tokenStringErr := accessToken.SignedString(jwtSecret)
	if tokenStringErr != nil {
		response.Resource.Ok = false
		response.Resource.Error = "error while signing user access token"

		WriteErrorResponse(w, response, "/users", response.Resource.Error, http.StatusBadRequest)

		return
	}

	refreshClaims := RefreshTokenClaims{
		User: struct {
			UserId int `json:"user_id"`
		}{
			UserId: newUserId,
		},
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(REFRESH_TOKEN_EXPIRY)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)

	refreshTokenString, refreshTokenStringErr := refreshToken.SignedString(jwtRefreshSecret)
	if refreshTokenStringErr != nil {
		response.Resource.Ok = false
		response.Resource.Error = "error while signing user refresh token"

		WriteErrorResponse(w, response, "/users", response.Resource.Error, http.StatusBadRequest)

		return
	}

	cookie := http.Cookie{
		Name:     "refresh_token",
		Value:    refreshTokenString,
		MaxAge:   int(REFRESH_TOKEN_EXPIRY.Seconds()),
		Path:     "/",
		Domain:   "",
		HttpOnly: true,
		Secure:   false, // Set to true in production (requires HTTPS)
	}

	response.Data.UserId = newUserId
	response.Data.Token = accessTokenString

	http.SetCookie(w, &cookie)
	WriteSuccessResponse(w, response)
}

func (u *Users) HandleLogin(w http.ResponseWriter, r *http.Request) {
	SetJsonContentType(w)

	response := HandleUserLoginResponse{
		Resource: ResponseHeader{
			Ok: true,
		},
		Data: UserLoginDataResponse{},
	}

	bodyContent, bodyErr := io.ReadAll(r.Body)

	if bodyErr != nil {
		response.Resource.Ok = false
		response.Resource.Error = "error on read login body"

		WriteErrorResponse(w, response, "/users", response.Resource.Error, http.StatusBadRequest)

		return
	}

	var user HandleUserRegisterRequest

	jsonErr := json.Unmarshal(bodyContent, &user)

	if jsonErr != nil {
		response.Resource.Ok = false
		response.Resource.Error = "some fields can be in invalid format"

		WriteErrorResponse(w, response, "/users", response.Resource.Error, http.StatusBadRequest)

		return
	}

	user.UserEmail = strings.TrimSpace(user.UserEmail)

	hasAllData := user.UserEmail != "" &&
		user.UserPass != ""

	if !hasAllData {
		response.Resource.Ok = false
		response.Resource.Error = "fields user_name and user_pass are required"

		WriteErrorResponse(w, response, "/users", response.Resource.Error, http.StatusBadRequest)

		return
	}

	userInfo, userInfoErr := u.model.ByEmail(user.UserEmail)

	if userInfoErr != nil {
		response.Resource.Ok = false
		response.Resource.Error = "error while searching user"

		WriteErrorResponse(w, response, "/users", response.Resource.Error, http.StatusBadRequest)

		return
	}

	if userInfo.UserId == 0 {
		response.Resource.Ok = false
		response.Resource.Error = "user does not exists"

		WriteErrorResponse(w, response, "/users", response.Resource.Error, http.StatusBadRequest)

		return
	}

	passErr := bcrypt.CompareHashAndPassword([]byte(userInfo.UserPass), []byte(user.UserPass))
	if passErr != nil {
		response.Resource.Ok = false
		response.Resource.Error = "invalid credentials"

		WriteErrorResponse(w, response, "/users", response.Resource.Error, http.StatusBadRequest)

		return
	}

	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		response.Resource.Ok = false
		response.Resource.Error = "JWT secret is not set"

		WriteErrorResponse(w, response, "/users", response.Resource.Error, http.StatusBadRequest)

		return
	}
	jwtSecret := []byte(secret)

	refreshSecret := os.Getenv("JWT_REFRESH_SECRET")
	if refreshSecret == "" {
		response.Resource.Ok = false
		response.Resource.Error = "JWT refresh secret is not set"

		WriteErrorResponse(w, response, "/users", response.Resource.Error, http.StatusBadRequest)

		return
	}
	jwtRefreshSecret := []byte(refreshSecret)

	claims := AccessTokenClaims{
		User: struct {
			UserId int `json:"user_id"`
		}{
			UserId: userInfo.UserId,
		},
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ACCESS_TOKEN_EXPIRY)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	accessTokenString, tokenStringErr := accessToken.SignedString(jwtSecret)
	if tokenStringErr != nil {
		response.Resource.Ok = false
		response.Resource.Error = "error while signing user access token"

		WriteErrorResponse(w, response, "/users", response.Resource.Error, http.StatusBadRequest)

		return
	}

	refreshClaims := RefreshTokenClaims{
		User: struct {
			UserId int `json:"user_id"`
		}{
			UserId: userInfo.UserId,
		},
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(REFRESH_TOKEN_EXPIRY)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)

	refreshTokenString, refreshTokenStringErr := refreshToken.SignedString(jwtRefreshSecret)
	if refreshTokenStringErr != nil {
		response.Resource.Ok = false
		response.Resource.Error = "error while signing user refresh token"

		WriteErrorResponse(w, response, "/users", response.Resource.Error, http.StatusBadRequest)

		return
	}

	cookie := http.Cookie{
		Name:     "refresh_token",
		Value:    refreshTokenString,
		MaxAge:   int(REFRESH_TOKEN_EXPIRY.Seconds()),
		Path:     "/",
		Domain:   "",
		HttpOnly: true,
		Secure:   false, // Set to true in production (requires HTTPS)
	}

	response.Data.UserId = userInfo.UserId
	response.Data.UserName = userInfo.UserName
	response.Data.UserEmail = userInfo.UserEmail
	response.Data.Token = accessTokenString

	http.SetCookie(w, &cookie)
	WriteSuccessResponse(w, response)
}

func (u *Users) HandleRefresh(w http.ResponseWriter, r *http.Request) {
	SetJsonContentType(w)

	response := HandleUserLoginResponse{
		Resource: ResponseHeader{
			Ok: true,
		},
		Data: UserLoginDataResponse{},
	}

	refreshTokenCookie, refreshTokenCookieErr := r.Cookie("refresh_token")

	if refreshTokenCookieErr != nil {
		response.Resource.Ok = false
		response.Resource.Error = "refresh_token cookie is required"

		if refreshTokenCookieErr == http.ErrNoCookie {
			response.Resource.Error = "no refresh_token found into cookies"
		}

		WriteErrorResponse(w, response, "/users", response.Resource.Error, http.StatusBadRequest)

		return
	}

	tokenString := refreshTokenCookie.Value

	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		response.Resource.Ok = false
		response.Resource.Error = "JWT secret is not set"

		WriteErrorResponse(w, response, "/users", response.Resource.Error, http.StatusBadRequest)

		return
	}
	jwtSecret := []byte(secret)

	refreshSecret := os.Getenv("JWT_REFRESH_SECRET")
	if refreshSecret == "" {
		response.Resource.Ok = false
		response.Resource.Error = "JWT refresh secret is not set"

		WriteErrorResponse(w, response, "/users", response.Resource.Error, http.StatusBadRequest)

		return
	}
	jwtRefreshSecret := []byte(refreshSecret)

	claims := &RefreshTokenClaims{}
	token, tokenErr := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}

		return jwtRefreshSecret, nil
	})

	if tokenErr != nil || !token.Valid {
		response.Resource.Ok = false
		response.Resource.Error = "refresh token is not valid"

		WriteErrorResponse(w, response, "/users", response.Resource.Error, http.StatusBadRequest)

		return
	}

	userInfo, userInfoErr := u.model.ById(claims.User.UserId)

	if userInfo.UserId == 0 || userInfoErr != nil {
		response.Resource.Ok = false
		response.Resource.Error = "user not exists with user_id within refresh_token"

		WriteErrorResponse(w, response, "/users", response.Resource.Error, http.StatusBadRequest)

		return
	}

	accessClaims := AccessTokenClaims{
		User: struct {
			UserId int `json:"user_id"`
		}{
			UserId: claims.User.UserId,
		},
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ACCESS_TOKEN_EXPIRY)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)

	accessTokenString, tokenStringErr := accessToken.SignedString(jwtSecret)
	if tokenStringErr != nil {
		response.Resource.Ok = false
		response.Resource.Error = "error while signing user access token"

		WriteErrorResponse(w, response, "/users", response.Resource.Error, http.StatusBadRequest)

		return
	}

	refreshClaims := RefreshTokenClaims{
		User: struct {
			UserId int `json:"user_id"`
		}{
			UserId: claims.User.UserId,
		},
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(REFRESH_TOKEN_EXPIRY)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)

	refreshTokenString, refreshTokenStringErr := refreshToken.SignedString(jwtRefreshSecret)
	if refreshTokenStringErr != nil {
		response.Resource.Ok = false
		response.Resource.Error = "error while signing user refresh token"

		WriteErrorResponse(w, response, "/users", response.Resource.Error, http.StatusBadRequest)

		return
	}

	cookie := http.Cookie{
		Name:     "refresh_token",
		Value:    refreshTokenString,
		MaxAge:   int(REFRESH_TOKEN_EXPIRY.Seconds()),
		Path:     "/",
		Domain:   "",
		HttpOnly: true,
		Secure:   false, // Set to true in production (requires HTTPS)
	}

	response.Data.UserId = userInfo.UserId
	response.Data.UserName = userInfo.UserName
	response.Data.UserEmail = userInfo.UserEmail
	response.Data.Token = accessTokenString

	http.SetCookie(w, &cookie)
	WriteSuccessResponse(w, response)
}

func (u *Users) HandleCheck(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")

	response := HandleUserCheckResponse{
		Resource: ResponseHeader{
			Ok: true,
		},
	}

	if authHeader == "" {
		response.Resource.Ok = false
		response.Resource.Error = "Bearer Authorization header is required"

		WriteErrorResponse(w, response, "/users", response.Resource.Error, http.StatusBadRequest)

		return
	}

	parts := strings.Split(authHeader, " ")

	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		response.Resource.Ok = false
		response.Resource.Error = "invalid Bearer Authorization header format"

		WriteErrorResponse(w, response, "/users", response.Resource.Error, http.StatusBadRequest)

		return
	}

	tokenString := parts[1]

	if tokenString == "" {
		response.Resource.Ok = false
		response.Resource.Error = "Bearer token can not be empty"

		WriteErrorResponse(w, response, "/users", response.Resource.Error, http.StatusBadRequest)

		return
	}

	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		response.Resource.Ok = false
		response.Resource.Error = "JWT secret is not set"

		WriteErrorResponse(w, response, "/users", response.Resource.Error, http.StatusBadRequest)

		return
	}
	jwtSecret := []byte(secret)

	claims := &AccessTokenClaims{}
	token, tokenErr := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}

		return jwtSecret, nil
	})

	if tokenErr != nil || !token.Valid {
		response.Resource.Ok = false
		response.Resource.Error = "access token is not valid"

		if errors.Is(tokenErr, jwt.ErrTokenExpired) {
			response.Resource.Error = "access token has expired"
		}

		WriteErrorResponse(w, response, "/users", response.Resource.Error, http.StatusUnauthorized)

		return
	}

	userInfo, userInfoErr := u.model.ById(claims.User.UserId)

	if userInfo.UserId == 0 || userInfoErr != nil {
		response.Resource.Ok = false
		response.Resource.Error = "invalid user supplied by access_token"

		WriteErrorResponse(w, response, "/users", response.Resource.Error, http.StatusUnauthorized)

		return
	}

	WriteSuccessResponse(w, response)
}

func (u *Users) HandleLogout(w http.ResponseWriter, r *http.Request) {
	SetJsonContentType(w)

	response := HandleUserCheckResponse{
		Resource: ResponseHeader{
			Ok: true,
		},
	}

	cookie := http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		Domain:   "",
		HttpOnly: true,
		Secure:   false, // Set to true in production (requires HTTPS)
	}

	http.SetCookie(w, &cookie)
	WriteSuccessResponse(w, response)
}
