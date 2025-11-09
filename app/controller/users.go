package controller

import (
	"database/sql"
	"encoding/json"
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

type HandleUserRegisterRequest struct {
	UserName  string `json:"user_name"`
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
