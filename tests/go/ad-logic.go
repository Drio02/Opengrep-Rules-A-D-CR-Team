package main

import (
	"math/rand"
	"net/http"
	"strconv"
	"time"
	"unsafe"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

// ruleid: go-hardcoded-signing-key
var jwtSecret = []byte("supersecret")

// ruleid: go-hardcoded-signing-key
var store = sessions.NewCookieStore([]byte("cookie-secret"))

func auth(tokenStr string) jwt.MapClaims {
	// ruleid: go-jwt-parse-error-ignored, go-jwt-keyfunc-no-alg-check
	token, _ := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	return token.Claims.(jwt.MapClaims)
}

func auth2(tokenStr string) (*jwt.Token, error) {
	// ok: go-jwt-keyfunc-no-alg-check
	return jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return jwtSecret, nil
	})
}

func init() {
	// ruleid: go-rand-seeded-with-time
	rand.Seed(time.Now().UnixNano())
}

func login(hash []byte, pw string) bool {
	// ruleid: go-password-compare-result-ignored
	bcrypt.CompareHashAndPassword(hash, []byte(pw))
	return true
}

func login2(hash []byte, pw string) bool {
	// ok: go-password-compare-result-ignored
	return bcrypt.CompareHashAndPassword(hash, []byte(pw)) == nil
}

func checkKey(r *http.Request, apiKey string) bool {
	// ruleid: go-timing-unsafe-secret-compare
	return r.Header.Get("X-Api-Key") == apiKey || apiKey == r.Header.Get("X")
}

func checkKey2(apiToken string, given string) bool {
	// ruleid: go-timing-unsafe-secret-compare
	return apiToken == given
}

func register(c *gin.Context) {
	var u User
	// ruleid: go-mass-assignment-bind-save
	c.ShouldBindJSON(&u)
	db.Create(&u)
}

func admin(w http.ResponseWriter, r *http.Request) {
	// ruleid: go-cookie-based-authorization
	ck, _ := r.Cookie("role")
	if ck.Value == "admin" {
		w.Write([]byte(flag))
	}
}

func internal(c *gin.Context) {
	// ruleid: go-ip-based-auth-spoofable
	if c.ClientIP() == "127.0.0.1" {
		c.String(200, flag)
	}
}

func peek(b []byte) uintptr {
	// ruleid: go-unsafe-package
	return uintptr(unsafe.Pointer(&b[0]))
}

func qty(s string) int16 {
	n, _ := strconv.Atoi(s)
	// ruleid: go-integer-truncation-after-parse
	return int16(n)
}
