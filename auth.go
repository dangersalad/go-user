package user

import (
	"crypto/sha512"
	"fmt"
	"net/http"
	"regexp"

	env "github.com/dangersalad/go-environment"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

// EnvKeyJWTKey is the environment key containing the key for JWT
// hashing. Changing this will invalidate all active keys.
const EnvKeyJWTKey = "JWT_KEY"

// Claims are the default JWT claims
type Claims struct {
	Username string `json:"username"`
	UserID   int64  `json:"userId"`
	jwt.StandardClaims
}

// Auther is an interface for a "user" that can auth. The function
// names are meant to match the generated names from GRPC.
type Auther interface {
	GetUsername() string
	GetPassword() string
	GetID() int64
}

// PasswordIsValid checks the password and a provided hash
func PasswordIsValid(hash, pass string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass)) == nil
}

func passwordValid(u Auther, pass string) bool {
	return PasswordIsValid(u.GetPassword(), pass)
}

// MakePasswordHash makes a bcrypt password hash for the given password
func MakePasswordHash(pass string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(pass), 8)
	if err != nil {
		return "", fmt.Errorf("making password: %w", err)
	}
	return string(hash), nil
}

// GetKey returns the key for signing JWT tokens
func GetKey(token *jwt.Token) (interface{}, error) {

	if token != nil && token.Claims != nil {
		if err := token.Claims.Valid(); err != nil {
			return nil, fmt.Errorf("invalid claims: %w", err)
		}
	}

	conf, err := env.ReadOptions(env.Options{
		EnvKeyJWTKey: "",
	})
	if err != nil {
		return nil, fmt.Errorf("getting JWT key from env: %w", err)
	}

	// use the provided env var to make a key
	return makeKey([]byte(conf[EnvKeyJWTKey])), nil
}

// crazy hashing shit
// TODO: make sure this is OK
func makeKey(key []byte) []byte {
	hash := sha512.New()
	var result []byte

	hash.Write(key)
	result = hash.Sum(result)
	hash.Reset()

	hash.Write(key[len(key)/2:])
	hash.Write(key[:len(key)/2])
	result = hash.Sum(result)
	hash.Reset()

	hash.Write(result)
	return hash.Sum([]byte{})
}

// SetToken takes JWT claims and generates a cookie, which is then set
// on the given http.ResponseWriter
func SetToken(w http.ResponseWriter, origin, host string, claims jwt.Claims, cookieName string, keyFunc jwt.Keyfunc) error {

	// get token string
	token, err := MakeTokenString(claims, keyFunc)
	if err != nil {
		return err
	}

	// make a cookie
	cookie := MakeCookie(token, origin, host, cookieName)

	// set the cookie on the response
	http.SetCookie(w, cookie)

	return nil
}

var originParse = regexp.MustCompile(`^(https?)://([^/]+).*$`)

// MakeCookie makes a cookie for use with http.SetCookie from a given
// token string, origin and hostname
func MakeCookie(token, origin, host string, cookieName string) *http.Cookie {
	var secure bool

	matches := originParse.FindStringSubmatch(origin)
	if len(matches) == 3 {
		secure = matches[1] == "https"
	}

	return &http.Cookie{
		Name:     cookieName,
		Value:    token,
		HttpOnly: true,
		Secure:   secure,
		Domain:   host,
		Path:     "/",
	}

}

// MakeTokenString makes a JWT token string from a given set of claims
func MakeTokenString(claims jwt.Claims, keyFunc jwt.Keyfunc) (string, error) {
	// make a new token with the user claims we want
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	if keyFunc == nil {
		keyFunc = GetKey
	}

	key, err := keyFunc(token)
	if err != nil {
		return "", err
	}

	// sign the token using the secret key
	signedToken, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("signing token: %w", err)
	}

	return signedToken, nil

}

// CheckTokenString verifies that a JWT token string is valid
func CheckTokenString(tokenStr string, claims jwt.Claims, keyFunc jwt.Keyfunc) (token *jwt.Token, err error) {
	if keyFunc == nil {
		keyFunc = GetKey
	}
	token, err = jwt.ParseWithClaims(tokenStr, claims, keyFunc)
	if err != nil {
		if vErr, ok := err.(*jwt.ValidationError); ok {
			debug(vErr)
			debugf("jwt.ValidationErrorMalformed        : token errors %010b & %010b = %010b", vErr.Errors, jwt.ValidationErrorMalformed, vErr.Errors&jwt.ValidationErrorMalformed)
			debugf("jwt.ValidationErrorUnverifiable     : token errors %010b & %010b = %010b", vErr.Errors, jwt.ValidationErrorUnverifiable, vErr.Errors&jwt.ValidationErrorUnverifiable)
			debugf("jwt.ValidationErrorSignatureInvalid : token errors %010b & %010b = %010b", vErr.Errors, jwt.ValidationErrorSignatureInvalid, vErr.Errors&jwt.ValidationErrorSignatureInvalid)
			debugf("jwt.ValidationErrorAudience         : token errors %010b & %010b = %010b", vErr.Errors, jwt.ValidationErrorAudience, vErr.Errors&jwt.ValidationErrorAudience)
			debugf("jwt.ValidationErrorExpired          : token errors %010b & %010b = %010b", vErr.Errors, jwt.ValidationErrorExpired, vErr.Errors&jwt.ValidationErrorExpired)
			debugf("jwt.ValidationErrorIssuedAt         : token errors %010b & %010b = %010b", vErr.Errors, jwt.ValidationErrorIssuedAt, vErr.Errors&jwt.ValidationErrorIssuedAt)
			debugf("jwt.ValidationErrorIssuer           : token errors %010b & %010b = %010b", vErr.Errors, jwt.ValidationErrorIssuer, vErr.Errors&jwt.ValidationErrorIssuer)
			debugf("jwt.ValidationErrorNotValidYet      : token errors %010b & %010b = %010b", vErr.Errors, jwt.ValidationErrorNotValidYet, vErr.Errors&jwt.ValidationErrorNotValidYet)
			debugf("jwt.ValidationErrorId               : token errors %010b & %010b = %010b", vErr.Errors, jwt.ValidationErrorId, vErr.Errors&jwt.ValidationErrorId)
			debugf("jwt.ValidationErrorClaimsInvalid    : token errors %010b & %010b = %010b", vErr.Errors, jwt.ValidationErrorClaimsInvalid, vErr.Errors&jwt.ValidationErrorClaimsInvalid)
			if vErr.Errors&jwt.ValidationErrorMalformed != 0 {
				return nil, errJWTMalformed
			} else if vErr.Errors&jwt.ValidationErrorExpired != 0 || vErr.Errors&jwt.ValidationErrorNotValidYet != 0 {
				debug("time error", errJWTTime, vErr)
				return nil, errJWTTime
			} else if vErr.Errors&jwt.ValidationErrorSignatureInvalid != 0 {
				return nil, errJWTSignature
			}
		}
		return nil, &authErr{
			err:  fmt.Errorf("parsing JWT: %w", err),
			code: http.StatusUnauthorized,
		}
	}

	if !token.Valid {
		return nil, errJWTInvalid
	}

	return token, nil

}

// ExtractClaims gets the claims from a given token string
func ExtractClaims(tokenStr string, claims jwt.Claims, keyFunc jwt.Keyfunc) (jwt.Claims, error) {
	token, err := CheckTokenString(tokenStr, claims, keyFunc)
	if err != nil {
		return nil, err
	}
	return token.Claims, nil
}

// ExtractDefaultClaims gets the default claims from a given token string
func ExtractDefaultClaims(tokenStr string, keyFunc jwt.Keyfunc) (*Claims, error) {
	token, err := CheckTokenString(tokenStr, &Claims{}, keyFunc)
	if err != nil {
		return nil, err
	}

	// cast the interface
	if claims, ok := token.Claims.(*Claims); ok {
		return claims, nil
	}
	return nil, fmt.Errorf("invalid claims")
}
