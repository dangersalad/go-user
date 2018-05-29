package user

import (
	"encoding/base64"
	"github.com/dgrijalva/jwt-go"
	"net/http"
	"regexp"
	"strings"
)

var regexpUserPass = regexp.MustCompile(`^Basic (.*)$`)
var regexpToken = regexp.MustCompile(`^Bearer (.*)$`)

// CheckUserPass uses the AuthConfig to extract and check a username and
// password from a provided authorization header string
func CheckUserPass(conf *AuthConfig, authHeader string) (jwt.Claims, error) {
	username, password, err := extractUserPass(authHeader)
	if err != nil {
		return nil, err
	}
	claims, err := conf.getLoginClaims(username, password)
	if err != nil {
		return nil, err
	}
	return claims, nil
}

// LoginHandlerFunc returns an http.HandlerFunc that logs in a user
// with either a username/password or a token in the Authorization
// header and returns a 201 with the user's token in a cookie
func LoginHandlerFunc(conf *AuthConfig) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("authorization")
		if authHeader == "" {
			conf.handleError(errLoginMissingAuth, w, r)
			return
		}
		claims, err := CheckUserPass(conf, authHeader)
		if err != nil {
			// if not found, try to do a token auth
			if err == errLoginAuthNotFound {
				token, err := extractToken(authHeader)
				if err != nil {
					conf.handleError(err, w, r)
					return
				}
				_, _, err = conf.updateAndSetCookie(token, w, r)
				if err != nil {
					conf.handleError(err, w, r)
					return
				}
				w.WriteHeader(http.StatusAccepted)
				return
			}
			conf.handleError(err, w, r)
			return
		}

		token, err := MakeTokenString(claims)
		if err != nil {
			conf.handleError(err, w, r)
			return
		}

		cookie := MakeCookie(token, r.Header.Get("origin"), r.Host, conf.cookieName())
		http.SetCookie(w, cookie)

		w.WriteHeader(http.StatusAccepted)
		return
	})
}

func extractToken(header string) (string, error) {
	match := regexpToken.FindStringSubmatch(header)
	if match == nil {
		return "", errLoginAuthNotFound
	}
	if len(match) != 2 {
		return "", errLoginAuthNotFound
	}
	return match[1], nil
}

func extractUserPass(header string) (string, string, error) {
	match := regexpUserPass.FindStringSubmatch(header)
	if match == nil {
		return "", "", errLoginAuthNotFound
	}
	if len(match) != 2 {
		return "", "", errLoginAuthNotFound
	}
	// parse the auth data
	authData, err := base64.StdEncoding.DecodeString(match[1])
	if err != nil {
		return "", "", errLoginInvalidUserPass
	}
	authParts := strings.Split(string(authData), ":")
	if len(authParts) != 2 {
		return "", "", errLoginInvalidUserPass
	}
	return authParts[0], authParts[1], nil
}
