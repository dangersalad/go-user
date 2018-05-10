package user

import (
	"fmt"
	"github.com/pkg/errors"
	"net/http"
)

type authErr struct {
	code int
	err  error
}

// Code returns the HTTP status code for the error
func (e *authErr) Code() int {
	return e.code
}

// Err returns the wrapped error
func (e *authErr) Err() error {
	return e.err
}

// Error returns the error string
func (e *authErr) Error() string {
	return fmt.Sprintf("[%d] %s", e.code, e.err.Error())
}

// AuthErr is the interface to get more info on an auth error
type AuthErr interface {
	error
	Code() int
	Err() error
}

var errJWTMalformed = &authErr{code: http.StatusUnauthorized, err: errors.New("malformed JWT")}
var errJWTTime = &authErr{code: http.StatusUnauthorized, err: errors.New("JWT expired or not yet valid")}
var errJWTSignature = &authErr{code: http.StatusUnauthorized, err: errors.New("invalid JWT signature")}
var errJWTInvalid = &authErr{code: http.StatusUnauthorized, err: errors.New("invalid JWT")}
var errLoginMissingAuth = &authErr{code: http.StatusUnauthorized, err: errors.New("no authorization header")}
var errLoginInvalidAuth = &authErr{code: http.StatusBadRequest, err: errors.New("invalid authorization header")}
var errLoginAuthNotFound = &authErr{code: http.StatusBadRequest, err: errors.New("invalid authorization header")}
var errLoginInvalidUserPass = &authErr{code: http.StatusBadRequest, err: errors.New("invalid username or password")}
var errLoginIncorrectUserPass = &authErr{code: http.StatusUnauthorized, err: errors.New("incorrect username or password")}
