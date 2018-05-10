package user

import (
	"context"
	"github.com/dgrijalva/jwt-go"
	"net/http"
)

type contextKey string

func (c contextKey) String() string {
	return string(c)
}

var (
	contextKeyClaims = contextKey("dangersalad/go-user:jwt-claims")
	contextKeyToken  = contextKey("dangersalad/go-user:jwt-token")
)

// ContextClaims returns the JWT claims stored on the context
func ContextClaims(ctx context.Context) (jwt.Claims, bool) {
	v, ok := ctx.Value(contextKeyClaims).(jwt.Claims)
	return v, ok
}

// ContextToken returns the JWT token stored on the context
func ContextToken(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(contextKeyToken).(string)
	return v, ok
}

// RequestClaims returns the JWT claims stored on the request context
func RequestClaims(r http.Request) (jwt.Claims, bool) {
	return ContextClaims(r.Context())
}

// RequestToken returns the JWT token stored on the request context
func RequestToken(r http.Request) (string, bool) {
	return ContextToken(r.Context())
}
