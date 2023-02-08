package user

import (
	"context"
	"github.com/golang-jwt/jwt/v4"
	"net/http"
)

type contextKey string

func (c contextKey) String() string {
	return string(c)
}

var (
	// ContextKeyClaims is the context key for claims
	ContextKeyClaims = contextKey("dangersalad/go-user:jwt-claims")
	// ContextKeyToken is the context key for the token string
	ContextKeyToken = contextKey("dangersalad/go-user:jwt-token")
)

// ContextClaims returns the JWT claims stored on the context
func ContextClaims(ctx context.Context) (jwt.Claims, bool) {
	v, ok := ctx.Value(ContextKeyClaims).(jwt.Claims)
	return v, ok
}

// ContextToken returns the JWT token stored on the context
func ContextToken(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(ContextKeyToken).(string)
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
