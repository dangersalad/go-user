package user

import (
	"context"
	"fmt"
	"net/http"
)

// TokenCheckHandler returns an http.Handler that checks cookie for a
// JWT, parses it and sets the claims to the request context
func TokenCheckHandler(h http.Handler, conf *AuthConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// if we are trying to authenticate, let the request go on
		if conf.Bypass != nil && conf.Bypass.CanBypass(r.Method, r.URL.Path) {
			h.ServeHTTP(w, r)
			return
		}

		cookie, err := r.Cookie(conf.cookieName())
		if err != nil {
			conf.handleError(&authErr{
				code: http.StatusUnauthorized,
				err:  fmt.Errorf("getting cookie: %w", err),
			}, w, r)
			return
		}

		claims, token, err := conf.updateAndSetCookie(cookie.Value, w, r)
		if err != nil {
			conf.handleError(err, w, r)
			return
		}

		// now that we have the claims and validated the token,
		// set some values on the request context
		r = r.WithContext(context.WithValue(r.Context(), ContextKeyClaims, claims))
		r = r.WithContext(context.WithValue(r.Context(), ContextKeyToken, token))
		h.ServeHTTP(w, r)

	})
}
