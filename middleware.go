package goauth

import (
	"net/http"
	"strings"
)

func (h handler) Secure(requiredScope []string, handler http.HandlerFunc) http.HandlerFunc {
	switch DefaultTokenType {
	case TokenTypeBearer:
		return checkBearerAuth(h.SessionStore, requiredScope, handler)
	case TokenTypeMac:
		return checkMacAuth(h.SessionStore, requiredScope, handler)
	default:
		return func(w http.ResponseWriter, r *http.Request) {
			h.ErrorHandler(w, ErrorServerError)
		}
	}
}

// checkBearerAuth returns an http.HandlerFunc that authenticates requests using the bearer token authorization.
func checkBearerAuth(sessionStore *SessionStore, requiredScope []string, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get the authorization header
		cred := r.Header.Get("Authorization")
		if cred == "" {
			// If not present set status and return error
			w.WriteHeader(http.StatusUnauthorized)
			DefaultErrorHandler(w, ErrorAccessDenied)
			return
		}
		// Check that the method is Mac
		if strings.Index(cred, "Bearer") != 0 {
			w.WriteHeader(http.StatusUnauthorized)
			DefaultErrorHandler(w, ErrorAccessDenied)
			return
		}
		// Trim the auth header (it should be prefixed with Bearer\s)
		accessToken := strings.TrimPrefix(cred, "Bearer ")
		grant, err := sessionStore.CheckGrant(Secret(accessToken))
		if err != nil {
			// If not present set status and return error
			w.WriteHeader(http.StatusUnauthorized)
			DefaultErrorHandler(w, ErrorAccessDenied)
			return
		}
		// If required scope is provided then check that the request is allowed
		if requiredScope != nil {
			err := grant.CheckScope(requiredScope)
			if err != nil {
				// If not present set status and return error
				w.WriteHeader(http.StatusUnauthorized)
				DefaultErrorHandler(w, ErrorAccessDenied)
				return
			}
		}
		// Assuming all of the above checks have
		// passed then call the handler.
		handler(w, r)
	}
}

// checkMacAuth returns an http.HandlerFunc that is currently not implemented to accept mac token authentication. s
func checkMacAuth(sessionStore *SessionStore, requiredScope []string, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		DefaultErrorHandler(w, ErrorInvalidRequest)
	}
}
