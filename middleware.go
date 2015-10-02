package goauth

import (
	"net/http"
	"strings"
)

// checkAuth returns an http.HandlerFunc that implemtns authentication as middleware before calling the provided
// handler.
func checkAuth(tokenType TokenType, sessionStore *SessionStore, requiredScope []string, handler http.HandlerFunc) http.HandlerFunc {
	switch tokenType {
	case TokenTypeBearer:
		return checkBearerAuth(sessionStore, requiredScope, handler)
	case TokenTypeMac:
		return checkMacAuth(sessionStore, requiredScope, handler)
	default:
		return func(w http.ResponseWriter, r *http.Request) {
			DefaultErrorHandler(w, ErrorServerError)
		}
	}
}

// checkInScope checks whether check is present in scope returning a bool.
func checkInScope(check string, scope []string) bool {
	for _, s := range scope {
		if s == check {
			return true
		}
	}
	return false
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
			DefaultErrorHandler(w, err)
			return
		}
		// If required scope is provided then check that the request is allowed
		if requiredScope != nil {
			if grant.Client == nil {
				// No stored client means that the check cannot be performed so
				// return an auth error
				w.WriteHeader(http.StatusUnauthorized)
				DefaultErrorHandler(w, ErrorAccessDenied)
				return
			}
			scope, err := grant.Client.AuthorizeScope(requiredScope)
			if err != nil {
				// If not present set status and return error
				w.WriteHeader(http.StatusUnauthorized)
				DefaultErrorHandler(w, ErrorAccessDenied)
			}
			// For each of the required scopes check that the client has access
			for _, check := range requiredScope {
				if !checkInScope(check, scope) {
					// If not present set status and return error
					w.WriteHeader(http.StatusUnauthorized)
					DefaultErrorHandler(w, ErrorAccessDenied)
					return
				}
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
