package goauth

import (
	"net/http"
	"strings"
)

func (s Server) Secure(requiredScope []string, handler http.HandlerFunc) http.HandlerFunc {
	switch DefaultTokenType {
	case TokenTypeBearer:
		return s.checkBearerAuth(s.SessionStore, requiredScope, handler)
	case TokenTypeMac:
		return s.checkMacAuth(s.SessionStore, requiredScope, handler)
	default:
		return func(w http.ResponseWriter, r *http.Request) {
			s.ErrorHandler(w, ErrorServerError.StatusCode, ErrorServerError)
		}
	}
}

func GetBearerToken(r *http.Request) (Secret, error) {
	// Get the authorization header
	cred := r.Header.Get("Authorization")
	if cred == "" {
		// If not present set status and return error
		return "", ErrorAccessDenied
	}
	// Check that the method is Mac
	if strings.Index(cred, "Bearer") != 0 {
		return "", ErrorAccessDenied
	}
	// Trim the auth header (it should be prefixed with Bearer\s)
	accessToken := strings.TrimPrefix(cred, "Bearer ")
	return Secret(accessToken), nil
}

// checkBearerAuth returns an http.HandlerFunc that authenticates requests using the bearer token authorization.
func (s Server) checkBearerAuth(sessionStore *SessionStore, requiredScope []string, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		accessToken, err := GetBearerToken(r)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			s.ErrorHandler(w, ErrorAccessDenied.StatusCode, ErrorAccessDenied)
			return
		}
		grant, err := sessionStore.CheckGrant(accessToken)
		if err != nil {
			// If not present set status and return error
			w.WriteHeader(http.StatusUnauthorized)
			s.ErrorHandler(w, ErrorAccessDenied.StatusCode, ErrorAccessDenied)
			return
		}
		// If required scope is provided then check that the request is allowed
		if requiredScope != nil {
			err := grant.CheckScope(requiredScope)
			if err != nil {
				// If not present set status and return error
				w.WriteHeader(http.StatusUnauthorized)
				s.ErrorHandler(w, ErrorAccessDenied.StatusCode, ErrorAccessDenied)
				return
			}
		}
		// Assuming all of the above checks have
		// passed then call the handler.
		handler(w, r)
	}
}

// checkMacAuth returns an http.HandlerFunc that is currently not implemented to accept mac token authentication. s
func (s Server) checkMacAuth(sessionStore *SessionStore, requiredScope []string, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.ErrorHandler(w, ErrorInvalidRequest.StatusCode, ErrorInvalidRequest)
	}
}
