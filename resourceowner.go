package goauth

import (
	"net/http"
	"strings"
)

// ResourceOwnerPasswordCredentialsGrant implements methods required to
// perform a Resource Owner Password Credentials Grant as per http://tools.ietf.org/html/rfc6749#section-4.3
type ResourceOwnerPasswordCredentialsGrant interface {
	// GetClientWithSecret returns a Client given a client ID and secret. It returns an error if the client
	// is not found or if the client ID is invalid.
	GetClientWithSecret(clientID string, clientSecret Secret) (Client, error)
	// AuthorizeGrant checks the resource owners credentials and requested scope. If successful it returns
	// a new AuthorizationCode, otherwise, it returns an error.
	AuthorizeGrant(username string, password Secret, scope []string) ([]string, error)
}

// generateResourceOwnerPasswordCredentialsGrant returns an http.HandlerFunc using the provided ResourceOwnerPasswordCredentialsGrant and SessionStore.
func generateResourceOwnerPasswordCredentialsGrant(ropcg ResourceOwnerPasswordCredentialsGrant, sessionStore *SessionStore) http.HandlerFunc {
	// Return a http.HandlerFunc
	return func(w http.ResponseWriter, r *http.Request) {
		// Check that the grant type is set to password
		if r.PostFormValue(ParamGrantType) != GrantTypePassword {
			w.WriteHeader(http.StatusBadRequest)
			DefaultErrorHandler(w, ErrorInvalidRequest)
			return
		}
		// Authorize the client using basic auth
		clientID, clientSecret, ok := r.BasicAuth()
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			DefaultErrorHandler(w, ErrorAccessDenied)
			return
		}
		client, err := ropcg.GetClientWithSecret(clientID, Secret(clientSecret))
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			DefaultErrorHandler(w, err)
			return
		}
		// Get the username
		username := r.PostFormValue("username")
		if username == "" {
			w.WriteHeader(http.StatusUnauthorized)
			DefaultErrorHandler(w, ErrorAccessDenied)
			return
		}
		// Check that the client is permitted to act on behalf of the resource owner.
		err = client.AuthorizeResourceOwner(username)
		if err != nil {
			// An error means that the Client is not approved for this resource owner.
			// w.WriteHeader(http.StatusUnauthorized)
			DefaultErrorHandler(w, err)
			return
		}
		// Get the password
		password := r.PostFormValue("password")
		if password == "" {
			w.WriteHeader(http.StatusUnauthorized)
			DefaultErrorHandler(w, ErrorAccessDenied)
			return
		}
		// Get the scope (OPTIONAL)
		rawScope := r.PostFormValue(ParamScope)
		scope := strings.Split(rawScope, " ")
		// Authorize the scope against the client
		scope, err = client.AuthorizeScope(scope)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			DefaultErrorHandler(w, ErrorUnauthorizedClient)
			return
		}
		// Authorize the resource owner
		scope, err = ropcg.AuthorizeGrant(username, Secret(password), scope)
		if err != nil {
			// If an error occurs then the client / resource owner must not have access
			w.WriteHeader(http.StatusUnauthorized)
			DefaultErrorHandler(w, err)
			return
		}
		grant, err := sessionStore.NewGrant(scope)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			DefaultErrorHandler(w, err)
			return
		}
		// Write the grant to the http response
		err = grant.Write(w)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			DefaultErrorHandler(w, err)
			return
		}
	}
}
