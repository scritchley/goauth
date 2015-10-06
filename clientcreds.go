package goauth

import (
	"net/http"
	"strings"
)

// ClientCredentialsGrant implements methods required to
// perform a Client Credentials Grant as per http://tools.ietf.org/html/rfc6749#section-4.4
type ClientCredentialsGrant interface {
	// GetClientWithSecret returns a Client given a client ID and secret. It returns an error if the client
	// is not found or if the client ID is invalid.
	GetClientWithSecret(clientID string, clientSecret Secret) (Client, error)
}

// generateClientCredentialsGrantHandler returns an http.HandlerFunc using the provided ClientCredentialsGrant and SessionStore implementation.
func generateClientCredentialsGrantHandler(ccg ClientCredentialsGrant, sessionStore *SessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check that the grant type is set to password
		if r.PostFormValue(ParamGrantType) != GrantTypeClientCredentials {
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
		client, err := ccg.GetClientWithSecret(clientID, Secret(clientSecret))
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			DefaultErrorHandler(w, err)
			return
		}
		// Get the scope (OPTIONAL)
		rawScope := r.PostFormValue(ParamScope)
		scope := strings.Split(rawScope, " ")
		scope, err = client.AuthorizeScope(scope)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			DefaultErrorHandler(w, ErrorUnauthorizedClient)
			return
		}
		grant, err := sessionStore.NewGrant(client, scope)
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
