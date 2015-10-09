package goauth

import (
	"net/http"
	"strings"
)

func (h handler) handleResourceOwnerPasswordCredentialsGrant(w http.ResponseWriter, r *http.Request) {
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
	client, err := h.Authenticator.GetClientWithSecret(clientID, Secret(clientSecret))
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
	scope, err = h.Authenticator.AuthorizeResourceOwner(username, Secret(password), scope)
	if err != nil {
		// If an error occurs then the client / resource owner must not have access
		w.WriteHeader(http.StatusUnauthorized)
		DefaultErrorHandler(w, err)
		return
	}
	grant, err := h.SessionStore.NewGrant(scope)
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
