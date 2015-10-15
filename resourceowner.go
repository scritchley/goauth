package goauth

import (
	"net/http"
	"strings"
)

func (s Server) handleResourceOwnerPasswordCredentialsGrant(w http.ResponseWriter, r *http.Request) {
	// Check that the grant type is set to password
	if r.PostFormValue(ParamGrantType) != GrantTypePassword {
		w.WriteHeader(http.StatusBadRequest)
		s.ErrorHandler(w, ErrorInvalidRequest)
		return
	}
	// Authorize the client using basic auth
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		s.ErrorHandler(w, ErrorAccessDenied)
		return
	}
	client, err := s.Authenticator.GetClientWithSecret(clientID, Secret(clientSecret))
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		s.ErrorHandler(w, err)
		return
	}
	// Check that the client is allowed for this grant type
	ok, err = client.AllowStrategy(StrategyResourceOwnerPasswordCredentials)
	if err != nil {
		// Failed to determine whether grant type allowed, return an error
		w.WriteHeader(http.StatusInternalServerError)
		s.ErrorHandler(w, err)
		return
	}
	if !ok {
		// The client is not authorized for the grant type, therefore, return an error
		w.WriteHeader(http.StatusUnauthorized)
		s.ErrorHandler(w, ErrorUnauthorizedClient)
		return
	}
	// Get the username
	username := r.PostFormValue("username")
	if username == "" {
		w.WriteHeader(http.StatusUnauthorized)
		s.ErrorHandler(w, ErrorAccessDenied)
		return
	}
	// Check that the client is permitted to act on behalf of the resource owner.
	allowed, err := client.AuthorizeResourceOwner(username)
	if err != nil {
		// An error means that the Client is not approved for this resource owner.
		// w.WriteHeader(http.StatusUnauthorized)
		s.ErrorHandler(w, err)
		return
	}
	if !allowed {
		// If not allowed return an unauthorized client error
		s.ErrorHandler(w, ErrorUnauthorizedClient)
		return
	}
	// Get the password
	password := r.PostFormValue("password")
	if password == "" {
		w.WriteHeader(http.StatusUnauthorized)
		s.ErrorHandler(w, ErrorAccessDenied)
		return
	}
	// Get the scope (OPTIONAL)
	rawScope := r.PostFormValue(ParamScope)
	scope := strings.Split(rawScope, " ")
	// Authorize the scope against the client
	scope, err = client.AuthorizeScope(scope)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		s.ErrorHandler(w, ErrorUnauthorizedClient)
		return
	}
	// Authorize the resource owner
	scope, err = s.Authenticator.AuthorizeResourceOwner(username, Secret(password), scope)
	if err != nil {
		// If an error occurs then the client / resource owner must not have access
		w.WriteHeader(http.StatusUnauthorized)
		s.ErrorHandler(w, err)
		return
	}
	grant, err := s.SessionStore.NewGrant(scope)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		s.ErrorHandler(w, err)
		return
	}
	// Write the grant to the http response
	err = grant.Write(w)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		s.ErrorHandler(w, err)
		return
	}
}
