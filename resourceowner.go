package goauth

import (
	"net/http"
	"strings"
)

func (s Server) handleResourceOwnerPasswordCredentialsGrant(w http.ResponseWriter, r *http.Request) {
	// Check that the grant type is set to password
	if r.PostFormValue(ParamGrantType) != GrantTypePassword {
		w.WriteHeader(http.StatusBadRequest)
		s.ErrorHandler(w, ErrorInvalidRequest.StatusCode, ErrorInvalidRequest)
		return
	}
	// Authorize the client using basic auth
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		s.ErrorHandler(w, ErrorAccessDenied.StatusCode, ErrorAccessDenied)
		return
	}
	client, err := s.Authenticator.GetClientWithSecret(clientID, Secret(clientSecret))
	if err != nil {
		s.ErrorHandler(w, http.StatusUnauthorized, err)
		return
	}
	// Check that the client is allowed for this grant type
	ok = client.AllowStrategy(StrategyResourceOwnerPasswordCredentials)
	if !ok {
		// The client is not authorized for the grant type, therefore, return an error
		s.ErrorHandler(w, ErrorUnauthorizedClient.StatusCode, ErrorUnauthorizedClient)
		return
	}
	// Get the username
	username := r.PostFormValue("username")
	if username == "" {
		w.WriteHeader(http.StatusUnauthorized)
		s.ErrorHandler(w, ErrorAccessDenied.StatusCode, ErrorAccessDenied)
		return
	}
	// Check that the client is permitted to act on behalf of the resource owner.
	allowed, err := client.AuthorizeResourceOwner(username)
	if err != nil {
		// An error means that the Client is not approved for this resource owner.
		// w.WriteHeader(http.StatusUnauthorized)
		s.ErrorHandler(w, http.StatusUnauthorized, err)
		return
	}
	if !allowed {
		// If not allowed return an unauthorized client error
		s.ErrorHandler(w, ErrorUnauthorizedClient.StatusCode, ErrorUnauthorizedClient)
		return
	}
	// Get the password
	password := r.PostFormValue("password")
	if password == "" {
		s.ErrorHandler(w, ErrorAccessDenied.StatusCode, ErrorAccessDenied)
		return
	}
	// Get the scope (OPTIONAL)
	rawScope := r.PostFormValue(ParamScope)
	scope := strings.Split(rawScope, " ")
	// Authorize the scope against the client
	scope, err = client.AuthorizeScope(scope)
	if err != nil {
		s.ErrorHandler(w, ErrorUnauthorizedClient.StatusCode, ErrorUnauthorizedClient)
		return
	}
	// Authorize the resource owner
	isAuthorized, err := s.Authenticator.AuthorizeResourceOwner(username, Secret(password), scope)
	if err != nil || !isAuthorized {
		// If an error occurs then the client / resource owner must not have access
		s.ErrorHandler(w, http.StatusUnauthorized, err)
		return
	}
	grant, err := client.CreateGrant(scope)
	if err != nil {
		s.ErrorHandler(w, http.StatusInternalServerError, err)
		return
	}
	err = s.SessionStore.PutGrant(grant)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		s.ErrorHandler(w, ErrorServerError.StatusCode, ErrorServerError)
		return
	}
	// Write the grant to the http response
	err = grant.Write(w)
	if err != nil {
		s.ErrorHandler(w, http.StatusInternalServerError, err)
		return
	}
}
