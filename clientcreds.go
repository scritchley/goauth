package goauth

import (
	"net/http"
	"strings"
)

func (s Server) handleClientCredentialsGrant(w http.ResponseWriter, r *http.Request) {
	// Check that the grant type is set to password
	if r.PostFormValue(ParamGrantType) != GrantTypeClientCredentials {
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
	ok = client.AllowStrategy(StrategyClientCredentials)
	if !ok {
		// The client is not authorized for the grant type, therefore, return an error
		s.ErrorHandler(w, ErrorUnauthorizedClient.StatusCode, ErrorUnauthorizedClient)
		return
	}
	// Get the scope (OPTIONAL)
	rawScope := r.PostFormValue(ParamScope)
	scope := strings.Split(rawScope, " ")
	scope, err = client.AuthorizeScope(scope)
	if err != nil {
		s.ErrorHandler(w, ErrorUnauthorizedClient.StatusCode, ErrorUnauthorizedClient)
		return
	}
	grant, err := s.SessionStore.NewGrant(scope)
	if err != nil {
		s.ErrorHandler(w, http.StatusInternalServerError, err)
		return
	}
	// Write the grant to the http response
	err = grant.Write(w)
	if err != nil {
		s.ErrorHandler(w, http.StatusInternalServerError, err)
		return
	}
}
