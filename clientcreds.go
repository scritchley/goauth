package goauth

import (
	"net/http"
	"strings"
)

func (h handler) handleClientCredentialsGrant(w http.ResponseWriter, r *http.Request) {
	// Check that the grant type is set to password
	if r.PostFormValue(ParamGrantType) != GrantTypeClientCredentials {
		w.WriteHeader(http.StatusBadRequest)
		h.ErrorHandler(w, ErrorInvalidRequest)
		return
	}
	// Authorize the client using basic auth
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		h.ErrorHandler(w, ErrorAccessDenied)
		return
	}
	client, err := h.Authenticator.GetClientWithSecret(clientID, Secret(clientSecret))
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		h.ErrorHandler(w, err)
		return
	}
	// Get the scope (OPTIONAL)
	rawScope := r.PostFormValue(ParamScope)
	scope := strings.Split(rawScope, " ")
	scope, err = client.AuthorizeScope(scope)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		h.ErrorHandler(w, ErrorUnauthorizedClient)
		return
	}
	grant, err := h.SessionStore.NewGrant(scope)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		h.ErrorHandler(w, err)
		return
	}
	// Write the grant to the http response
	err = grant.Write(w)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		h.ErrorHandler(w, err)
		return
	}
}
