package goauth

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// ImplicitGrant implements methods required to
// perform an Implicit Grant Grant as per http://tools.ietf.org/html/rfc6749#section-4.2
type ImplicitGrant interface {
	// GetClient returns a Client given a client ID. It returns an error if the client is not found or if
	// the client ID is invalid.
	GetClient(clientID string) (Client, error)
}

// generateImplicitGrantHandler returns an http.HandlerFunc using the provided ImplicitGrant and SessionStore implementation.
func generateImplicitGrantHandler(ig ImplicitGrant, sessionStore *SessionStore) http.HandlerFunc {
	// Return a http.HandlerFunc
	return func(w http.ResponseWriter, r *http.Request) {
		// Check that the grant type is set to password
		if r.FormValue(ParamResponseType) != ResponseTypeToken {
			w.WriteHeader(http.StatusBadRequest)
			DefaultErrorHandler(w, ErrorInvalidRequest)
			return
		}
		rawurl := r.FormValue(ParamRedirectURI)
		if rawurl == "" {
			// The there is no redirect url then return an error
			w.WriteHeader(http.StatusBadRequest)
			DefaultErrorHandler(w, ErrorInvalidRequest)
			return
		}
		uri, err := url.Parse(rawurl)
		if err != nil {
			// The redirect URI is an invalid url, therefore, return an error and DO NOT redirect
			w.WriteHeader(http.StatusBadRequest)
			DefaultErrorHandler(w, ErrorInvalidRequest)
			return
		}
		// Get the client id
		clientID := r.FormValue(ParamClientID)
		if clientID == "" {
			implicitErrorRedirect(w, r, rawurl, ErrorUnauthorizedClient)
			return
		}
		// Find the client
		client, err := ig.GetClient(clientID)
		if err != nil {
			implicitErrorRedirect(w, r, rawurl, ErrorUnauthorizedClient)
			return
		}
		// Get the scope (OPTIONAL) and authorize it
		rawScope := r.FormValue(ParamScope)
		scope := strings.Split(rawScope, " ")
		scope, err = client.AuthorizeScope(scope)
		if err != nil {
			implicitErrorRedirect(w, r, rawurl, ErrorInvalidScope)
			return
		}
		// Get the redirect_uri and authorize it
		redirectURI := r.FormValue(ParamRedirectURI)
		err = client.AuthorizeRedirectURI(redirectURI)
		if err != nil {
			implicitErrorRedirect(w, r, rawurl, ErrorUnauthorizedClient)
			return
		}
		// Create a new grant
		grant, err := sessionStore.NewGrant(scope)
		if err != nil {
			implicitErrorRedirect(w, r, rawurl, ErrorUnauthorizedClient)
			return
		}
		// Redirect passing the grant to the redirect uri
		frag := url.Values{}
		frag.Add(ParamAccessToken, grant.AccessToken.RawString())
		frag.Add(ParamExpiresIn, strconv.Itoa(grant.ExpiresIn))
		frag.Add(ParamTokenType, grant.TokenType)
		frag.Add(ParamScope, strings.Join(scope, " "))
		// If the state param was included then make sure it is passed onto the redirect
		if r.FormValue(ParamState) != "" {
			frag.Add(ParamState, r.FormValue(ParamState))
		}
		uri.Fragment = frag.Encode()
		urlStr := uri.String()
		http.Redirect(w, r, urlStr, http.StatusFound)
	}
}

func implicitErrorRedirect(w http.ResponseWriter, r *http.Request, redirectURI string, e Error) {
	frag := url.Values{}
	frag.Add(ParamError, e.Code)
	frag.Add(ParamErrorDescription, e.Description)
	uri, err := url.Parse(redirectURI)
	if err != nil {
		http.Redirect(w, r, redirectURI, http.StatusBadRequest)
		return
	}
	uri.Fragment = frag.Encode()
	urlStr := uri.String()
	http.Redirect(w, r, urlStr, http.StatusFound)
}
