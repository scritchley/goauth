package goauth

import (
	"html/template"
	"net/http"
)

const (
	AuthorizeEnpoint = "/authorize"
	TokenEndpoint    = "/token"
)

type handler struct {
	mux *http.ServeMux
	ss  *SessionStore
}

func New() handler {
	mux := http.NewServeMux()
	mux.HandleFunc(AuthorizeEnpoint, authorizeHandler)
	mux.HandleFunc(TokenEndpoint, tokenHandler)
	return handler{
		mux,
		DefaultSessionStore,
	}
}

// UseSessionStore overrides the referenced SessionStore implementation for the handler.
func (h handler) UseSessionStore(ss *SessionStore) {
	*h.ss = *ss
}

// ServeHTTP implements the http.Handler interface.
func (h handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

// RegisterAuthorizationGrant registers handlers for the given AuthorizationCodeGrant interface using the provided template
// for performing user agent authentication.
func (h handler) RegisterAuthorizationCodeGrant(acg AuthorizationCodeGrant, tmpl *template.Template) {
	tokenHandlers.AddHandler(GrantTypeAuthorizationCode, generateAuthCodeTokenRequestHandler(acg, h.ss))
	authorizeHandlers.AddHandler(ResponseTypeCode, generateAuthorizationCodeGrantHandler(acg, tmpl, h.ss))
}

// RegisterImplicitGrant registers handlers for the provided ImplicitGrant interface.
func (h handler) RegisterImplicitGrant(ig ImplicitGrant) {
	authorizeHandlers.AddHandler(ResponseTypeToken, generateImplicitGrantHandler(ig, h.ss))
}

// RegisterResourceOwnerPasswordCredentialsGrant registers handlers for the provided ResourceOwnerPasswordCredentialsGrant interface.
func (h handler) RegisterResourceOwnerPasswordCredentialsGrant(ropcg ResourceOwnerPasswordCredentialsGrant) {
	tokenHandlers.AddHandler(GrantTypePassword, generateResourceOwnerPasswordCredentialsGrant(ropcg, h.ss))
}

// RegisterClientCredentialsGrant registers handlers for the provided ClientCredentialsGrant interface.
func (h handler) RegisterClientCredentialsGrant(ccg ClientCredentialsGrant) {
	tokenHandlers.AddHandler(GrantTypeClientCredentials, generateClientCredentialsGrantHandler(ccg, h.ss))
}
