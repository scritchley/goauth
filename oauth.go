package goauth

import (
	"html/template"
	"net/http"
)

const (
	AuthorizeEnpoint = "/authorize"
	TokenEndpoint    = "/token"
)

func ApplyRoutes(mux *http.ServeMux) {
	mux.HandleFunc(AuthorizeEnpoint, authorizeHandler)
	mux.HandleFunc(TokenEndpoint, tokenHandler)
}

func RegisterAuthorizationCodeGrant(acg AuthorizationCodeGrant, tmpl *template.Template, ss *SessionStore) {
	tokenHandlers.AddHandler(GrantTypeAuthorizationCode, generateAuthCodeTokenRequestHandler(acg, ss))
	authorizeHandlers.AddHandler(ResponseTypeCode, generateAuthorizationCodeGrantHandler(acg, tmpl, ss))
}

func RegisterImplicitGrant(ig ImplicitGrant, ss *SessionStore) {
	authorizeHandlers.AddHandler(ResponseTypeToken, generateImplicitGrantHandler(ig, ss))
}

func RegisterResourceOwnerPasswordCredentialsGrant(ropcg ResourceOwnerPasswordCredentialsGrant, ss *SessionStore) {
	tokenHandlers.AddHandler(GrantTypePassword, generateResourceOwnerPasswordCredentialsGrant(ropcg, ss))
}

func RegisterClientCredentialsGrant(ccg ClientCredentialsGrant, ss *SessionStore) {
	tokenHandlers.AddHandler(GrantTypeClientCredentials, generateClientCredentialsGrantHandler(ccg, ss))
}
