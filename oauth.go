package goauth

import (
	"html/template"
	"net/http"
)

const (
	AuthorizeEnpoint = "/authorize"
	TokenEndpoint    = "/token"
)

type Server struct {
	sessionStore *SessionStore
	mux          *http.ServeMux
}

func NewServer(sessionStore *SessionStore) *Server {
	s := &Server{
		sessionStore,
		http.NewServeMux(),
	}
	s.mux.HandleFunc(AuthorizeEnpoint, authorizeHandler)
	s.mux.HandleFunc(TokenEndpoint, tokenHandler)
	return s
}

func (s *Server) AuthorizationCodeGrant(acg AuthorizationCodeGrant, tmpl *template.Template) {
	tokenHandlers.AddHandler(GrantTypeAuthorizationCode, generateAuthCodeTokenRequestHandler(acg, s.sessionStore))
	authorizeHandlers.AddHandler(ResponseTypeCode, generateAuthorizationCodeGrantHandler(acg, tmpl, s.sessionStore))
}

func (s *Server) ImplicitGrant(ig ImplicitGrant) {
	authorizeHandlers.AddHandler(ResponseTypeToken, generateImplicitGrantHandler(ig, s.sessionStore))
}

func (s *Server) ResourceOwnerPasswordCredentialsGrant(ropcg ResourceOwnerPasswordCredentialsGrant) {
	tokenHandlers.AddHandler(GrantTypePassword, generateResourceOwnerPasswordCredentialsGrant(ropcg, s.sessionStore))
}

func (s *Server) ClientCredentialsGrant(ccg ClientCredentialsGrant) {
	tokenHandlers.AddHandler(GrantTypeClientCredentials, generateClientCredentialsGrantHandler(ccg, s.sessionStore))
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}
