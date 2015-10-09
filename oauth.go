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
	mux               *http.ServeMux
	SessionStore      *SessionStore
	ErrorHandler      ErrorHandler
	Authenticator     Authenticator
	AuthorizeTemplate *template.Template
	authorizeHandlers AuthorizeHandlers
	tokenHandlers     TokenHandlers
}

// Authenticator implements methods required to perform
// an Authorization Code Grant as per http://tools.ietf.org/html/rfc6749#section-4.1
type Authenticator interface {
	// GetClient returns a Client given a client ID. It returns an error if the client is not found or if
	// the client ID is invalid.
	GetClient(clientID string) (Client, error)
	// GetClientWithSecret returns a Client given a client ID and secret. It returns an error if the client
	// is not found or if the client ID is invalid.
	GetClientWithSecret(clientID string, clientSecret Secret) (Client, error)
	// AuthorizeResourceOwner checks the resource owners credentials and requested scope. If successful it returns
	// the approved scope, otherwise, it returns an error.
	AuthorizeResourceOwner(username string, password Secret, scope []string) ([]string, error)
}

// New creates a handler implementing the http.Handler interface.
func New(a Authenticator) handler {
	h := handler{
		mux:               http.NewServeMux(),
		SessionStore:      DefaultSessionStore,
		ErrorHandler:      DefaultErrorHandler,
		tokenHandlers:     make(TokenHandlers),
		authorizeHandlers: make(AuthorizeHandlers),
		AuthorizeTemplate: DefaultAuthorizationTemplate,
		Authenticator:     a,
	}
	// Add the Authorization Code Grant handlers
	h.tokenHandlers.AddHandler(GrantTypeAuthorizationCode, h.handleAuthCodeTokenRequest)
	h.authorizeHandlers.AddHandler(ResponseTypeCode, h.handleAuthorizationCodeGrant)

	// Add the Implicit Grant handlers
	h.authorizeHandlers.AddHandler(ResponseTypeToken, h.handleImplicitGrant)

	// Add the Resource Owner Password Credentials Grant handlers
	h.tokenHandlers.AddHandler(GrantTypePassword, h.handleResourceOwnerPasswordCredentialsGrant)

	// Add the Client Credentials Grant handler
	h.tokenHandlers.AddHandler(GrantTypeClientCredentials, h.handleClientCredentialsGrant)

	// Configure the authorize and token handlers against the router mux
	h.mux.HandleFunc(AuthorizeEnpoint, h.authorizeHandler)
	h.mux.HandleFunc(TokenEndpoint, h.tokenHandler)

	// Return the handler
	return h
}

// ServeHTTP implements the http.Handler interface.
func (h handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

// TokenHandlers is a map of http.Handerfuncs indexed by GrantType.
type TokenHandlers map[GrantType]http.HandlerFunc

// AddHandler adds a http.HandlerFunc indexed against the provided GrantType. Only one handler can be registered
// against a grant type.
func (t TokenHandlers) AddHandler(grantType GrantType, handler http.HandlerFunc) {
	t[grantType] = handler
}

// tokenHandler is a http.HandlerFunc that can be used to satisfy token requests. If a handler is registered
// against the requests grant type then it is used, else an error is returned in the response.
func (h handler) tokenHandler(w http.ResponseWriter, r *http.Request) {
	grantType := r.FormValue(ParamGrantType)
	if handler, ok := h.tokenHandlers[GrantType(grantType)]; ok {
		handler(w, r)
		return
	}
	h.ErrorHandler(w, ErrorInvalidRequest)
}

// AuthorizeHandlers is a map of http.Handerfuncs indexed by ResponseType.
type AuthorizeHandlers map[ResponseType]http.HandlerFunc

// AddHandler adds a http.HandlerFunc indexed against the provided ResponseType. Only one handler can be registered
// against a grant type.
func (a AuthorizeHandlers) AddHandler(responseType ResponseType, handler http.HandlerFunc) {
	a[responseType] = handler
}

func (h handler) authorizeHandler(w http.ResponseWriter, r *http.Request) {
	responseType := r.FormValue(ParamResponseType)
	if handler, ok := h.authorizeHandlers[ResponseType(responseType)]; ok {
		handler(w, r)
		return
	}
	h.ErrorHandler(w, ErrorInvalidRequest)
}
