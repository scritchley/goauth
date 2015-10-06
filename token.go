package goauth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

// TokenType is the type of the token and defines how it
// must be used in order to authenticate requests.
type TokenType string

const (
	// TokenTypeBearer is the bearer token type.
	TokenTypeBearer = "bearer"
	// TokenTypeMac is the mac token type.
	TokenTypeMac = "mac"
)

var (
	// DefaultTokenExpiry is the default number of seconds
	// that a token is
	DefaultTokenExpiry = 3600
	// DefaultTokenType is the default token type that should be used when creating new tokens.
	DefaultTokenType = TokenTypeBearer
	// NewToken is a utility method for generating a new token that can be overriden in testing.
	NewToken = newToken
	// tokenHandlers is a map of http.HandlerFuncs that are indexed by GrantType.
	tokenHandlers = make(TokenHandlers)
)

// newToken generates a new token and returns it as a secret.
func newToken() Secret {
	b := make([]byte, 24)
	n, err := io.ReadFull(rand.Reader, b)
	if n != len(b) || err != nil {
		panic(err)
	}
	return Secret(base64.URLEncoding.EncodeToString(b))
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
func tokenHandler(w http.ResponseWriter, r *http.Request) {
	grantType := r.FormValue(ParamGrantType)
	if handler, ok := tokenHandlers[GrantType(grantType)]; ok {
		handler(w, r)
		return
	}
	DefaultErrorHandler(w, ErrorInvalidRequest)
}

// Grant represents an authorization grant consisting of an access token, an optional refresh token
// and additional fields containing details of the authentication session.
type Grant struct {
	AccessToken  Secret
	TokenType    string
	ExpiresIn    int
	RefreshToken Secret
	Scope        []string
	CreatedAt    time.Time
	Client       Client
}

// Refresh refreshes the Grant providing it with a new.
func (g *Grant) Refresh() {
	g.AccessToken = NewToken()
	g.RefreshToken = NewToken()
	g.TokenType = DefaultTokenType
	g.ExpiresIn = DefaultTokenExpiry
	g.CreatedAt = timeNow()
}

// IsExpired returns true if the grant has expired, else it returns false.
func (g *Grant) IsExpired() bool {
	if g.CreatedAt.Add(time.Duration(g.ExpiresIn) * time.Second).After(timeNow()) {
		return false
	}
	return true
}

func (g *Grant) CheckScope(requiredScope []string) error {
	// For each of the required scopes check that the grant has access
	for _, check := range requiredScope {
		if !checkInScope(check, g.Scope) {
			return ErrorAccessDenied
		}
	}
	if g.Client != nil {
		scope, err := g.Client.AuthorizeScope(requiredScope)
		if err != nil {
			return ErrorAccessDenied
		}
		if scope != nil {
			// For each of the required scopes check that the client has access
			for _, check := range requiredScope {
				if !checkInScope(check, scope) {
					return ErrorAccessDenied
				}
			}
		}
	}
	return nil
}

// checkInScope checks whether check is present in scope returning a bool.
func checkInScope(check string, scope []string) bool {
	for _, s := range scope {
		if s == check {
			return true
		}
	}
	return false
}

// Write marshals the Grant into JSON, including only the required fields and writes it
// to the provided io.Writer. It is used to return Grants in an http response.
func (g *Grant) Write(w io.Writer) error {
	m := make(map[string]interface{})
	m["access_token"] = g.AccessToken
	m["token_type"] = g.TokenType
	m["expires_in"] = g.ExpiresIn
	if g.RefreshToken != "" {
		m["refresh_token"] = g.RefreshToken
	}
	if g.Scope != nil {
		m["scope"] = strings.Join(g.Scope, " ")
	}
	enc := json.NewEncoder(w)
	return enc.Encode(m)
}
