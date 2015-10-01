package goauth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

type TokenType string

const (
	TokenTypeBearer = "bearer"
)

var (
	// DefaultTokenExpiry is the default number of seconds
	// that a token is
	DefaultTokenExpiry = 3600
	// DefaultTokenType is the default token type that should be used when creating new tokens
	DefaultTokenType = TokenTypeBearer
	// NewToken is a utility method for generating a new token that can be overriden in testing.
	NewToken      = newToken
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

type TokenHandlers map[GrantType]http.HandlerFunc

func (t TokenHandlers) AddHandler(grantType GrantType, handler http.HandlerFunc) {
	t[grantType] = handler
}

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
	AccessToken  Secret    `json:"access_token,omitempty"`
	TokenType    string    `json:"token_type,omitempty"`
	ExpiresIn    int       `json:"expires_in,omitempty"`
	RefreshToken Secret    `json:"refresh_token,omitempty"`
	Scope        string    `json:"scope,omitempty"`
	CreatedAt    time.Time `json:"-"`
}

func (g *Grant) Refresh() {
	g.AccessToken = NewToken()
	g.RefreshToken = NewToken()
	g.TokenType = DefaultTokenType
	g.ExpiresIn = DefaultTokenExpiry
	g.CreatedAt = timeNow()
}

func (g *Grant) Write(w io.Writer) error {
	enc := json.NewEncoder(w)
	return enc.Encode(g)
}
