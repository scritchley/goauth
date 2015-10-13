package goauth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"time"
)

// TokenType is the type of the token and defines how it
// must be used in order to authenticate requests.
type TokenType string

const (
	// TokenTypeBearer is the bearer token type.
	TokenTypeBearer TokenType = "bearer"
	// TokenTypeMac is the mac token type.
	TokenTypeMac TokenType = "mac"
)

var (
	// DefaultTokenExpiry is the default number of seconds
	// that a token is
	DefaultTokenExpiry = time.Hour
	// DefaultTokenType is the default token type that should be used when creating new tokens.
	DefaultTokenType = TokenTypeBearer
	// NewToken is a utility method for generating a new token that can be overriden in testing.
	NewToken = newToken
)

// newToken generates a new token and returns it as a secret.
func newToken() (Secret, error) {
	b := make([]byte, 24)
	n, err := io.ReadFull(rand.Reader, b)
	if n != len(b) || err != nil {
		return "", err
	}
	return Secret(base64.URLEncoding.EncodeToString(b)), nil
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
}

// Refresh refreshes the Grant providing it with a new.
func (g *Grant) Refresh() error {
	accessToken, err := NewToken()
	if err != nil {
		return err
	}
	g.AccessToken = accessToken
	refreshToken, err := NewToken()
	if err != nil {
		return err
	}
	g.RefreshToken = refreshToken
	g.TokenType = string(DefaultTokenType)
	g.ExpiresIn = int(DefaultTokenExpiry.Seconds())
	g.CreatedAt = timeNow()
	return nil
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
