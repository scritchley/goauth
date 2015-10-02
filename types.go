package goauth

import "strings"

type Param string

const (
	ParamResponseType     = "response_type"
	ParamGrantType        = "grant_type"
	ParamClientID         = "client_id"
	ParamRedirectURI      = "redirect_uri"
	ParamScope            = "scope"
	ParamState            = "state"
	ParamError            = "error"
	ParamErrorDescription = "error_description"
	ParamCode             = "code"
)

type ResponseType string

const (
	ResponseTypeCode = "code"
)

// GrantType is a string representing the grant type to use
// when requesting a new grant.
type GrantType string

const (
	// GrantTypeAuthorizationCode is the grant type used for the Authorization Code Grant strategy.
	GrantTypeAuthorizationCode = "authorization_code"
)

// Secret is a string which is masked when serialized.
type Secret string

// string returns the Secret string without masking
func (s Secret) string() string {
	return string(s)
}

// render returns a string of equal length to the Secret but composed of `x` runes only.
func (s Secret) render() string {
	return strings.Map(func(r rune) rune {
		return 'x'
	}, string(s))
}

// String returns a masked version of the Secret.
func (s Secret) String() string {
	return s.render()
}
