package goauth

// Client is an interface that implements methods for performing authorization checks on a client.
type Client interface {
	// AllowStrategy checks that the client is authorized to authenticate using the provided Strategy.
	// It returns a bool indicating whether authorization has been granted.
	AllowStrategy(s Strategy) bool
	// AuthorizeScope checks that the client has access to the provided scope returning the approved scope
	// or an error if the scope is not invalid. The implementation may ignore the passed scope or may approve
	// it fully or partially.
	AuthorizeScope(scope []string) ([]string, error)
	// AllowRedirectURI checks that the client has passed an approved redirect URI. It returns
	// an bool indicating whether the redirect uri is allowed.
	AllowRedirectURI(uri string) bool
	// AuthorizeResourceOwner checks that the client has permission to act on behalf of the resource
	// owner. It returns a bool indicating whether the client is allowed and an error if one occurs.
	AuthorizeResourceOwner(username string) (bool, error)
}
