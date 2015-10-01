package goauth

// Client is an interface that implements methods for performing authorization checks on a client.
type Client interface {
	// AuthorizeScope checks that the client has access to the provided scope returning the approved scope
	// or an error if the scope is not invalid. The implementation may ignore the passed scope or may approve
	// it fully or partially.
	AuthorizeScope(scope []string) ([]string, error)
	// AuthorizeRedirectURI checks that the client has passed an approved redirect URI. It returns
	// an error if the redirect URI is not allowed or is invalid. A nil error is treated as approved.
	AuthorizeRedirectURI(uri string) error
	// AuthorizeResourceOwner checks that the client has permission to act on behalf of the resource
	// owner. It returns an error if the client is not allowed or the username is invalid. A nil
	// error is treated as approved.
	AuthorizeResourceOwner(username string) error
}
