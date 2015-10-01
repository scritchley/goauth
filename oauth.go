package goauth

// ImplicitGrant implements methods required to
// perform an Implicit Grant Grant as per http://tools.ietf.org/html/rfc6749#section-4.2
type ImplicitGrant interface {
}

// ResourceOwnerPasswordCredentialsGrant implements methods required to
// perform a Resource Owner Password Credentials Grant as per http://tools.ietf.org/html/rfc6749#section-4.3
type ResourceOwnerPasswordCredentialsGrant interface {
}

// ClientCredentialsGrant implements methods required to
// perform a Client Credentials Grant as per http://tools.ietf.org/html/rfc6749#section-4.4
type ClientCredentialsGrant interface {
}
