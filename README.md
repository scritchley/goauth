# goauth 
An OAuth 2.0 server toolkit written in Go.

[![Build Status](https://drone.io/github.com/scritchley/goauth/status.png)](https://drone.io/github.com/scritchley/goauth/latest)

## Overview

Goauth supports the following methods for authenticating a client:

- Authorization Code Grant
- Implicit Grant
- Client Credentials Grant
- Resource Owner Password Credentials Grant

## Getting started

Creating an OAuth 2.0 server is easy! All you need to do is provide an implementation of the Authenticator interface:

```
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
```

A goauth.Server implements the http.Handler interface and internally handles routing to the various OAuth 2.0 endpoints. All you need do is attach it to an http.Server.

```
func main() {

	server := goauth.New(example)

	log.Fatal(http.ListenAndServe(":8080", server))
}

```

## Session Storage

Goauth implements a memory session store by default, however, this is not intended for production use and will not persist sessions between restarts or scale beyond a single instance. In order to implement your own session storage, you must satisfy the SessionStoreBackend interface:

```
// SessionStoreBackend implements methods for storing, retrieving and refreshing
// existing grants and authorization codes.
type SessionStoreBackend interface {
	// PutGrant stores a new Grant in the session store.
	PutGrant(grant Grant) error
	// GetGrant retrieves an existing Grant from the session store.
	GetGrant(accessToken Secret) (Grant, error)
	// DeleteGrant removes an existing Grant from the session store.
	DeleteGrant(accessToken Secret) error
	// RefreshGrant refreshes an existing Grant returning the updated grant.
	RefreshGrant(refreshToken Secret) (Grant, error)
	// PutAuthorizationCode stores a new AuthorizationCode in the session store.
	PutAuthorizationCode(authCode AuthorizationCode) error
	// GetAuthorizationCode retrieves an existing AuthorizationCode from the session store.
	GetAuthorizationCode(code Secret) (AuthorizationCode, error)
	// DeleteAuthorizationCode removes an existing AuthorizationCode from the session store.
	DeleteAuthorizationCode(code Secret) error
}
```

It is then possible to utilise your session store by overriding the default:

```
func main() {

	server := goauth.New(example)

	server.SessionStore = goauth.NewSessionStore(customSessionStoreBackend)

	log.Fatal(http.ListenAndServe(":8080", server))
}
```