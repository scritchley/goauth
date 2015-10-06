package goauth

import "sync"

// SessionStoreBackend implements methods for storing, retrieving and refreshing
// existing grants and authorization codes.
type SessionStoreBackend interface {
	// PutGrant stores a new Grant in the session store.
	PutGrant(grant Grant) error
	// GetGrant retrieves an existing Grant from the session store.
	GetGrant(accessToken Secret) (Grant, error)
	// DeleteGrant removes an existing Grant from the session store.
	DeleteGrant(accessToken Secret) error
	// PutAuthorizationCode stores a new AuthorizationCode in the session store.
	PutAuthorizationCode(authCode AuthorizationCode) error
	// GetAuthorizationCode retrieves an existing AuthorizationCode from the session store.
	GetAuthorizationCode(code Secret) (AuthorizationCode, error)
	// DeleteAuthorizationCode removes an existing AuthorizationCode from the session store.
	DeleteAuthorizationCode(code Secret) error
}

// SessionStore wraps the SessionStoreBackend interface and
// provides methods for interacting with the session store.
type SessionStore struct {
	SessionStoreBackend
}

// NewSessionStore returns a new SessionStore with the provided backend.
func NewSessionStore(backend SessionStoreBackend) *SessionStore {
	return &SessionStore{backend}
}

// NewGrant creates a new grant and saves it in the session store returning the
// new grant and any error that occurs.
func (s *SessionStore) NewGrant(client Client, scope []string) (Grant, error) {
	grant := Grant{}
	// Set the client on the grant
	grant.Client = client
	// Set the scope
	grant.Scope = scope
	// Refresh to initialise the grant properties
	grant.Refresh()
	// Check whether there is an existing grant with this access token
	existing, err := s.GetGrant(grant.AccessToken)
	// If there is an existing grant then return an error
	if err == nil && existing.AccessToken == grant.AccessToken {
		return grant, ErrorServerError
	}
	// Otherwise return the grant and add it to the session store.
	return grant, s.PutGrant(grant)
}

// CheckAuthorizationCode retrieves an AuthorizationCode and validates it against the given
// code and redirect URI. It returns an error if the code is invalid or any other errors occur.
func (s *SessionStore) CheckAuthorizationCode(code Secret, redirectURI string) (AuthorizationCode, error) {
	authCode, err := s.GetAuthorizationCode(code)
	if err != nil {
		return authCode, err
	}
	// If set, check that RedirectURI matches the given redirectURI
	if authCode.RedirectURI != "" && authCode.RedirectURI != redirectURI {
		return authCode, ErrorAccessDenied
	}
	// Check that the code is not expired.
	if authCode.IsExpired() {
		return authCode, ErrorAccessDenied
	}
	return authCode, nil
}

// CheckGrant returns a Grant from the session store and checks that it has not
// expired. If the grant does not exist or has expired then an error is returned.
func (s *SessionStore) CheckGrant(accessToken Secret) (Grant, error) {
	grant, err := s.GetGrant(accessToken)
	if err != nil {
		return grant, err
	}
	if grant.IsExpired() {
		// In the event that the grant has expired, ensure that it is deleted
		// from the session store. In practice, SessionStoreBackend implementations
		// should apply some form of TTL to the Grant when it is stored.
		err := s.DeleteGrant(accessToken)
		if err == nil {
			err = ErrorAccessDenied
		}
		return grant, err
	}
	return grant, nil
}

// MemSessionStoreBackend is an in-memory session store, implementing the SessionStore interface.
type MemSessionStoreBackend struct {
	mtx       *sync.Mutex
	grants    map[string]Grant
	authCodes map[string]AuthorizationCode
}

func NewMemSessionStoreBackend() *MemSessionStoreBackend {
	return &MemSessionStoreBackend{
		&sync.Mutex{},
		make(map[string]Grant),
		make(map[string]AuthorizationCode),
	}
}

// PutGrant stores a Grant in the session store.
func (m *MemSessionStoreBackend) PutGrant(grant Grant) error {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.grants[grant.AccessToken.RawString()] = grant
	return nil
}

// GetGrant retrieves a Grant from the session store.
func (m *MemSessionStoreBackend) GetGrant(accessToken Secret) (Grant, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	if grant, ok := m.grants[accessToken.RawString()]; ok {
		return grant, nil
	}
	return Grant{}, ErrorAccessDenied
}

// DeleteGrant removes a Grant from the session store.
func (m *MemSessionStoreBackend) DeleteGrant(accessToken Secret) error {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	if _, ok := m.grants[accessToken.RawString()]; ok {
		delete(m.grants, accessToken.RawString())
		return nil
	}
	return ErrorServerError
}

// PutAuthorizationCode stores a AuthorizationCode in the session store.
func (m *MemSessionStoreBackend) PutAuthorizationCode(authCode AuthorizationCode) error {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.authCodes[authCode.Code.RawString()] = authCode
	return nil
}

// GetAuthorizationCode retrieves an AuthorizationCode from the session store.
func (m *MemSessionStoreBackend) GetAuthorizationCode(code Secret) (AuthorizationCode, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	if authCode, ok := m.authCodes[code.RawString()]; ok {
		return authCode, nil
	}
	return AuthorizationCode{}, ErrorAccessDenied
}

// DeleteAuthorizationCode removes a AuthorizationCode from the session store.
func (m *MemSessionStoreBackend) DeleteAuthorizationCode(code Secret) error {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	if _, ok := m.authCodes[code.RawString()]; ok {
		delete(m.authCodes, code.RawString())
		return nil
	}
	return ErrorServerError
}
