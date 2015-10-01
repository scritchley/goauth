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
func (s *SessionStore) NewGrant() (Grant, error) {
	grant := Grant{}
	// Refresh to initialise the grant properties
	grant.Refresh()
	// Check whether there is an existing grant with this access token
	existing, err := s.GetGrant(grant.AccessToken)
	// If there is an existing grant then start over
	if err == nil && existing.AccessToken == grant.AccessToken {
		return s.NewGrant()
	}
	// Otherwise return the grant and add it to the session store.
	return grant, s.PutGrant(grant)
}

func (s *SessionStore) CheckAuthorizationCode(code Secret, redirectURI string) error {
	authCode, err := s.GetAuthorizationCode(code)
	if err != nil {
		return err
	}
	// If set, check that RedirectURI matches the given redirectURI
	if authCode.RedirectURI != "" && authCode.RedirectURI != redirectURI {
		return ErrorAccessDenied
	}
	if authCode.IsExpired() {
		return ErrorAccessDenied
	}
	return nil
}

// MemSessionStoreBackend is an in-memory session store, implementing the SessionStore interface.
type MemSessionStoreBackend struct {
	mtx       *sync.Mutex
	grants    map[string]Grant
	authCodes map[string]AuthorizationCode
}

// PutGrant stores a Grant in the session store.
func (m *MemSessionStoreBackend) PutGrant(grant Grant) error {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.grants[grant.AccessToken.string()] = grant
	return nil
}

// GetGrant retrieves a Grant from the session store.
func (m *MemSessionStoreBackend) GetGrant(accessToken Secret) (Grant, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	if grant, ok := m.grants[accessToken.string()]; ok {
		return grant, nil
	}
	return Grant{}, ErrorAccessDenied
}

// DeleteGrant removes a Grant from the session store.
func (m *MemSessionStoreBackend) DeleteGrant(accessToken Secret) error {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	if _, ok := m.grants[accessToken.string()]; ok {
		delete(m.grants, accessToken.string())
		return nil
	}
	return ErrorServerError
}

// PutAuthorizationCode stores a AuthorizationCode in the session store.
func (m *MemSessionStoreBackend) PutAuthorizationCode(authCode AuthorizationCode) error {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.authCodes[authCode.Code.string()] = authCode
	return nil
}

// GetAuthorizationCode retrieves an AuthorizationCode from the session store.
func (m *MemSessionStoreBackend) GetAuthorizationCode(code Secret) (AuthorizationCode, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	if authCode, ok := m.authCodes[code.string()]; ok {
		return authCode, nil
	}
	return AuthorizationCode{}, ErrorAccessDenied
}

// DeleteAuthorizationCode removes a AuthorizationCode from the session store.
func (m *MemSessionStoreBackend) DeleteAuthorizationCode(code Secret) error {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	if _, ok := m.authCodes[code.string()]; ok {
		delete(m.authCodes, code.string())
		return nil
	}
	return ErrorServerError
}
