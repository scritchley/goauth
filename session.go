package goauth

import "sync"

var (
	// DefaultSessionStore is a default implementation of the session store using
	// the MemSessionStoreBackend.
	DefaultSessionStore = NewSessionStore(NewMemSessionStoreBackend())
)

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

// SessionStore wraps the SessionStoreBackend interface and
// provides methods for interacting with the session store.
type SessionStore struct {
	SessionStoreBackend
}

// NewSessionStore returns a new SessionStore with the provided backend.
func NewSessionStore(backend SessionStoreBackend) *SessionStore {
	return &SessionStore{backend}
}

// NewAuthorizationCode creates a new authorization code and saves it in the session store returning the
// new auth code and any error that occurs.
func (s *SessionStore) NewAuthorizationCode(clientID, redirectURI string, scope []string) (AuthorizationCode, error) {
	code, err := NewToken()
	if err != nil {
		return AuthorizationCode{}, err
	}
	authCode := AuthorizationCode{
		Code:        Secret(code),
		ClientID:    clientID,
		RedirectURI: redirectURI,
		Scope:       scope,
		CreatedAt:   timeNow(),
		ExpiresIn:   DefaultAuthorizationCodeExpiry,
	}
	// Check whether there is an existing authcode with this access token
	existing, err := s.GetAuthorizationCode(authCode.Code)
	// If there is an existing auth code then return an error
	if err == nil && existing.Code.RawString() == authCode.Code.RawString() {
		return authCode, ErrorServerError
	}
	// Otherwise return the auth code and add it to the session store.
	return authCode, s.PutAuthorizationCode(authCode)
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

// RefreshGrant refreshes an existing Grant returning the updated grant.
func (m *MemSessionStoreBackend) RefreshGrant(refreshToken Secret) (Grant, error) {
	return Grant{}, ErrorServerError
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
