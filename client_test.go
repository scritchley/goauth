package goauth

// testClient implements the Client interface and is
// intended for use only in testing.
type testClient struct {
	ID          string
	secret      string
	username    string
	redirectURI string
	scope       []string
}

// AllowStrategy satisfies the Client interface, returning true if the client is approved for the
// provided Strategy
func (t *testClient) AllowStrategy(s Strategy) (bool, error) {
	return true, nil
}

// AuthorizeScope satisfies the Client interface, returning an approved scope for the client.
func (t *testClient) AuthorizeScope(scope []string) ([]string, error) {
	var approvedScope []string
	for _, requestedScope := range scope {
		for _, allowedScope := range t.scope {
			if allowedScope == requestedScope {
				approvedScope = append(approvedScope, requestedScope)
			}
		}
	}
	return approvedScope, nil
}

// AllowRedirectURI satisfies the Client interface, returning an bool indicating whether the
// redirect uri is allowed.
func (t *testClient) AllowRedirectURI(uri string) bool {
	if uri != t.redirectURI {
		return false
	}
	return true
}

// AuthorizeResourceOwner satisfies the Client interface, return an error if the provided resource owner
// username is not allowed or is invalid.
func (t *testClient) AuthorizeResourceOwner(username string) (bool, error) {
	if t.username != username {
		return false, nil
	}
	return true, nil
}
