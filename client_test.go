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

// AuthorizeRedirectURI satisfies the Client interface, returning an error if the provided
// URI is not valid.
func (t *testClient) AuthorizeRedirectURI(uri string) error {
	if uri != t.redirectURI {
		return ErrorUnauthorizedClient
	}
	return nil
}

// AuthorizeResourceOwner satisfies the Client interface, return an error if the provided resource owner
// username is not allowed or is invalid.
func (t *testClient) AuthorizeResourceOwner(username string) error {
	if t.username != username {
		return ErrorUnauthorizedClient
	}
	return nil
}
