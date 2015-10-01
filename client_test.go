package goauth

import "fmt"

// testClient implements the Client interface and is
// intended for use only in testing.
type testClient struct {
	ID          string
	secret      string
	username    string
	redirectURI string
	scope       []string
}

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

func (t *testClient) AuthorizeRedirectURI(uri string) error {
	if uri != t.redirectURI {
		return fmt.Errorf("invalid redirect URI")
	}
	return nil
}

func (t *testClient) AuthorizeResourceOwner(username string) error {
	if t.username != username {
		return fmt.Errorf("unauthorized client")
	}
	return nil
}
