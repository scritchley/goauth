package goauth

import (
	"net/http"
	"reflect"
	"testing"
)

// testAuthenticator implements the Authenticator interface and
// is intended for use only in testing.
type testAuthenticator struct {
	client   *testClient
	username string
	password Secret
}

// GetClient returns a Client given a clientID or an error if the client is not found. It is implemented for testing purposes only.
func (t *testAuthenticator) GetClient(clientID string) (Client, error) {
	if clientID == t.client.ID {
		return t.client, nil
	}
	return nil, ErrorUnauthorizedClient
}

// GetClientWithSecret returns a Client given a clientID or an error if the client is not found. It is implemented for testing purposes only.
func (t *testAuthenticator) GetClientWithSecret(clientID string, clientSecret Secret) (Client, error) {
	if clientID == t.client.ID && clientSecret.RawString() == t.client.secret {
		return t.client, nil
	}
	return nil, ErrorUnauthorizedClient
}

// AuthorizeResourceOwner checks the username and password against the configured properties of t. It returns an error if they do not match. It
// is implemented for testing purposes only.
func (t *testAuthenticator) AuthorizeResourceOwner(username string, password Secret, scope []string) ([]string, error) {
	if username != t.username {
		return nil, ErrorAccessDenied
	}
	if password != t.password {
		return nil, ErrorAccessDenied
	}
	return scope, nil
}

func newTestHandler() handler {
	return New(&testAuthenticator{
		&testClient{
			"testclientid",
			"testclientsecret",
			"testusername",
			"https://testuri.com",
			[]string{"testscope"},
		},
		"testusername",
		Secret("testpassword"),
	})
}

func TestNew(t *testing.T) {

	auth := newTestHandler()
	// Auth should implement the http.Handler interface.
	_, ok := reflect.ValueOf(auth).Interface().(http.Handler)
	if !ok {
		t.Error("Test failed, expected auth to implement http.Handler")
	}

}
