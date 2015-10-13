package goauth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// testResourceOwnerPasswordGrant implements the ResourceOwnerPasswordGrant interface and
// is intended for use only in testing.
type testResourceOwnerPasswordGrant struct {
	client   *testClient
	username string
	password Secret
}

// GetClientWithSecret returns a Client given a clientID or an error if the client is not found. It is implemented for testing purposes only.
func (t *testResourceOwnerPasswordGrant) GetClientWithSecret(clientID string, clientSecret Secret) (Client, error) {
	if clientID == t.client.ID && clientSecret.RawString() == t.client.secret {
		return t.client, nil
	}
	return nil, ErrorUnauthorizedClient
}

// AuthorizeResourceOwner checks the username and password against the configured properties of t. It returns an error if they do not match. It
// is implemented for testing purposes only.
func (t *testResourceOwnerPasswordGrant) AuthorizeResourceOwner(username string, password Secret, scope []string) ([]string, error) {
	if username != t.username {
		return nil, ErrorAccessDenied
	}
	if password != t.password {
		return nil, ErrorAccessDenied
	}
	return scope, nil
}

func TestResourceOwnerPasswordGrantHandler(t *testing.T) {
	// Override NewToken to return a known value
	NewToken = func() (Secret, error) {
		return Secret("testtoken"), nil
	}

	// Set the default expiry for authorization codes to a low value
	DefaultAuthorizationCodeExpiry = time.Millisecond

	// Create a new instance of the mem session store
	DefaultSessionStore = NewSessionStore(NewMemSessionStoreBackend())

	server := newTestHandler()

	// Generate a method to check the authentication of a request
	securedHandler := server.Secure([]string{"testscope"}, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("approved"))
	})

	// Generate a method to check the authentication of a request with a slightly different scope
	securedHandlerDifferentScope := server.Secure([]string{"securescope"}, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("approved"))
	})

	testCases([]testCase{
		// Should return an error as the request does not contain the correct grant type
		{
			"POST",
			"",
			nil,
			server.handleResourceOwnerPasswordCredentialsGrant,
			func(r *http.Request) {
				r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
			},
			func(r *httptest.ResponseRecorder) {
				if r.Code != 400 {
					t.Errorf("Test failed, status %v", r.Code)
				}
				expected := []byte(`{"code":"invalid_request","description":"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed."}` + "\n")
				if !bytes.Equal(r.Body.Bytes(), expected) {
					t.Errorf("Test failed, expected %s but got %s", expected, r.Body.Bytes())
				}
			},
		},
		// Should return an error as the request does not contain the correct grant type
		{
			"POST",
			"",
			strings.NewReader("grant_type=password"),
			server.handleResourceOwnerPasswordCredentialsGrant,
			func(r *http.Request) {
				r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
			},
			func(r *httptest.ResponseRecorder) {
				if r.Code != 401 {
					t.Errorf("Test failed, status %v", r.Code)
				}
				expected := []byte(`{"code":"access_denied","description":"The resource owner or authorization server denied the request."}` + "\n")
				if !bytes.Equal(r.Body.Bytes(), expected) {
					t.Errorf("Test failed, expected %s but got %s", expected, r.Body.Bytes())
				}
			},
		},
		// Should return a valid access token
		{
			"POST",
			"",
			strings.NewReader("grant_type=password&username=testusername&password=testpassword&scope=testscope"),
			server.handleResourceOwnerPasswordCredentialsGrant,
			func(r *http.Request) {
				r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
				r.SetBasicAuth("testclientid", "testclientsecret")
			},
			func(r *httptest.ResponseRecorder) {
				if r.Code != 200 {
					t.Errorf("Test failed, status %v", r.Code)
				}
				m := make(map[string]interface{})
				err := json.Unmarshal(r.Body.Bytes(), &m)
				if err != nil {
					t.Fatal(err)
				}
				if m["access_token"] != "testtoken" {
					t.Errorf("Test failed, got %s but expected something else", r.Body.Bytes())
				}
				if m["refresh_token"] != "testtoken" {
					t.Errorf("Test failed, got %s but expected something else", r.Body.Bytes())
				}
				if m["expires_in"] != 3600.00 {
					t.Errorf("Test failed, got %s but expected something else", r.Body.Bytes())
				}
				if m["token_type"] != "bearer" {
					t.Errorf("Test failed, got %s but expected something else", r.Body.Bytes())
				}
				if m["scope"] != "testscope" {
					t.Errorf("Test failed, got %s but expected something else", r.Body.Bytes())
				}
			},
		},
		// Should throw an error attempting to access a secure resource
		{
			"GET",
			"",
			nil,
			securedHandler,
			func(r *http.Request) {
			},
			func(r *httptest.ResponseRecorder) {
				if r.Code != 401 {
					t.Errorf("Test failed, status %v", r.Code)
				}
				expected := []byte(`{"code":"access_denied","description":"The resource owner or authorization server denied the request."}` + "\n")
				if !bytes.Equal(r.Body.Bytes(), expected) {
					t.Errorf("Test failed, expected %s but got %s", expected, r.Body.Bytes())
				}
			},
		},
		// Should disallow the request as the client is not authorized for this scope
		{
			"GET",
			"",
			nil,
			securedHandlerDifferentScope,
			func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer testtoken")
			},
			func(r *httptest.ResponseRecorder) {
				if r.Code != 401 {
					t.Errorf("Test failed, status %v", r.Code)
				}
				expected := []byte(`{"code":"access_denied","description":"The resource owner or authorization server denied the request."}` + "\n")
				if !bytes.Equal(r.Body.Bytes(), expected) {
					t.Errorf("Test failed, expected %s but got %s", expected, r.Body.Bytes())
				}
			},
		},
		// Should allow the request as a valid token is passed
		{
			"GET",
			"",
			nil,
			securedHandler,
			func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer testtoken")
			},
			func(r *httptest.ResponseRecorder) {
				if r.Code != 200 {
					t.Errorf("Test failed, status %v", r.Code)
				}
				expected := []byte(`approved`)
				if !bytes.Equal(r.Body.Bytes(), expected) {
					t.Errorf("Test failed, expected %s but got %s", expected, r.Body.Bytes())
				}
			},
		},
	})

}
