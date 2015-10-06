package goauth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// testClientCredentialsGrant implements the ClientCredentialsGrant interface and
// is intended for use only in testing.
type testClientCredentialsGrant struct {
	client   *testClient
	username string
	password Secret
}

// GetClientWithSecret returns a Client given a clientID or an error if the client is not found. It is implemented for testing purposes only.
func (t *testClientCredentialsGrant) GetClientWithSecret(clientID string, clientSecret Secret) (Client, error) {
	if clientID == t.client.ID && clientSecret.RawString() == t.client.secret {
		return t.client, nil
	}
	return nil, ErrorUnauthorizedClient
}

func TestClientCredentialsGrant(t *testing.T) {
	// Override NewToken to return a known value
	NewToken = func() Secret {
		return Secret("testtoken")
	}

	// Set the default expiry for authorization codes to a low value
	DefaultAuthorizationCodeExpiry = time.Millisecond

	// Create a new session store using the mem backend
	ss := NewSessionStore(&MemSessionStoreBackend{
		&sync.Mutex{},
		make(map[string]Grant),
		make(map[string]AuthorizationCode),
	})

	// Create an AuthorizationCodeGrant interface.
	ccg := &testClientCredentialsGrant{
		&testClient{
			"testclientid",
			"testclientsecret",
			"testusername",
			"https://testuri.com",
			[]string{"testscope"},
		},
		"testusername",
		Secret("testpassword"),
	}

	// Generate a resource owner password grant handler
	handler := generateClientCredentialsGrantHandler(ccg, ss)

	// Generate a method to check the authentication of a request
	securedHandler := checkAuth(TokenTypeBearer, ss, []string{"testscope"}, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("approved"))
	})

	// Generate a method to check the authentication of a request with a slightly different scope
	securedHandlerDifferentScope := checkAuth(TokenTypeBearer, ss, []string{"securescope"}, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("approved"))
	})

	testCases([]testCase{
		// Should return an error as the request does not contain the correct grant type
		{
			"POST",
			"",
			nil,
			handler,
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
		// Should return access denied as no credentials are passed on the request
		{
			"POST",
			"",
			strings.NewReader("grant_type=client_credentials"),
			handler,
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
		// Should return a valid token with no scope
		{
			"POST",
			"",
			strings.NewReader("grant_type=client_credentials"),
			handler,
			func(r *http.Request) {
				// Remove the existing token
				ss.DeleteGrant("testtoken")
				// Set request properties
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
			},
		},
		// Should return a valid token with the approved scope
		{
			"POST",
			"",
			strings.NewReader("grant_type=client_credentials&scope=testscope"),
			handler,
			func(r *http.Request) {
				// Remove the existing token
				ss.DeleteGrant("testtoken")
				// Set request properties
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
