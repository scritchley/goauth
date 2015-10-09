package goauth

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// testImplicitGrant implements the ImplicitGrant interface and
// is intended for use only in testing.
type testImplicitGrant struct {
	client *testClient
}

// GetClient returns a Client given a clientID or an error if the client is not found. It is implemented for testing purposes only.
func (t *testImplicitGrant) GetClient(clientID string) (Client, error) {
	if clientID == t.client.ID {
		return t.client, nil
	}
	return nil, ErrorUnauthorizedClient
}

func TestImplicitGrantHandler(t *testing.T) {
	// Override NewToken to return a known value
	NewToken = func() Secret {
		return Secret("testtoken")
	}

	// Set the default expiry for authorization codes to a low value
	DefaultAuthorizationCodeExpiry = time.Millisecond

	// Create a new instance of the mem session store
	DefaultSessionStore = NewSessionStore(NewMemSessionStoreBackend())

	handler := newTestHandler()

	// Generate a method to check the authentication of a request
	securedHandler := handler.Secure([]string{"testscope"}, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("approved"))
	})

	// Generate a method to check the authentication of a request with a slightly different scope
	securedHandlerDifferentScope := handler.Secure([]string{"securescope"}, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("approved"))
	})

	testCases([]testCase{
		// Should return an invalid_request as the request does not contain any of the required params
		{
			"GET",
			"/",
			nil,
			handler.handleImplicitGrant,
			func(r *http.Request) {
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
		// Should redirect including an error
		{
			"GET",
			"/?response_type=token&client_id=testclientid&redirect_uri=https://testuri.com&scope=testscope",
			nil,
			handler.handleImplicitGrant,
			func(r *http.Request) {
				r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
			},
			func(r *httptest.ResponseRecorder) {
				if r.Code != 302 {
					t.Errorf("Test failed, status %v", r.Code)
				}
				if r.Header().Get("Location") != "https://testuri.com#access_token=testtoken&expires_in=3600&scope=testscope&token_type=bearer" {
					t.Errorf("Test failed, location %v", r.Header().Get("Location"))
				}
				expected := []byte(`<a href="https://testuri.com#access_token=testtoken&amp;expires_in=3600&amp;scope=testscope&amp;token_type=bearer">Found</a>.` + "\n\n")
				if !bytes.Equal(r.Body.Bytes(), expected) {
					t.Errorf("Test failed, expected %s but got %s", expected, r.Body.Bytes())
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
