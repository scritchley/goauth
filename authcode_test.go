package goauth

import (
	"bytes"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// testAuthCodeGrant implements the AuthCodeGrant interface and
// is intended for use only in testing.
type testAuthCodeGrant struct {
	client   *testClient
	username string
	password Secret
}

// GetClient returns a Client given a clientID or an error if the client is not found. It is implemented for testing purposes only.
func (t *testAuthCodeGrant) GetClient(clientID string) (Client, error) {
	if clientID == t.client.ID {
		return t.client, nil
	}
	return nil, ErrorAccessDenied
}

// GetClientWithSecret returns a Client given a clientID or an error if the client is not found. It is implemented for testing purposes only.
func (t *testAuthCodeGrant) GetClientWithSecret(clientID string, clientSecret Secret) (Client, error) {
	if clientID == t.client.ID && clientSecret.string() == t.client.secret {
		return t.client, nil
	}
	return nil, ErrorAccessDenied
}

// AuthorizeCode checks the username and password against the configured properties of t. It returns an error if they do not match. It
// is implemented for testing purposes only.
func (t *testAuthCodeGrant) AuthorizeCode(username string, password Secret, scope []string) error {
	if username != t.username {
		return ErrorAccessDenied
	}
	if password != t.password {
		return ErrorAccessDenied
	}
	return nil
}

// TestAuthCodeHandler tests the request/response for the Authorization Code Grant Handler. It
// should check against the specified behaviour documented here: http://tools.ietf.org/html/rfc6749#section-4.1
func TestAuthCodeHandler(t *testing.T) {

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
	acg := &testAuthCodeGrant{
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

	// Create the new template
	tmpl, err := template.New("authcodegrant").Parse(`{{.Client.ID}}|{{.Scope}}|{{.Error}}`)
	if err != nil {
		t.Fatal(err)
	}

	// Generate the auth code grant handler
	handler := generateAuthorizationCodeGrantHandler(acg, tmpl, ss)

	// Reference to the token handler for auth code grants
	tokenHandler, ok := tokenHandlers[GrantTypeAuthorizationCode]
	if !ok {
		t.Error("Test failed, token handler not generated")
	}

	testCases([]testCase{
		// Should throw an error due to no client id being passed on the request
		{
			"GET",
			"",
			nil,
			handler,
			func(r *http.Request) {},
			func(r *httptest.ResponseRecorder) {
				expected := []byte(`{"code":"unauthorized_client","description":"The client is not authorized to request an authorization code using this method."}` + "\n")
				if !bytes.Equal(r.Body.Bytes(), expected) {
					t.Errorf("Test failed, expected %s but got %s", expected, r.Body.Bytes())
				}
			},
		},
		// Should throw an error due to an unknown client id being passed on the request
		{
			"GET",
			"?client_id=test",
			nil,
			handler,
			func(r *http.Request) {},
			func(r *httptest.ResponseRecorder) {
				expected := []byte(`{"code":"unauthorized_client","description":"The client is not authorized to request an authorization code using this method."}` + "\n")
				if !bytes.Equal(r.Body.Bytes(), expected) {
					t.Errorf("Test failed, expected %s but got %s", expected, r.Body.Bytes())
				}
			},
		},
		// Should throw an access denied error due to providing no redirect uri
		{
			"GET",
			"?client_id=testclientid",
			nil,
			handler,
			func(r *http.Request) {},
			func(r *httptest.ResponseRecorder) {
				expected := []byte(`{"code":"access_denied","description":"The resource owner or authorization server denied the request."}` + "\n")
				if !bytes.Equal(r.Body.Bytes(), expected) {
					t.Errorf("Test failed, expected %s but got %s", expected, r.Body.Bytes())
				}
			},
		},
		// Should redirect to the uri passing an error as the response type is not valid
		{
			"GET",
			"?client_id=testclientid&redirect_uri=https://testuri.com",
			nil,
			handler,
			func(r *http.Request) {},
			func(r *httptest.ResponseRecorder) {
				if r.Code != 302 {
					t.Errorf("Test failed, status %v", r.Code)
				}
				if r.Header().Get("Location") != "https://testuri.com?error=unsupported_response_type&error_description=The+authorization+server+does+not+support+obtaining+an+authorization+code+using+this+method." {
					t.Errorf("Test failed, got location %s", r.Header().Get("Location"))
				}
				expected := []byte(`<a href="https://testuri.com?error=unsupported_response_type&amp;error_description=The+authorization+server+does+not+support+obtaining+an+authorization+code+using+this+method.">Found</a>.` + "\n\n")
				if !bytes.Equal(r.Body.Bytes(), expected) {
					t.Errorf("Test failed, expected %s but got %s", expected, r.Body.Bytes())
				}
			},
		},
		// Should render the template including the interpolated values (not including any scope values)
		{
			"GET",
			"?response_type=code&client_id=testclientid&redirect_uri=https://testuri.com",
			nil,
			handler,
			func(r *http.Request) {},
			func(r *httptest.ResponseRecorder) {
				expected := []byte(`testclientid|[]|`)
				if !bytes.Equal(r.Body.Bytes(), expected) {
					t.Errorf("Test failed, expected %s but got %s", expected, r.Body.Bytes())
				}
			},
		},
		// Should render the template including the interpolated values (including scope values)
		{
			"GET",
			"?response_type=code&client_id=testclientid&redirect_uri=https://testuri.com&scope=testscope testscope2",
			nil,
			handler,
			func(r *http.Request) {},
			func(r *httptest.ResponseRecorder) {
				expected := []byte(`testclientid|[testscope]|`)
				if !bytes.Equal(r.Body.Bytes(), expected) {
					t.Errorf("Test failed, expected %s but got %s", expected, r.Body.Bytes())
				}
			},
		},
		// Should render the template including an error message for invalid credentials
		{
			"POST",
			"?response_type=code&client_id=testclientid&redirect_uri=https://testuri.com&scope=testscope testscope2",
			strings.NewReader("username=test&password=test"),
			handler,
			func(r *http.Request) {},
			func(r *httptest.ResponseRecorder) {
				expected := []byte(`||username or password invalid`)
				if !bytes.Equal(r.Body.Bytes(), expected) {
					t.Errorf("Test failed, expected %s but got %s", expected, r.Body.Bytes())
				}
			},
		},
		// Should redirect to the redirect uri providing a authorization code value
		{
			"POST",
			"?response_type=code&client_id=testclientid&redirect_uri=https://testuri.com&scope=testscope testscope2",
			strings.NewReader("username=testusername&password=testpassword"),
			handler,
			func(r *http.Request) {
				r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
			},
			func(r *httptest.ResponseRecorder) {
				if r.Code != 302 {
					t.Errorf("Test failed, status %v", r.Code)
				}
				if r.Header().Get("Location") != "https://testuri.com?code=testtoken" {
					t.Errorf("Test failed, got location %s", r.Header().Get("Location"))
				}
			},
		},
		// Should return a new access token.
		{
			"POST",
			"?response_type=code&client_id=testclientid&redirect_uri=https://testuri.com&scope=testscope testscope2",
			strings.NewReader("grant_type=authorization_code&code=testtoken&redirect_uri=https://testuri.com"),
			tokenHandler,
			func(r *http.Request) {
				r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
				r.SetBasicAuth("testclientid", "testclientsecret")
			},
			func(r *httptest.ResponseRecorder) {
				if r.Code != 200 {
					t.Errorf("Test failed, status %v", r.Code)
				}
				expected := []byte(`{"access_token":"testtoken","token_type":"bearer","expires_in":3600,"refresh_token":"testtoken"}` + "\n")
				if !bytes.Equal(r.Body.Bytes(), expected) {
					t.Errorf("Test failed, expected %s but got %s", expected, r.Body.Bytes())
				}
			},
		},
		// Should return access denied as using the authorization code has already been used and deleted.
		{
			"POST",
			"?response_type=code&client_id=testclientid&redirect_uri=https://testuri.com&scope=testscope testscope2",
			strings.NewReader("grant_type=authorization_code&code=testtoken&redirect_uri=https://testuri.com"),
			tokenHandler,
			func(r *http.Request) {
				r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
				r.SetBasicAuth("testclientid", "testclientsecret")
			},
			func(r *httptest.ResponseRecorder) {
				if r.Code != 200 {
					t.Errorf("Test failed, status %v", r.Code)
				}
				expected := []byte(`{"code":"access_denied","description":"The resource owner or authorization server denied the request."}` + "\n")
				if !bytes.Equal(r.Body.Bytes(), expected) {
					t.Errorf("Test failed, expected %s but got %s", expected, r.Body.Bytes())
				}
			},
		},
		// Repeats earlier step to retrieve a new a authorization code
		{
			"POST",
			"?response_type=code&client_id=testclientid&redirect_uri=https://testuri.com&scope=testscope testscope2",
			strings.NewReader("username=testusername&password=testpassword"),
			handler,
			func(r *http.Request) {
				r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
			},
			func(r *httptest.ResponseRecorder) {
				if r.Code != 302 {
					t.Errorf("Test failed, status %v", r.Code)
				}
				if r.Header().Get("Location") != "https://testuri.com?code=testtoken" {
					t.Errorf("Test failed, got location %s", r.Header().Get("Location"))
				}
			},
		},
		// Should throw an error as the authorization code has expired
		{
			"POST",
			"?response_type=code&client_id=testclientid&redirect_uri=https://testuri.com&scope=testscope testscope2",
			strings.NewReader("grant_type=authorization_code&code=testtoken&redirect_uri=https://testuri.com"),
			tokenHandler,
			func(r *http.Request) {
				time.Sleep(5 * time.Millisecond)
				r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
				r.SetBasicAuth("testclientid", "testclientsecret")
			},
			func(r *httptest.ResponseRecorder) {
				if r.Code != 200 {
					t.Errorf("Test failed, status %v", r.Code)
				}
				expected := []byte(`{"code":"access_denied","description":"The resource owner or authorization server denied the request."}` + "\n")
				if !bytes.Equal(r.Body.Bytes(), expected) {
					t.Errorf("Test failed, expected %s but got %s", expected, r.Body.Bytes())
				}
			},
		},
	})

}