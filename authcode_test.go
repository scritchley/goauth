package goauth

import (
	"bytes"
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
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
	return nil, ErrorUnauthorizedClient
}

// GetClientWithSecret returns a Client given a clientID or an error if the client is not found. It is implemented for testing purposes only.
func (t *testAuthCodeGrant) GetClientWithSecret(clientID string, clientSecret Secret) (Client, error) {
	if clientID == t.client.ID && clientSecret.RawString() == t.client.secret {
		return t.client, nil
	}
	return nil, ErrorUnauthorizedClient
}

// AuthorizeResourceOwner checks the username and password against the configured properties of t. It returns an error if they do not match. It
// is implemented for testing purposes only.
func (t *testAuthCodeGrant) AuthorizeResourceOwner(username string, password Secret, scope []string) ([]string, error) {
	if username != t.username {
		return nil, ErrorAccessDenied
	}
	if password != t.password {
		return nil, ErrorAccessDenied
	}
	return scope, nil
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

	handler := newTestHandler()
	var err error
	handler.AuthorizeTemplate, err = template.New("authcodegrant").Parse(`{{.Client.ID}}|{{.Scope}}|{{.Error}}`)
	if err != nil {
		t.Fatal(err)
	}

	// Generate a method to check the authentication of a request
	securedHandler := handler.Secure([]string{"testscope"}, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("approved"))
	})

	// Generate a method to check the authentication of a request with a slightly different scope
	securedHandlerDifferentScope := handler.Secure([]string{"securescope"}, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("approved"))
	})

	testCases([]testCase{
		// Should throw an error due to no client id being passed on the request
		{
			"GET",
			"",
			nil,
			handler.handleAuthorizationCodeGrant,
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
			handler.handleAuthorizationCodeGrant,
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
			handler.handleAuthorizationCodeGrant,
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
			handler.handleAuthorizationCodeGrant,
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
			handler.handleAuthorizationCodeGrant,
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
			handler.handleAuthorizationCodeGrant,
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
			handler.handleAuthorizationCodeGrant,
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
			handler.handleAuthorizationCodeGrant,
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
			handler.handleAuthCodeTokenRequest,
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
			},
		},
		// Should return access denied as using the authorization code has already been used and deleted.
		{
			"POST",
			"?response_type=code&client_id=testclientid&redirect_uri=https://testuri.com&scope=testscope testscope2",
			strings.NewReader("grant_type=authorization_code&code=testtoken&redirect_uri=https://testuri.com"),
			handler.handleAuthCodeTokenRequest,
			func(r *http.Request) {
				r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
				r.SetBasicAuth("testclientid", "testclientsecret")
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
		// Repeats earlier step to retrieve a new a authorization code
		{
			"POST",
			"?response_type=code&client_id=testclientid&redirect_uri=https://testuri.com&scope=testscope testscope2",
			strings.NewReader("username=testusername&password=testpassword"),
			handler.handleAuthorizationCodeGrant,
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
			handler.handleAuthCodeTokenRequest,
			func(r *http.Request) {
				time.Sleep(5 * time.Millisecond)
				r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
				r.SetBasicAuth("testclientid", "testclientsecret")
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
		// Should disallow the request as the token is incorrectly formatted
		{
			"GET",
			"",
			nil,
			securedHandler,
			func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer: testtoken")
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
