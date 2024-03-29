package goauth

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheckInScopeTrue(t *testing.T) {
	scope := []string{"1", "2", "3"}
	check := "1"
	b := checkInScope(check, scope)
	if !b {
		t.Error("Test failed, expected true but got false")
	}
}

func TestCheckInScopeFalse(t *testing.T) {
	scope := []string{"1", "2", "3"}
	check := "4"
	b := checkInScope(check, scope)
	if b {
		t.Error("Test failed, expected false but got true")
	}
}

func TestCheckAuth(t *testing.T) {
	grant := Grant{AccessToken: "testtoken", Scope: []string{"testscope"}}

	handler := newTestHandler()

	// Create the handler
	middlewareHandler := handler.Secure([]string{"testscope"}, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("approved"))
	})

	testCases([]testCase{
		// Should throw an error due to no bearer token being passed on the request
		{
			"GET",
			"",
			nil,
			middlewareHandler,
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
		// Should approve the request and call the underlying handler
		{
			"GET",
			"",
			nil,
			middlewareHandler,
			func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer "+grant.AccessToken.RawString())
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
