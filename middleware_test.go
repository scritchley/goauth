package goauth

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"sync"
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
	// Create a new session store using the mem backend
	ss := NewSessionStore(&MemSessionStoreBackend{
		&sync.Mutex{},
		make(map[string]Grant),
		make(map[string]AuthorizationCode),
	})

	grant, err := ss.NewGrant(&testClient{
		"testclientid",
		"testclientsecret",
		"testusername",
		"https://testuri.com",
		[]string{"testscope"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create the handler
	handler := checkAuth(TokenTypeBearer, ss, []string{"testscope"}, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("approved"))
	})

	testCases([]testCase{
		// Should throw an error due to no bearer token being passed on the request
		{
			"GET",
			"",
			nil,
			handler,
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
			handler,
			func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer "+grant.AccessToken.string())
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
