package goauth

import (
	"io"
	"net/http"
	"net/http/httptest"
)

type testCase struct {
	method  string
	url     string
	body    io.Reader
	handler http.HandlerFunc
	request func(r *http.Request)
	expect  func(r *httptest.ResponseRecorder)
}

func testCases(tcs []testCase) {
	for _, tc := range tcs {
		w := httptest.NewRecorder()
		r, err := http.NewRequest(tc.method, tc.url, tc.body)
		if err != nil {
			panic(err)
		}
		tc.request(r)
		tc.handler(w, r)
		tc.expect(w)
	}
}
