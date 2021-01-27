package goauth

import (
	"encoding/json"
	"net/http"
)

// ErrorHandler is a function that accepts a http.ResponseWriter and Error.
type ErrorHandler func(w http.ResponseWriter, s int, e error)

var (
	// DefaultErrorHandler can be overriden in order to implement a custom error handler.
	DefaultErrorHandler ErrorHandler = defaultErrorHandler
)

// defaultErrorHandler is the default error handler that is used for returning errors via http.
func defaultErrorHandler(w http.ResponseWriter, httpStatusCode int, e error) {
	w.Header().Set("Content-Type", "application/json")

	if httpStatusCode == 0 {
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		w.WriteHeader(httpStatusCode)
	}

	enc := json.NewEncoder(w)
	err := enc.Encode(e)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// Error is an error type that can be used in response to failing authentication attempts.
type Error struct {
	StatusCode  int    `json:"-"`
	Code        string `json:"code"`
	Description string `json:"description"`
}

// Error satisfies the error interface
func (e Error) Error() string {
	return e.Code + ": " + e.Description
}

var (
	ErrorInvalidRequest = Error{
		http.StatusBadRequest,
		"invalid_request",
		"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.",
	}
	ErrorUnauthorizedClient = Error{
		http.StatusUnauthorized,
		"unauthorized_client",
		"The client is not authorized to request an authorization code using this method.",
	}
	ErrorAccessDenied = Error{
		http.StatusUnauthorized,
		"access_denied",
		"The resource owner or authorization server denied the request.",
	}
	ErrorUnsupportedResponseType = Error{
		http.StatusBadRequest,
		"unsupported_response_type",
		"The authorization server does not support obtaining an authorization code using this method.",
	}
	ErrorInvalidScope = Error{
		http.StatusBadRequest,
		"invalid_scope",
		"The requested scope is invalid, unknown, or malformed.",
	}
	ErrorServerError = Error{
		http.StatusInternalServerError,
		"server_error",
		"The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
	}
	ErrorTemporarilyUnavailable = Error{
		http.StatusServiceUnavailable,
		"temporarily_unavailable",
		"The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.",
	}
)
