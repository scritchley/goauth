package goauth

import (
	"encoding/json"
	"net/http"
)

// ErrorHandler is a function that accepts a http.ResponseWriter and Error
type ErrorHandler func(w http.ResponseWriter, e Error)

var (
	// DefaultErrorHandler can be overriden in order to implement a custom error handler
	DefaultErrorHandler = defaultErrorHandler
)

// defaultErrorHandler is the default error handler that is used for returning errors
// via http.
func defaultErrorHandler(w http.ResponseWriter, e error) {
	enc := json.NewEncoder(w)
	err := enc.Encode(e)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

type Error struct {
	Code        string `json:"code"`
	Description string `json:"description"`
}

func (e Error) Error() string {
	return e.Description
}

var (
	ErrorInvalidRequest = Error{
		"invalid_request",
		"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.",
	}
	ErrorUnauthorizedClient = Error{
		"unauthorized_client",
		"The client is not authorized to request an authorization code using this method.",
	}
	ErrorAccessDenied = Error{
		"access_denied",
		"The resource owner or authorization server denied the request.",
	}
	ErrorUnsupportedResponseType = Error{
		"unsupported_response_type",
		"The authorization server does not support obtaining an authorization code using this method.",
	}
	ErrorInvalidScope = Error{
		"invalid_scope",
		"The requested scope is invalid, unknown, or malformed.",
	}
	ErrorServerError = Error{
		"server_error",
		"The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
	}
	ErrorTemporarilyUnavailable = Error{
		"temporarily_unavailable",
		"The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.",
	}
)
