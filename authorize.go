package goauth

import "net/http"

var (
	// authorizeHandlers is a map of http.HandlerFuncs that are indexed by GrantType.
	authorizeHandlers = make(AuthorizeHandlers)
)

// AuthorizeHandlers is a map of http.Handerfuncs indexed by ResponseType.
type AuthorizeHandlers map[ResponseType]http.HandlerFunc

// AddHandler adds a http.HandlerFunc indexed against the provided ResponseType. Only one handler can be registered
// against a grant type.
func (a AuthorizeHandlers) AddHandler(responseType ResponseType, handler http.HandlerFunc) {
	a[responseType] = handler
}

// authorizeHandler is a http.HandlerFunc that can be used to satisfy authorize requests. If a handler is registered
// against the requests grant type then it is used, else an error is returned in the response.
func authorizeHandler(w http.ResponseWriter, r *http.Request) {
	responseType := r.FormValue(ParamResponseType)
	if handler, ok := authorizeHandlers[ResponseType(responseType)]; ok {
		handler(w, r)
		return
	}
	DefaultErrorHandler(w, ErrorInvalidRequest)
}
