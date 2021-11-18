package goauth

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	// DefaultAuthorizationCodeExpiry is the default expiry for an AuthorizationCode.
	// It should be a short period of time as it is intended that Authorization Codes
	// are used immediately.
	DefaultAuthorizationCodeExpiry = 10 * time.Second

	DefaultAuthorizationTemplate = template.Must(template.New("authorize").Parse(`
<!DOCTYPE html>
<html>
<head>
	<title></title>
</head>
<body>
{{if .Error}}
	<h3>{{.Error}}</h3>
{{end}}
{{if .Client}}
	{{if .Scope}}		
		<h3>{{.Client}} has requested access using the following scope:</h3>
		{{range .Scope}}
		<h3>{{.}}</h3>
		{{end}}
	{{else}}
		<h3>{{.Client}} has requested access.</h3>
	{{end}}
{{end}}
<form action="{{.ActionPath}}" method="POST">
	<input type="text" name="username">
	<input type="password" name="password">
	<input type="submit" value="Login">
</form>
</body>
</html>
`))

	DefaultAuthorizationHandler = func(client Client, scope []string, authErr error, actionURL string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if authErr != nil {
				w.WriteHeader(http.StatusUnauthorized)
			}
			err := DefaultAuthorizationTemplate.Execute(w, map[string]interface{}{
				"Client":    client,
				"Scope":     scope,
				"ActionURL": actionURL,
				"Error":     authErr,
			})
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		})
	}
)

// AuthorizationCode is a temporary authorization request
// that can be exchanged for a Grant.
type AuthorizationCode struct {
	Code        Secret
	RedirectURI string
	Scope       []string
	CreatedAt   time.Time
	ExpiresIn   time.Duration
}

// IsExpired returns true if the AuthorizationCode has expired.
func (a AuthorizationCode) IsExpired() bool {
	if a.CreatedAt.Add(a.ExpiresIn).After(timeNow()) {
		return false
	}
	return true
}

// CheckRedirectURI checks the given redirect URI against the provided string.
func (a AuthorizationCode) CheckRedirectURI(s string) bool {
	return a.RedirectURI == s
}

func (s Server) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request) {
	// Get the client
	clientID := r.FormValue(ParamClientID)
	client, err := s.Authenticator.GetClient(clientID)
	if err != nil {
		// Failed to retrieve client, therefore, return an error and DO NOT redirect
		w.WriteHeader(http.StatusUnauthorized)
		s.ErrorHandler(w, ErrorUnauthorizedClient.StatusCode, ErrorUnauthorizedClient)
		return
	}
	// Check that the client is allowed for this grant type
	ok := client.AllowStrategy(StrategyAuthorizationCode)
	if !ok {
		// The client is not authorized for the grant type, therefore, return an error
		w.WriteHeader(http.StatusUnauthorized)
		s.ErrorHandler(w, ErrorUnauthorizedClient.StatusCode, ErrorUnauthorizedClient)
		return
	}
	rawurl := r.FormValue(ParamRedirectURI)
	uri, err := url.Parse(rawurl)
	if err != nil {
		// The redirect URI is an invalid url, therefore, return an error and DO NOT redirect
		s.ErrorHandler(w, http.StatusInternalServerError, err)
		return
	}
	// Ensure the redirect URI is allowed
	ok = client.AllowRedirectURI(uri.String())
	if !ok {
		// The redirect URI is invalid, therefore, return an error and DO NOT redirect
		s.ErrorHandler(w, ErrorUnauthorizedClient.StatusCode, ErrorUnauthorizedClient)
		return
	}
	// If the response type is not code then return an error and redirect
	if r.FormValue(ParamResponseType) != ResponseTypeCode {
		// Add the error to the redirect URI and
		values := uri.Query()
		values.Add(ParamError, ErrorUnsupportedResponseType.Code)
		values.Add(ParamErrorDescription, ErrorUnsupportedResponseType.Description)
		uri.RawQuery = values.Encode()
		urlStr := uri.String()
		http.Redirect(w, r, urlStr, http.StatusFound)
		return
	}
	// Check that the given scope is allowed
	rawScope := r.FormValue(ParamScope)
	scope := strings.Split(rawScope, " ")
	scope, err = client.AuthorizeScope(scope)
	if err != nil {
		s.ErrorHandler(w, http.StatusUnauthorized, err)
		return
	}
	// If the method is POST then check resource owner credentials
	if r.Method == "POST" {
		err := r.ParseForm()
		if err != nil {
			s.AuthorizationHandler(client, nil, err, "").ServeHTTP(w, r)
			return
		}
		username := r.PostFormValue("username")
		password := r.PostFormValue("password")
		// Check that the client is permitted to act on behalf of the resource owner.
		allowed, err := client.AuthorizeResourceOwner(username)
		if err != nil {
			s.AuthorizationHandler(client, scope, err, "").ServeHTTP(w, r)
			return
		}
		if !allowed {
			s.AuthorizationHandler(client, scope, ErrorUnauthorizedClient, "").ServeHTTP(w, r)
			return
		}
		scope, err = s.Authenticator.AuthorizeResourceOwner(username, Secret(password), scope)
		if err != nil {
			s.AuthorizationHandler(client, scope, fmt.Errorf("username or password invalid"), "").ServeHTTP(w, r)
			return
		}
		authCode, err := s.SessionStore.NewAuthorizationCode(r.FormValue(ParamRedirectURI), scope)
		if err != nil {
			s.AuthorizationHandler(client, scope, fmt.Errorf("an internal server error occurred, please try again"), "").ServeHTTP(w, r)
			return
		}
		// The AuthorizationCode has been approved therefore redirect including the code
		values := uri.Query()
		values.Add(ParamCode, authCode.Code.RawString())
		// If the state param was included then make sure it is passed onto the redirect
		if r.FormValue(ParamState) != "" {
			values.Add(ParamState, r.FormValue(ParamState))
		}
		uri.RawQuery = values.Encode()
		urlStr := uri.String()
		http.Redirect(w, r, urlStr, http.StatusFound)
		return
	}
	actionURL := url.Values{}
	actionURL.Add(ParamScope, strings.Join(scope, " "))
	actionURL.Add(ParamRedirectURI, uri.String())
	if r.FormValue(ParamState) != "" {
		actionURL.Add(ParamState, r.FormValue(ParamState))
	}
	s.AuthorizationHandler(client, scope, nil, actionURL.Encode()).ServeHTTP(w, r)
}

func (s Server) handleAuthCodeTokenRequest(w http.ResponseWriter, r *http.Request) {
	// Parse the form
	err := r.ParseForm()
	if err != nil {
		s.ErrorHandler(w, http.StatusInternalServerError, err)
		return
	}
	// Authorize the client using basic auth
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		s.ErrorHandler(w, ErrorAccessDenied.StatusCode, ErrorAccessDenied)
		return
	}
	client, err := s.Authenticator.GetClientWithSecret(clientID, Secret(clientSecret))
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		s.ErrorHandler(w, ErrorAccessDenied.StatusCode, ErrorUnauthorizedClient)
		return
	}
	// Check that the client is allowed for this grant type
	ok = client.AllowStrategy(StrategyAuthorizationCode)
	if !ok {
		// The client is not authorized for the grant type, therefore, return an error
		w.WriteHeader(http.StatusUnauthorized)
		s.ErrorHandler(w, ErrorUnauthorizedClient.StatusCode, ErrorUnauthorizedClient)
		return
	}
	// Check that the request is using the correct grant type
	if r.PostFormValue(ParamGrantType) != GrantTypeAuthorizationCode {
		w.WriteHeader(http.StatusBadRequest)
		s.ErrorHandler(w, ErrorInvalidRequest.StatusCode, ErrorInvalidRequest)
		return
	}
	// Get the code value from the request
	code := r.PostFormValue(ParamCode)
	if code == "" {
		w.WriteHeader(http.StatusUnauthorized)
		s.ErrorHandler(w, ErrorAccessDenied.StatusCode, ErrorAccessDenied)
		return
	}
	// Get the redirect URI, this is required if a redirect URI was used to generate the token
	redirectURI := r.PostFormValue(ParamRedirectURI)
	// Check that the authorization code is valid
	authCode, err := s.SessionStore.CheckAuthorizationCode(Secret(code), redirectURI)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		s.ErrorHandler(w, ErrorAccessDenied.StatusCode, ErrorAccessDenied)
		return
	}
	// Also check the redirect URI against the authenticated client
	ok = client.AllowRedirectURI(redirectURI)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		s.ErrorHandler(w, ErrorUnauthorizedClient.StatusCode, ErrorUnauthorizedClient)
		return
	}
	// If valid, remove the authorization code
	err = s.SessionStore.DeleteAuthorizationCode(Secret(code))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		s.ErrorHandler(w, ErrorServerError.StatusCode, ErrorServerError)
		return
	}
	grant, err := client.CreateGrant(authCode.Scope)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		s.ErrorHandler(w, ErrorServerError.StatusCode, ErrorServerError)
		return
	}
	err = s.SessionStore.PutGrant(grant)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		s.ErrorHandler(w, ErrorServerError.StatusCode, ErrorServerError)
		return
	}
	// Write the grant to the http response
	err = grant.Write(w)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		s.ErrorHandler(w, ErrorServerError.StatusCode, ErrorServerError)
		return
	}
}
