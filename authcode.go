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
{{if .Client.ID}}
	{{if .Scope}}		
		<h3>{{.Client.ID}} has requested access using the following scope:</h3>
		{{range .Scope}}
		<h3>{{.}}</h3>
		{{end}}
	{{else}}
		<h3>{{.Client.ID}} has requested access.</h3>
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
		s.ErrorHandler(w, ErrorUnauthorizedClient)
		return
	}
	rawurl := r.FormValue(ParamRedirectURI)
	uri, err := url.Parse(rawurl)
	if err != nil {
		// The redirect URI is an invalid url, therefore, return an error and DO NOT redirect
		s.ErrorHandler(w, ErrorInvalidRequest)
		return
	}
	// Ensure the redirect URI is allowed
	err = client.AuthorizeRedirectURI(uri.String())
	if err != nil {
		// The redirect URI is invalid, therefore, return an error and DO NOT redirect
		s.ErrorHandler(w, ErrorAccessDenied)
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
		w.WriteHeader(http.StatusUnauthorized)
		s.ErrorHandler(w, ErrorUnauthorizedClient)
		return
	}
	// If the method is POST then check resource owner credentials
	if r.Method == "POST" {
		err := r.ParseForm()
		if err != nil {
			// Render the template
			s.AuthorizeTemplate.Execute(w, map[string]interface{}{
				"Error": err,
			})
			return
		}
		username := r.PostFormValue("username")
		password := r.PostFormValue("password")
		// Check that the client is permitted to act on behalf of the resource owner.
		err = client.AuthorizeResourceOwner(username)
		if err != nil {
			// Render the template with the error
			w.WriteHeader(http.StatusUnauthorized)
			s.AuthorizeTemplate.Execute(w, map[string]interface{}{
				"Error": ErrorUnauthorizedClient,
			})
			return
		}
		scope, err = s.Authenticator.AuthorizeResourceOwner(username, Secret(password), scope)
		if err != nil {
			// Render the template with the error
			w.WriteHeader(http.StatusUnauthorized)
			s.AuthorizeTemplate.Execute(w, map[string]interface{}{
				"Error": fmt.Errorf("username or password invalid"),
			})
			return
		}
		authCode, err := s.SessionStore.NewAuthorizationCode(r.FormValue(ParamRedirectURI), scope)
		if err != nil {
			// Render the template with the error
			w.WriteHeader(http.StatusInternalServerError)
			s.AuthorizeTemplate.Execute(w, map[string]interface{}{
				"Error": fmt.Errorf("an internal server error occurred, please try again"),
			})
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
	// Render the template
	s.AuthorizeTemplate.Execute(w, map[string]interface{}{
		"Client":    client,
		"Scope":     scope,
		"ActionURL": actionURL.Encode(),
	})
}

func (s Server) handleAuthCodeTokenRequest(w http.ResponseWriter, r *http.Request) {
	// Parse the form
	err := r.ParseForm()
	if err != nil {
		s.ErrorHandler(w, err)
		return
	}
	// Authorize the client using basic auth
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		s.ErrorHandler(w, ErrorAccessDenied)
		return
	}
	client, err := s.Authenticator.GetClientWithSecret(clientID, Secret(clientSecret))
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		s.ErrorHandler(w, ErrorUnauthorizedClient)
		return
	}
	// Check that the request is using the correct grant type
	if r.PostFormValue(ParamGrantType) != GrantTypeAuthorizationCode {
		w.WriteHeader(http.StatusBadRequest)
		s.ErrorHandler(w, ErrorInvalidRequest)
		return
	}
	// Get the code value from the request
	code := r.PostFormValue(ParamCode)
	if code == "" {
		w.WriteHeader(http.StatusUnauthorized)
		s.ErrorHandler(w, ErrorAccessDenied)
		return
	}
	// Get the redirect URI, this is required if a redirect URI was used to generate the token
	redirectURI := r.PostFormValue(ParamRedirectURI)
	// Check that the authorization code is valid
	authCode, err := s.SessionStore.CheckAuthorizationCode(Secret(code), redirectURI)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		s.ErrorHandler(w, ErrorAccessDenied)
		return
	}
	// Also check the redirect URI against the authenticated client
	err = client.AuthorizeRedirectURI(redirectURI)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		s.ErrorHandler(w, ErrorUnauthorizedClient)
		return
	}
	// If valid, remove the authorization code
	err = s.SessionStore.DeleteAuthorizationCode(Secret(code))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		s.ErrorHandler(w, ErrorServerError)
		return
	}
	grant, err := s.SessionStore.NewGrant(authCode.Scope)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		s.ErrorHandler(w, ErrorServerError)
		return
	}
	// Write the grant to the http response
	err = grant.Write(w)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		s.ErrorHandler(w, ErrorServerError)
		return
	}
}
