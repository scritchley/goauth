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
)

// AuthorizationCode is a temporary authorization request
// that can be exchanged for a Grant.
type AuthorizationCode struct {
	Code        Secret
	RedirectURI string
	CreatedAt   time.Time
}

// IsExpired returns true if the AuthorizationCode has expired.
func (a AuthorizationCode) IsExpired() bool {
	return a.CreatedAt.Add(DefaultAuthorizationCodeExpiry).Before(timeNow())
}

// CheckRedirectURI checks the given redirect URI against the provided string.
func (a AuthorizationCode) CheckRedirectURI(s string) bool {
	return a.RedirectURI == s
}

// AuthorizationCodeGrant implements methods required to perform
// an Authorization Code Grant as per http://tools.ietf.org/html/rfc6749#section-4.1
type AuthorizationCodeGrant interface {
	// GetClient returns a Client given a client ID. It returns an error if the client is not found or if
	// the client ID is invalid.
	GetClient(clientID string) (Client, error)
	// GetClientWithSecret returns a Client given a client ID and secret. It returns an error if the client
	// is not found or if the client ID is invalid.
	GetClientWithSecret(clientID string, clientSecret Secret) (Client, error)
	// AuthorizeCode checks the resource owners credentials and requested scope. If successful it returns
	// a new AuthorizationCode, otherwise, it returns an error.
	AuthorizeCode(username string, password Secret, scope []string) error
}

// generateAuthorizationCodeGrantHandler returns an http.HandlerFunc using the provided AuthorizationCodeGrant, Template and SessionStore.
func generateAuthorizationCodeGrantHandler(acg AuthorizationCodeGrant, template *template.Template, sessionStore *SessionStore) http.HandlerFunc {
	// Add the token request handler for this auth type
	tokenHandlers.AddHandler(GrantTypeAuthorizationCode, generateAuthCodeTokenRequestHandler(acg, sessionStore))
	// Return a http.HandlerFunc
	return func(w http.ResponseWriter, r *http.Request) {
		// Get the client
		clientID := r.FormValue(ParamClientID)
		client, err := acg.GetClient(clientID)
		if err != nil {
			// Failed to retrieve client, therefore, return an error and DO NOT redirect
			DefaultErrorHandler(w, ErrorUnauthorizedClient)
			return
		}
		rawurl := r.FormValue(ParamRedirectURI)
		uri, err := url.Parse(rawurl)
		if err != nil {
			// The redirect URI is invalid, therefore, return an error and DO NOT redirect
			DefaultErrorHandler(w, ErrorInvalidRequest)
			return
		}
		// Ensure the redirect URI is allowed
		err = client.AuthorizeRedirectURI(uri.String())
		if err != nil {
			// The redirect URI is invalid, therefore, return an error and DO NOT redirect
			DefaultErrorHandler(w, ErrorAccessDenied)
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
		// If the method is POST then check resource owner credentials
		if r.Method == "POST" {
			err := r.ParseForm()
			if err != nil {
				// Render the template
				template.Execute(w, map[string]interface{}{
					"Error": err,
				})
				return
			}
			username := r.PostFormValue("username")
			password := r.PostFormValue("password")
			err = acg.AuthorizeCode(username, Secret(password), scope)
			if err != nil {
				// Render the template with the error
				template.Execute(w, map[string]interface{}{
					"Error": fmt.Errorf("username or password invalid"),
				})
				return
			}
			// Generate a new AuthorizationCode
			authCode := AuthorizationCode{
				Code:        Secret(NewToken()),
				RedirectURI: r.FormValue(ParamRedirectURI),
				CreatedAt:   timeNow(),
			}
			// Store the authorization code within the session store
			err = sessionStore.PutAuthorizationCode(authCode)
			if err != nil {
				// Render the template with the error
				template.Execute(w, map[string]interface{}{
					"Error": fmt.Errorf("an internal server error occurred, please try again"),
				})
				return
			}
			// The AuthorizationCode has been approved therefore redirect including the code
			values := uri.Query()
			values.Add(ParamCode, authCode.Code.string())
			// If the state param was included then make sure it is passed onto the redirect
			if r.FormValue(ParamState) != "" {
				values.Add(ParamState, r.FormValue(ParamState))
			}
			uri.RawQuery = values.Encode()
			urlStr := uri.String()
			http.Redirect(w, r, urlStr, http.StatusFound)
			return
		}
		// Render the template
		template.Execute(w, map[string]interface{}{
			"Client": client,
			"Scope":  scope,
		})
	}
}

func generateAuthCodeTokenRequestHandler(acg AuthorizationCodeGrant, sessionStore *SessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse the form
		err := r.ParseForm()
		if err != nil {
			DefaultErrorHandler(w, err)
			return
		}
		// Authorize the client using basic auth
		clientID, clientSecret, ok := r.BasicAuth()
		if !ok {
			DefaultErrorHandler(w, ErrorAccessDenied)
			return
		}
		client, err := acg.GetClientWithSecret(clientID, Secret(clientSecret))
		if err != nil {
			DefaultErrorHandler(w, err)
			return
		}
		// Check that the request is using the correct grant type
		if r.PostFormValue(ParamGrantType) != GrantTypeAuthorizationCode {
			DefaultErrorHandler(w, ErrorInvalidRequest)
			return
		}
		// Get the code value from the request
		code := r.PostFormValue(ParamCode)
		if code == "" {
			DefaultErrorHandler(w, ErrorAccessDenied)
			return
		}
		// Get the redirect URI, this is required if a redirect URI was used to generate the token
		redirectURI := r.PostFormValue(ParamRedirectURI)
		// Check that the authorization code is valid
		err = sessionStore.CheckAuthorizationCode(Secret(code), redirectURI)
		if err != nil {
			DefaultErrorHandler(w, err)
			return
		}
		// Also check the redirect URI against the authenticated client
		err = client.AuthorizeRedirectURI(redirectURI)
		if err != nil {
			DefaultErrorHandler(w, err)
			return
		}
		// If valid, remove the authorization code
		err = sessionStore.DeleteAuthorizationCode(Secret(code))
		if err != nil {
			DefaultErrorHandler(w, err)
			return
		}
		grant, err := sessionStore.NewGrant(client)
		if err != nil {
			DefaultErrorHandler(w, err)
			return
		}
		// Write the grant to the http response
		err = grant.Write(w)
		if err != nil {
			DefaultErrorHandler(w, err)
			return
		}
	}
}
