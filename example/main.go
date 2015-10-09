package main

import (
	"html/template"
	"log"
	"net/http"

	"code.simon-critchley.co.uk/goauth"
)

var tmpl = template.Must(template.New("authorize").Parse(`
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

type exampleAuthServer struct {
	client   *exampleClient
	username string
	password goauth.Secret
}

func (t *exampleAuthServer) GetClient(clientID string) (goauth.Client, error) {
	if clientID == t.client.ID {
		return t.client, nil
	}
	return nil, goauth.ErrorUnauthorizedClient
}

func (t *exampleAuthServer) GetClientWithSecret(clientID string, clientSecret goauth.Secret) (goauth.Client, error) {
	if clientID == t.client.ID && clientSecret.RawString() == t.client.secret {
		return t.client, nil
	}
	return nil, goauth.ErrorUnauthorizedClient
}

func (t *exampleAuthServer) AuthorizeResourceOwner(username string, password goauth.Secret, scope []string) ([]string, error) {
	if username != t.username {
		return nil, goauth.ErrorAccessDenied
	}
	if password != t.password {
		return nil, goauth.ErrorAccessDenied
	}
	return scope, nil
}

type exampleClient struct {
	ID          string
	secret      string
	username    string
	redirectURI string
	scope       []string
}

func (t *exampleClient) AuthorizeScope(scope []string) ([]string, error) {
	var approvedScope []string
	for _, requestedScope := range scope {
		for _, allowedScope := range t.scope {
			if allowedScope == requestedScope {
				approvedScope = append(approvedScope, requestedScope)
			}
		}
	}
	return approvedScope, nil
}

func (t *exampleClient) AuthorizeRedirectURI(uri string) error {
	if uri != t.redirectURI {
		return goauth.ErrorUnauthorizedClient
	}
	return nil
}

func (t *exampleClient) AuthorizeResourceOwner(username string) error {
	if t.username != username {
		return goauth.ErrorUnauthorizedClient
	}
	return nil
}

var example = &exampleAuthServer{
	&exampleClient{
		"testclientid",
		"testclientsecret",
		"testusername",
		"https://testuri.com",
		[]string{"testscope"},
	},
	"testusername",
	goauth.Secret("testpassword"),
}

func main() {

	handler := goauth.New(example)

	log.Fatal(http.ListenAndServe(":8080", handler))
}
