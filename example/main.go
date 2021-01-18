package main

import (
	"log"
	"net/http"

	"github.com/scritchley/goauth"
)

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

func (t *exampleClient) AllowRedirectURI(uri string) bool {
	if uri != t.redirectURI {
		return false
	}
	return true
}

func (t *exampleClient) AllowStrategy(s goauth.Strategy) bool {
	return true
}

func (t *exampleClient) AuthorizeResourceOwner(username string) (bool, error) {
	if t.username != username {
		return false, nil
	}
	return true, nil
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
