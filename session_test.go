package goauth

import (
	"reflect"
	"sync"
	"testing"
)

func TestSessionStore(t *testing.T) {
	// Test creating a new Grant and retrieving it from the session store.
	ss := NewSessionStore(&MemSessionStoreBackend{
		&sync.Mutex{},
		make(map[string]Grant),
		make(map[string]AuthorizationCode),
	})
	grant, _ := ss.NewGrant(&testClient{})
	grant2, err := ss.GetGrant(grant.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(grant, grant2) {
		t.Errorf("Test failed, expected %v to equal %v", grant, grant2)
	}
}
