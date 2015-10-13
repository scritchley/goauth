package goauth

import (
	"testing"
)

func TestTokenHandler(t *testing.T) {
	tok, err := newToken()
	if err != nil {
		t.Error(err)
	}
	if len(tok) != 32 {
		t.Errorf("Test failed, got token with length %v", len(tok))
	}
}
