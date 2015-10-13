package goauth

import (
	"testing"
)

func TestSecret(t *testing.T) {
	s := Secret("test")
	if s.String() != "xxxx" {
		t.Errorf("Test failed, got %s", s.String())
	}
}
