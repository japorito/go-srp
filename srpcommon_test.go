package libgosrp

import (
	"testing"
)

// Runs RandomBytes. Errors if err is non-nil
func TestRandomBytes(t *testing.T) {
	n, err := RandomBytes(64)
	if err != nil {
		t.Error(err)
	} else if len(n.Bytes()) != 64 {
		t.Error("Error: RandomBytes gave an incorrect length.")
	}

	t.Logf("Salt: %X", n.Bytes())
}
