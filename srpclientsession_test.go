package libgosrp

import (
	"math/big"
	"bytes"
	"testing"
)

func testagen(alen uint) (big.Int, error) {
	var a big.Int
	a.SetString("60975527035CF2AD1989806F0407210BC81EDC04E2762A56AFD529DDDA2D4393", 16)
	return a, nil
}

func TestNewSession(t *testing.T) {
	gp, err := GetGroupParameters(1024)
	if err != nil {
		t.Error(err)
	}

	config := new(SRPConfig).New(gp, testh, testgen)
	config.abgen = testagen
	sess, err := new(SRPClientSession).New("alice", config)

	if err != nil {
		t.Error(err)
	}

	var biga big.Int
	biga.SetString("61D5E490F6F1B79547B0704C436F523DD0E560F0C64115BB72557EC44352E8903211C04692272D8B2D1A5358A2CF1B6E0BFCF99F921530EC8E39356179EAE45E42BA92AEACED825171E1E8B9AF6D9C03E1327F44BE087EF06530E69F66615261EEF54073CA11CF5858F0EDFDFE15EFEAB349EF5D76988A3672FAC47B0769447B", 16)

	if !bytes.Equal(biga.Bytes(), sess.biga.Bytes()) {
		t.Errorf("Public ephemeral value A incorrect.\n Expected: %X\n Got: %X", biga.Bytes(), sess.biga.Bytes())
	}

	if sess.i != "alice" {
		t.Error("Username not correctly set.")
	}

	sess, err = new(SRPClientSession).New("", config)
	if err == nil {
		t.Error("Not properly reporting error on empty username.")
	}
}
