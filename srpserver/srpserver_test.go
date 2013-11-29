package srpserver

import (
	"crypto/sha1"
	"github.com/japorito/libgosrp"
	"math/big"
	"testing"
)

var v Verifier
var s SRPSession

// Gives a non-random salt for the purpose of testing.
func testgen(slen uint) (big.Int, error) {
	var salt big.Int
	salt.SetString("BEB25379D1A8581EB5A727673A2441EE", 16)
	return salt, nil
}

// Implements the hash function described in RFC 5054
// so that we can use their test vector to verify our code
func testh(to_hash, salt []byte) big.Int {
	var hash []byte
	var output big.Int

	outerhash := sha1.New()
	innerhash := sha1.New()

	innerhash.Write(to_hash)
	salt = innerhash.Sum(salt)
	outerhash.Write(salt)

	hash = outerhash.Sum(hash)
	output.SetBytes(hash)

	return output
}

func TestCheckInit(t *testing.T) {
        err := check_init()

	if err == nil {
	        t.Error("Error: failed to find uninitialized SrpServer.")
	} else {
		t.Log("check_init() correctly found uninitialized SrpServer.")
	}

     	testgp, err := srp.GetGroupParameters(1024)

	if err != nil {
	        t.Error("Error: ", err)
	}

        SrpServer(testgp, testh, testgen)
	err = check_init()

	if err != nil {
	        t.Error(err)
	} else {
		t.Log("check_init() correctly found SrpServer to be initialized.")
	}
}

// Tests v.New() with a simple hash function and a given salt
// checks output with test vector from appendix of RFC 5054
func TestSimpleHashSalt(t *testing.T) {
     	testgp, err := srp.GetGroupParameters(1024)

	if err != nil {
	        t.Error("Error: ", err)
	}

        SrpServer(testgp, testh, testgen)
	_, err = v.New("alice", "alice:password123", 32)
	if err == nil {
		t.Logf("Verifier is %X.\nSalt is %X.\n", v.Verifier.Bytes(), v.Salt.Bytes())
	} else {
		t.Error("Error: ", err)
	}

	var correctv, corrects big.Int
	correctv.SetString("7E273DE8696FFC4F4E337D05B4B375BEB0DDE1569E8FA00A9886D8129BADA1F1822223CA1A605B530E379BA4729FDC59F105B4787E5186F5C671085A1447B52A48CF1970B4FB6F8400BBF4CEBFBB168152E08AB5EA53D15C1AFF87B2B9DA6E04E058AD51CC72BFC9033B564E26480D78E955A5E29E7AB245DB2BE315E2099AFB", 16)
	corrects.SetString("BEB25379D1A8581EB5A727673A2441EE", 16)

	if len(corrects.Bytes()) != len(v.Salt.Bytes()) {
	        t.Error("Error: recieved incorrect salt.")
	}

	var fail bool = false

	correct_salt := corrects.Bytes()
	got_salt := v.Salt.Bytes()
	for i := range correct_salt {
		if got_salt[i] != correct_salt[i] {
			fail = true
		}
	}

	if fail {
		t.Error("Error: recieved incorrect salt.")
		fail = false
	}

	if len(correctv.Bytes()) != len(v.Verifier.Bytes()) {
	        t.Error("Error: recieved incorrect verifier.")
	}

	correct_verifier := correctv.Bytes()
	got_verifier := v.Verifier.Bytes()
	for i := range correct_verifier {
		if got_verifier[i] != correct_verifier[i] {
			fail = true
		}
	}

	if fail {
		t.Errorf("Error: Incorrect verifier.\nExpected: %X\nGot: %X", correct_verifier, got_verifier)
	}

	if v.I != "alice" {
	        t.Errorf("Error: username should be set to alice. Got %v", v.I)
	}
}

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

func TestStandardHashSalt(t *testing.T) {
        var tmpv Verifier
        testgp, err := srp.GetGroupParameters(4096)

	if err != nil {
	        t.Error("Error: ", err)
	}

        SrpServer(testgp, srp.H, RandomBytes)
	_, err = tmpv.New("username", "password", 32)
	if err != nil {
		t.Error(err)
	} else if len(tmpv.Salt.Bytes()) != 32 {
		t.Error(ErrorShortSalt{len(tmpv.Salt.Bytes()), 32})
	} else if len(tmpv.Verifier.Bytes()) == 0 {
		t.Error("Error: empty verifier returned.")
	} else if tmpv.I != "username" {
	        t.Errorf("Error: username should be set to \"username\". Got %v", tmpv.I)
	}

	t.Log("Verifier successfully created via v.New()")
	t.Logf("Salt: %X", tmpv.Salt.Bytes())
	t.Logf("Verifier: %X", tmpv.Verifier.Bytes())
	t.Logf("littleb: %X", Debug.Bytes())
}

func TestChallengeResponse(t *testing.T) {
        testgp, err := srp.GetGroupParameters(1024)

	if err != nil {
	        t.Error("Error: ", err)
	}

        SrpServer(testgp, testh, testgen)

	cr, err := s.ChallengeResponse(v)

	if err != nil {
	        t.Error("Error: ", err)
	} else {
	        t.Log("JSON encoded challenge response containing s and B: ", cr)
	}
}