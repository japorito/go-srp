package libgosrp

import (
	"bytes"
	"crypto/sha1"
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

func testbgen(slen uint) (big.Int, error) {
	var b big.Int
	b.SetString("E487CB59D31AC550471E81F00F6928E01DDA08E974A004F49E61F5D105284D20", 16)
	return b, nil
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

func sha1hash(to_hash, salt []byte) big.Int {
	var output big.Int

	hash := sha1.New()
	hash.Write(to_hash)
	hash.Write(salt)
	output.SetBytes(hash.Sum(make([]byte, 0)))

	return output
}

func TestCheckInit(t *testing.T) {
	err := check_init()

	if err == nil {
		t.Error("Error: failed to find uninitialized SrpServer.")
	} else {
		t.Log("check_init() correctly found uninitialized SrpServer.")
	}

	testgp, err := GetGroupParameters(1024)

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
	testgp, err := GetGroupParameters(1024)

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

	if !bytes.Equal(correctv.Bytes(), v.Verifier.Bytes()) {
		t.Errorf("Error: Incorrect verifier.\nExpected: %X\nGot: %X", correctv.Bytes(), v.Verifier.Bytes())
	}

	if !bytes.Equal(corrects.Bytes(), v.Salt.Bytes()) {
		t.Error("Error: recieved incorrect salt.")
	}

	if v.I != "alice" {
		t.Errorf("Error: username should be set to alice. Got %v", v.I)
	}
}

func TestStandardHashSalt(t *testing.T) {
	var tmpv Verifier
	testgp, err := GetGroupParameters(4096)

	if err != nil {
		t.Error("Error: ", err)
	}

	SrpServer(testgp, H, RandomBytes)
	_, err = tmpv.New("username", "password", 32)
	if err != nil {
		t.Error(err)
	} else if len(tmpv.Verifier.Bytes()) == 0 {
		t.Error("Error: empty verifier returned.")
	} else if tmpv.I != "username" {
		t.Errorf("Error: username should be set to \"username\". Got %v", tmpv.I)
	}

	t.Log("Verifier successfully created via v.New()")
	t.Logf("Salt: %X", tmpv.Salt.Bytes())
	t.Logf("Verifier: %X", tmpv.Verifier.Bytes())
}

// NOT rfc 5054 compliant
// They do some magic with their B. It is smaller
// than k*v, and it is supposed to be
// kv+g^b%N. I just implemented the actual
// equation. Tests now diverge from rfc5054
func TestChallengeResponse(t *testing.T) {
	testgp, err := GetGroupParameters(1024)
	var littleb, bigb big.Int

	t.Logf("%X", v.Verifier.Bytes())

	if err != nil {
		t.Error("Error: ", err)
	}

	SrpServer(testgp, sha1hash, testgen)

	bgen = testbgen

	cr, err := s.ChallengeResponse(v)

	if err != nil {
		t.Error("Error: ", err)
	} else {
		t.Log("JSON encoded challenge response containing s and B: ", cr)
	}

	littleb.SetString("E487CB59D31AC550471E81F00F6928E01DDA08E974A004F49E61F5D105284D20", 16)
	// Not from rfc 5054
	bigb.SetString("39D2A44238CC9017300647C9D9171B1468AE0A4D4538E4479B28E9307B57CCBAD240E26DF9651C381F02E54AC13A40A8193F8E77556FB8EEF83F7AF6DBAC7F5FFDF338649FF4B211BA88AE11AE0C99C44F921F2FA447E082395EE92709ED61A114F7FDF814440A40B509044CDD98C259613B281D73B3620DE8AEBAFF90604264FD2818C79B32EE1A53B9CEE98D74938F200E3DF8", 16)

	if !bytes.Equal(littleb.Bytes(), s.b.Bytes()) {
		t.Errorf("Error: littleb not properly set in test function. Possible problem in testbgen(). Expected: %X\nGot: %X", littleb.Bytes(), s.b.Bytes())
	}

	if !bytes.Equal(bigb.Bytes(), s.bigb.Bytes()) {
		t.Errorf("Error: bigb incorrect. \nExpected: %X\nGot: %X", bigb.Bytes(), s.bigb.Bytes())
	}
}
