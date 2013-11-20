package srpserver

import (
    "crypto/sha1"
    "fmt"
    "math/big"
    "testing"
)

var v Verifier

// Gives a non-random salt for the purpose of testing.
func sgen(slen int) ([]byte, error) {
    var salt big.Int
    salt.SetString("BEB25379D1A8581EB5A727673A2441EE", 16)
    return salt.Bytes(), nil
}

// Implements the hash function described in RFC 5054
// so that we can use their test vector to verify our code
func h(to_hash, salt []byte) []byte {
    var hash []byte
    outerhash := sha1.New()
    innerhash := sha1.New()
    
    innerhash.Write(to_hash)
    salt = innerhash.Sum(salt)
    outerhash.Write(salt)

    return outerhash.Sum(hash)
}

// Tests v.Create() with a simple hash function and a given salt
// checks output with test vector from appendix of RFC 5054
func TestCreateVerifier(t *testing.T) {
    _, err := v.Create("alice:password123", 32, h, sgen)
    if err == nil {
       t.Logf("Verifier is %X.\nSalt is %X.\n", v.V, v.S)
    } else {
       t.Error("Error: ", err)
    }

    var correctv, corrects []byte
    fmt.Sscanf("7E273DE8696FFC4F4E337D05B4B375BEB0DDE1569E8FA00A9886D8129BADA1F1822223CA1A605B530E379BA4729FDC59F105B4787E5186F5C671085A1447B52A48CF1970B4FB6F8400BBF4CEBFBB168152E08AB5EA53D15C1AFF87B2B9DA6E04E058AD51CC72BFC9033B564E26480D78E955A5E29E7AB245DB2BE315E2099AFB", "%X", correctv)
    fmt.Sscanf("BEB25379D1A8581EB5A727673A2441EE", "%X", corrects)
    
    for i := range corrects {
        if v.S[i] != corrects[i] {
            t.Error("Error: recieved incorrect salt.")
        }
    } 

    for i := range correctv {
        if v.V[i] != correctv[i] {
            t.Errorf("Error: Incorrect verifier.\nExpected: %X\nGot: %X", correctv, v.V)
        }
    }
}


// Runs RandomSalt. Errors if err is non-nil
func TestRandomSalt(t *testing.T) {
    _, err := RandomSalt(10)
    if err != nil {
        t.Error(err)
    }
}

func TestNew(t *testing.T) {
     _, err := v.New("password")
     if err != nil {
         t.Error(err)
     } else if len(v.S) < 32 {
         t.Error(ErrShortSalt{len(v.S), 32})
     } else if len(v.V) == 0 {
         t.Error("Error: empty verifier returned.")
     }

     t.Log("Verifier successfully created via v.New()")
     t.Log("Salt: ", v.S)
     t.Log("Verifier: ", v.V)
}