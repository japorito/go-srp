// The go-srp/srpserver package contains server-side utilities necessary to
// implement SRP v. 6a, as described here: http://srp.stanford.edu/design.html
// It aims to be a generalized implementation for use with various hash functions
// and key/salt sizes.
package srpserver

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/japorito/libgosrp"
	"io"
	"math/big"
)

var gp srp.SRPGroupParameters
var h func([]byte, []byte) big.Int
var sgen func(uint) (big.Int, error)

var Debug big.Int

func SrpServer(srpgp srp.SRPGroupParameters, hash func([]byte, []byte) big.Int, salt_gen func(uint) (big.Int, error)) {
	gp = srpgp
	h = hash
	sgen = salt_gen
}

func check_init() error {
        if h == nil || sgen == nil || len(gp.G.Bytes()) == 0 || len(gp.N.Bytes()) == 0 {
	        var err ErrorUninitializedSrpServer
		return err
	}

	return nil
}

type ErrorUninitializedSrpServer string

func (e ErrorUninitializedSrpServer) Error() string {
        return fmt.Sprintln("SRP Server improperly initialized. Please call SrpServer() with valid SRPGroupParameters, a hash function, and a salt generating function.", e)
}

// Creates an entirely random salt of length slen.
// For use with Create, if you only need to specify a hash function.
func RandomBytes(slen uint) (big.Int, error) {
	s := make([]byte, slen)
	n, err := io.ReadFull(rand.Reader, s)
	var salt big.Int
	salt.SetBytes(s)
	
	//check for errors, make sure salt is of the desired length.
	if err != nil {
		return salt, err
	} else if uint(n) < slen {
		return salt, ErrorShortSalt{n, slen}
	}

	return salt, nil
}

type ErrorShortSalt struct {
	n    int
	slen uint
}

func (e ErrorShortSalt) Error() string {
	return fmt.Sprintf("Generated salt is was shorter than requested. Expected length %d, got length %d.", e.slen, e.n)
}

type Verifier struct {
	I        string
	Salt     big.Int //salt
	Verifier big.Int //verifier
}

// Create an SRP verifier, given a password p, and the length of the desired salt,
// a hash function, and a salt generating function. This is the DIY version of
// Verifier.New()
// Note: does NOT take a function that generates a hash.Hash, because this would
// preclude doing things like pbkdf2, which takes the password and salt and deals
// with them separately. The function handed to this should be a wrapper function
// that takes the password and salt as its 1st and 2nd argument respectively.
func (v *Verifier) New(user, p string, slen uint) (*Verifier, error) {
	//Create random salt
	var err error

	v.I = user
	v.Salt, err = sgen(slen)

	//check for errors, make sure salt is of the desired length.
	if err != nil {
		return &Verifier{}, err
	}

	//run hash function on password and salt
	x := h([]byte(p), v.Salt.Bytes())

	//create verifier v with hash and g (g**x % N)
	v.Verifier.Exp(&gp.G, &x, &gp.N)

	return v, nil
}

type SRPSession struct {
	i                string
	s, v    	 big.Int
	b		 big.Int
	biga, bigb       big.Int
	session_key      big.Int
}

func (s *SRPSession) ReadChallenge(jsonIA string) error {
        err := check_init()

	return err
}

func (s *SRPSession) ChallengeResponse(v Verifier) (string, error) {
        err := check_init()

	var message challenge_response
	message.new(v, s)

	//Initialize SRPSession fields. s.littleb is set in challenge_response.new
	//s.I should be set in ReadChallenge
	s.s = v.Salt
	s.v = v.Verifier

	output, err := json.MarshalIndent(message, "", "    ")

	if err != nil {
	        return "", err
	}

	return string(output), nil
}

type ErrorWrongB struct {
        expectedLen, gotLen int
}

func (e ErrorWrongB) Error() string {
     return fmt.Sprintf("Read B value different than expected. Expected value of length %v bytes, read %v bytes", e.expectedLen, e.gotLen)
}

type challenge_response struct {
	Salt string
	B string
}

// Initialize a challenge_response object, which contains the data that is
// sent from the server to the client.
func (cr *challenge_response) new(v Verifier, sess *SRPSession) (*challenge_response, error) {
	var B big.Int
	Ng := make([]byte, len(gp.N.Bytes())+len(gp.G.Bytes())) 
	// make the buffer big enough for N and g

	//calculate kv
	copy(Ng, gp.N.Bytes())
	copy(Ng[len(gp.N.Bytes()):], gp.G.Bytes())
	kv := h(Ng, make([]byte, 0))
	kv.Mul(&kv, &v.Verifier)

	cr.Salt = fmt.Sprintf("%X", v.Salt.Bytes())

	//generate random b
	sess.b, err := RandomBytes(64)

	//check for errors, make sure salt is of the desired length.
	if err != nil {
		return &challenge_response{}, err
	}

	//calculate B = kv+g^b
	B.Exp(&gp.G, &sess.b, &gp.N)
	B.Add(&B, &kv)

	//store B for later calculations.
	sess.bigb = B

	cr.B = fmt.Sprintf("%X", B.Bytes())

	return cr, nil
}
