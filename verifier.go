package libgosrp

import (
	"math/big"
)

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
