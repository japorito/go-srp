// The go-srp/srpserver package contains server-side utilities necessary to 
// implement SRP v. 6a, as described here: http://srp.stanford.edu/design.html
// It aims to be a generalized implementation for use with various hash functions
// and key/salt sizes.
package srpserver

import (
    "crypto/rand"
    "fmt"
    "github.com/japorito/go-srp"
    "io"
    "math/big"
)

type Verifier struct {
    S []byte //salt
    V []byte //verifier
}

type ErrShortSalt struct {
     n, slen int
}

func (e ErrShortSalt) Error() string {
     return fmt.Sprintf("Generated salt is was shorter than requested. Expected length %d, got length %d.", e.slen, e.n)
}

// Creates an entirely random salt of length slen.
// For use with Create, if you only need to specify a hash function.
func RandomSalt(slen int) ([]byte, error) {
    salt := make([]byte, slen)
    n, err := io.ReadFull(rand.Reader, salt)

    //check for errors, make sure salt is of the desired length.
    if err != nil {
        return salt, err
    } else if n < slen {
        return salt, ErrShortSalt{n, slen}
    }

    return salt, nil
}

//Initializes new verifier by picking a salt of the desired length slen, and running
//the Hash function H which is passed to it.
func (v *Verifier) Create(p string, slen int, H func([]byte, []byte) []byte, SGen func(int) ([]byte, error)) (*Verifier, error) {
    // Create a SRP verifier, given a password p, and the length of the desired salt,
    // a hash function, and a salt generating function. This is the DIY version of
    // Verifier.New()
    //Create random salt
    var err error
    v.S, err = SGen(slen)

    //check for errors, make sure salt is of the desired length.
    if err != nil {
        return &Verifier{}, err
    }

    //run hash function on password and salt
    dk := H([]byte(p), v.S)
    var x big.Int
    x.SetBytes(dk) //convert []byte to big.Int

    //get group parameters, to use hashing function/create verifier
    gp, err := srp.GetGroupParameters(1024)

    //check for errors, exit if group parameters of that size not found
    if err != nil {
        return &Verifier{}, err
    }

    //Prepare variables for big.Int exponentiation call
    var g big.Int
    g.SetInt64(int64(gp.G))

    //create verifier v with hash and g (g**x % N)
    v.V = x.Exp(&g, &x, &gp.N).Bytes()

    return v, nil
}

func (v *Verifier) New(p string) (*Verifier, error) {
     return v.Create(p, 32, srp.H, RandomSalt)
}