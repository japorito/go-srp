package srpserver

import (
    "crypto/rand"
    "fmt"
    "github.com/japorito/go-srp"
    "io"
    "math/big"
)

type Verifier struct {
    S []byte
    V []byte
}

type ErrShortSalt struct {
     n, slen int
}

func (e ErrShortSalt) Error() string {
     return fmt.Sprintf("Generated salt is was shorter than requested. Expected length %d, got length %d.", e.slen, e.n)
}

func CreateVerifier(p string, slen int) (Verifier, error) {
    //Create a SRP verifier, given a password p, and the length of the desired salt.
    //Create random salt
    salt := make([]byte, slen)
    n, err := io.ReadFull(rand.Reader, salt)

    //check for errors, make sure salt is of the desired length.
    if err != nil {
        return Verifier{}, err
    } else if n < slen {
        return Verifier{}, ErrShortSalt{n, slen}
    }

    //run hash function on password and salt
    dk := srp.H([]byte(p), salt)
    var x big.Int
    x.SetBytes(dk) //convert []byte to big.Int

    //get group parameters, to use hashing function/create verifier
    gp, err := srp.GetGroupParameters(4096)

    //check for errors, exit if group parameters of that size not found
    if err != nil {
        return Verifier{}, err
    }

    //Prepare variables for big.Int exponentiation call
    var g, zero *big.Int
    g.SetInt64(int64(gp.G))
    zero.SetInt64(int64(0))

    //create verifier v with hash and g (g**x)
    v := x.Exp(g, &x, zero)

    return Verifier{salt, v.Bytes()}, nil
}
