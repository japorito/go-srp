package srpserver

import (
    "crypto/rand"
    "fmt"
    "io"
    "srp"
)

type Verifier struct {
    s []byte
    v []byte
}

type ErrShortSalt struct {
     n, slen int
}

func (e ErrShortSalt) Error() string {
     return fmt.Sprintf("Salt is too short. Expected length %d, got length %d.", e.slen, e.n)
}

func CreateVerifier(p string, slen int) (Verifier, error) {
    //Create a SRP verifier, given a password p, and the length of the desired salt.
    salt := make([]byte, slen)
    n, err := io.ReadFull(rand.Reader, salt)

    if err != nil {
        return Verifier{}, err
    } else if n < slen {
        return Verifier{}, ErrShortSalt{n, slen}
    }

    return Verifier{salt, []byte("test")}, nil
}
