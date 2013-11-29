package srpserver

import (
       "fmt"
       "github.com/japorito/libgosrp"
       "math/big"
)

type challenge_response struct {
	Salt string
	B string
}

// Initialize a challenge_response object, which contains the data that is
// sent from the server to the client.
func (cr *challenge_response) new(v Verifier, sess *SRPSession) (*challenge_response, error) {
	var B big.Int
	var err error
	Ng := make([]byte, len(gp.N.Bytes())+len(gp.G.Bytes())) 
	// make the buffer big enough for N and g

	//calculate kv
	copy(Ng, gp.N.Bytes())
	copy(Ng[len(gp.N.Bytes()):], gp.G.Bytes())
	kv := h(Ng, make([]byte, 0))
	kv.Mul(&kv, &v.Verifier)

	cr.Salt = fmt.Sprintf("%X", v.Salt.Bytes())

	//generate random b
	sess.b, err = srp.RandomBytes(64)

	//check for errors, make sure salt is of the desired length.
	if err != nil {
		return &challenge_response{}, err
	}

	//calculate B = kv+g^b
	B.Exp(&gp.G, &sess.b, &gp.N)
	B.Add(&kv, &B)

	//store B for later calculations.
	sess.bigb = B

	cr.B = fmt.Sprintf("%X", B.Bytes())

	return cr, nil
}

