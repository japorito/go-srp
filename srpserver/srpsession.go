package srpserver

import (
       "encoding/json"
       "fmt"
       "github.com/japorito/libgosrp"
       "math/big"
)

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

	if err != nil {
		return "", err
	}

	var B big.Int
	var cr srp.ChallengeResponse
	Ng := make([]byte, len(gp.N.Bytes())+len(gp.G.Bytes())) 
	// make the buffer big enough for N and g

	//calculate kv
	copy(Ng, gp.N.Bytes())
	copy(Ng[len(gp.N.Bytes()):], gp.G.Bytes())
	kv := h(Ng, make([]byte, 0))
	kv.Mul(&kv, &v.Verifier)

	//generate random b
	s.b, err = srp.RandomBytes(64)

	//check for errors, make sure salt is of the desired length.
	if err != nil {
		return "", err
	}

	//calculate B = kv+g^b
	B.Exp(&gp.G, &s.b, &gp.N)
	B.Add(&kv, &B)

	//store B for later calculations.
	cr.Salt = fmt.Sprintf("%X", v.Salt.Bytes())
	cr.B = fmt.Sprintf("%X", B.Bytes())


	//Initialize SRPSession fields.
	//s.I should be set in ReadChallenge
	s.s = v.Salt
	s.v = v.Verifier
	s.bigb = B


	output, err := json.MarshalIndent(cr, "", "    ")

	if err != nil {
	        return "", err
	}

	return string(output), nil
}
