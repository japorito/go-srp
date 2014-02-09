package libgosrp

import (
	"encoding/json"
	"fmt"
	"math/big"
)

type SRPSession struct {
	i           string
	s, v        big.Int
	b           big.Int
	biga, bigb  big.Int
	session_key big.Int
}

func (s *SRPSession) ReadChallenge(jsonIA string) error {
	err := check_init()

	if err != nil {
		return err
	}

	return err
}

func (s *SRPSession) ChallengeResponse(v Verifier) (string, error) {
	err := check_init()
	if err != nil {
		return "", err
	}

	var cr ChallengeResponse

	s.b, err = bgen(64)
	if err != nil {
		return "", err
	}

	//calculate B = kv+g^b
	B := calulate_k()
	B.Mul(&B, &v.Verifier)
	B.Add(&B, new(big.Int).Exp(&gp.G, &s.b, &gp.N))

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

func calulate_k() big.Int {
	var Ng []byte

	if pad_values {
		Ng = append(gp.N.Bytes(), Pad(len(gp.N.Bytes()), gp.G.Bytes())...)
	} else {
		Ng = append(gp.N.Bytes(), gp.G.Bytes()...)
	}

	k := h(Ng, make([]byte, 0))

	return k
}
