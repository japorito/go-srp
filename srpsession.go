package libgosrp

import (
	"encoding/json"
	"fmt"
	"math/big"
)

type SRPSession struct {
	// pointer to instance of server where
	// the session is held
	server      *SrpServer
	i           string //username
	s, v        big.Int //salt, verifier
	b           big.Int //secret ephemeral value
	biga, bigb  big.Int //public ephemeral value
	session_key big.Int
}

func (s *SRPSession) ReadChallenge(jsonIA string) error {
	if err := s.server.check_init(); err != nil {
		return err
	}

	return nil
}

func (s *SRPSession) New(v Verifier, server *SrpServer) (*SRPSession, error) {
	if err := server.check_init(); err != nil {
		return new(SRPSession), err
	}

	var err error
	s.b, err = server.bgen(64)
	if err != nil {
		return new(SRPSession), err
	}

	//Initialize SRPSession fields.
	//s.I should be set in ReadChallenge
	s.server = server
	s.s = v.Salt
	s.v = v.Verifier
	s.bigb = s.calculate_bigb(s.b)

	return s, nil
}

func (s *SRPSession) ChallengeResponse() (string, error) {
	if err := s.server.check_init(); err != nil {
		return "", err
	}

	var cr ChallengeResponse

	//Populate message from server.
	cr.Salt = fmt.Sprintf("%X", s.s.Bytes())
	cr.B = fmt.Sprintf("%X", s.bigb.Bytes())

	output, err := json.MarshalIndent(cr, "", "    ")
	
	if err != nil {
		return "", err
	}

	return string(output), nil
}

func (s *SRPSession) calulate_k() big.Int {
	var Ng []byte
	gp := s.server.gp

	if s.server.pad_values {
		Ng = append(gp.N.Bytes(), Pad(len(gp.N.Bytes()), gp.G.Bytes())...)
	} else {
		Ng = append(gp.N.Bytes(), gp.G.Bytes()...)
	}

	k := s.server.h(Ng, make([]byte, 0))

	return k
}

func (s *SRPSession) calculate_bigb(b big.Int) big.Int {
	gp := s.server.gp

	//calculate B = kv+g^b
	B := s.calulate_k()
	B.Mul(&B, &s.v)
	B.Add(&B, new(big.Int).Exp(&gp.G, &s.b, &gp.N))

	return B
}
