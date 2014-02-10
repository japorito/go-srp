package libgosrp

import (
	"math/big"
)

type SRPClientSession struct {
	config         *SRPConfig
	i              string //username
	hashed_pass    big.Int //hashed password
	s, a           big.Int //salt, private ephemeral value
	biga, bigb     big.Int //public ephemeral value
	session_key    big.Int
}

func (s *SRPClientSession) New(i string, config *SRPConfig) (*SRPClientSession, error) {
	if err := config.check_init(); err != nil {
		return new(SRPClientSession), err
	}

	if i == "" {
		return new(SRPClientSession), new(EmptyUsernameError)
	}

	var err error
	s.config = config
	s.i = i
	s.a, err = config.abgen(64)
	s.biga = s.calculate_biga()

	if err != nil {
		return new(SRPClientSession), err
	}

	return s, nil
}

func (s *SRPClientSession) calculate_biga() big.Int {
	var biga big.Int

	gp := s.config.gp
	biga.Exp(&gp.G, &s.a, &gp.N)
	return biga
}

type EmptyUsernameError int

func (e *EmptyUsernameError) Error() string {
	return "Error: username cannot be empty"
}
