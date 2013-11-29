package srpserver

import (
       "encoding/json"
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
