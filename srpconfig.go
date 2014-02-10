// The go-srp/srpserver package contains server-side utilities necessary to
// implement SRP v. 6a, as described here: http://srp.stanford.edu/design.html
// It aims to be a generalized implementation for use with various hash functions
// and key/salt sizes.
package libgosrp

import (
	"fmt"
	"math/big"
)

type SRPConfig struct {
	gp SRPGroupParameters
	h func([]byte, []byte) big.Int
	sgen func(uint) (big.Int, error)
	//generator for private ephemeral values
	//only defined here for testing purposes
	//(replaced with function that gives predictable value)
	abgen func(uint) (big.Int, error)
	pad_values bool
}

func (s *SRPConfig) New(srpgp SRPGroupParameters, hash func([]byte, []byte) big.Int, salt_gen func(uint) (big.Int, error)) *SRPConfig {
	s.gp = srpgp
	s.h = hash
	s.sgen = salt_gen
	s.abgen = RandomBytes
	s.pad_values = true

	return s
}

func (s *SRPConfig) SetPad(value bool) {
	s.pad_values = value
}

func (s *SRPConfig) check_init() *ErrorUninitializedSRPConfig {
	if s.h == nil || s.sgen == nil || s.gp.isEmpty() {
		return new(ErrorUninitializedSRPConfig)
	}

	return nil
}

type ErrorUninitializedSRPConfig string

func (e ErrorUninitializedSRPConfig) Error() string {
	return fmt.Sprintln("SRP configuration improperly initialized. Please call SRPConfig.New() with valid SRPGroupParameters, a hash function, and a salt generating function.", e)
}
