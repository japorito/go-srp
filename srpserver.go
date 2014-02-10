// The go-srp/srpserver package contains server-side utilities necessary to
// implement SRP v. 6a, as described here: http://srp.stanford.edu/design.html
// It aims to be a generalized implementation for use with various hash functions
// and key/salt sizes.
package libgosrp

import (
	"fmt"
	"math/big"
)

type SrpServer struct {
	gp SRPGroupParameters
	h func([]byte, []byte) big.Int
	sgen func(uint) (big.Int, error)
	bgen func(uint) (big.Int, error)
	pad_values bool
}

func (s *SrpServer) SrpServer(srpgp SRPGroupParameters, hash func([]byte, []byte) big.Int, salt_gen func(uint) (big.Int, error)) *SrpServer {
	s.gp = srpgp
	s.h = hash
	s.sgen = salt_gen
	s.bgen = RandomBytes
	s.pad_values = true

	return s
}

func (s *SrpServer) SetPad(value bool) {
	s.pad_values = value
}

func (s *SrpServer) check_init() *ErrorUninitializedSrpServer {
	if s.h == nil || s.sgen == nil || s.gp.isEmpty() {
		return new(ErrorUninitializedSrpServer)
	}

	return nil
}

type ErrorUninitializedSrpServer string

func (e ErrorUninitializedSrpServer) Error() string {
	return fmt.Sprintln("SRP Server improperly initialized. Please call SrpServer() with valid SRPGroupParameters, a hash function, and a salt generating function.", e)
}
