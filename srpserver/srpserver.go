// The go-srp/srpserver package contains server-side utilities necessary to
// implement SRP v. 6a, as described here: http://srp.stanford.edu/design.html
// It aims to be a generalized implementation for use with various hash functions
// and key/salt sizes.
package srpserver

import (
	"fmt"
	"github.com/japorito/libgosrp"
	"math/big"
)

var gp srp.SRPGroupParameters
var h func([]byte, []byte) big.Int
var sgen func(uint) (big.Int, error)

func SrpServer(srpgp srp.SRPGroupParameters, hash func([]byte, []byte) big.Int, salt_gen func(uint) (big.Int, error)) {
	gp = srpgp
	h = hash
	sgen = salt_gen
}

func check_init() error {
        if h == nil || sgen == nil || len(gp.G.Bytes()) == 0 || len(gp.N.Bytes()) == 0 {
	        var err ErrorUninitializedSrpServer
		return err
	}

	return nil
}

type ErrorUninitializedSrpServer string

func (e ErrorUninitializedSrpServer) Error() string {
        return fmt.Sprintln("SRP Server improperly initialized. Please call SrpServer() with valid SRPGroupParameters, a hash function, and a salt generating function.", e)
}
