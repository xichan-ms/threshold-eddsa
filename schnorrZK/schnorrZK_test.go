package schnorrZK

import (
	cryptorand "crypto/rand"
	ed "github.com/jnxchang/go-thresholdeddsa/edwards25519"
	"io"
	"testing"
)

func TestVerify(t *testing.T) {
	rand := cryptorand.Reader
	var sk [32]byte
	if _, err := io.ReadFull(rand, sk[:]); err != nil {
		t.Log("Error: io.ReadFull(rand, rndNum[:])")
	}
	sk[0] &= 248
	sk[31] &= 127
	sk[31] |= 64

	var one [32]byte
	one[0] = 1
	sk = one

	var pk ed.ExtendedGroupElement
	var pkBytes [32]byte
	ed.GeScalarMultBase(&pk, &sk)
	pk.ToBytes(&pkBytes)

	signature := Prove(sk)

	t.Log(Verify(signature, pkBytes))
}
