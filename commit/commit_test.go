package commit

import (
	"testing"
)

func TestVerify(t *testing.T) {
	message := []byte("hello thresholdeddsa")
	var secrets [][32]byte
	var secret [32]byte
	copy(secret[:], message[:])
	secrets = append(secrets, secret)

	C, D := Commit(secrets)
	t.Log(Verify(C, D))
}
