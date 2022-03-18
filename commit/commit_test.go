package commit

import (
	"testing"
)

func TestVerify(t *testing.T) {
	message := []byte("hello thresholdeddsa")
	var secret [32]byte
	copy(secret[:], message[:])

	C, D := Commit(secret)
	t.Log(Verify(C, D))
}
