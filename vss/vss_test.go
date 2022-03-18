package vss

import (
	cryptorand "crypto/rand"
	"fmt"
	ed "github.com/jnxchang/go-thresholdeddsa/edwards25519"
	"io"
	"testing"
)

func TestCombine(testing *testing.T) {
	var zero [32]byte
	var one [32]byte
	one[0] = 1
	rand := cryptorand.Reader

	t := 2
	n := 5

	var secret [32]byte
	io.ReadFull(rand, secret[:])
	ed.ScMulAdd(&secret, &secret, &one, &zero)
	fmt.Println("secret:")
	fmt.Println(secret)

	ids := make([][32]byte, n)
	var temId [32]byte
	for i := 0; i < n; i++ {
		io.ReadFull(rand, temId[:])
		ed.ScMulAdd(&temId, &temId, &one, &zero)
		ids[i] = temId
	}

	// input: secret [32]byte, ids [][32]byte, t int, n int
	// cotput: cfs, cfsBBytes, shares : [][32]byte, [][32]byte, [][32]byte
	_, cfsBBytes, shares := Vss(secret, ids, t, n)

	// input: share [32]byte, id [32]byte, cfsBBytes [][32]byte
	// output: bool
	testing.Log("share value and check")
	for i := 0; i < n; i++ {
		testing.Log(Verify(shares[i], ids[i], cfsBBytes))
		testing.Log(shares[i])
	}

	// intput: shares [][32]byte, ids [][32]byte
	// output: secret: [32]byte
	testing.Log("Combine(shares[:], ids[:])")
	testing.Log(Combine(shares[:], ids[:]))
}
