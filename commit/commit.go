package commit

import (
	"bytes"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"io"
)

func Commit(secret [][32]byte) ([32]byte, [][32]byte) {
	// Generate the random num
	rand := cryptorand.Reader
	var rndNum [32]byte
	if _, err := io.ReadFull(rand, rndNum[:]); err != nil {
		fmt.Println("Error: io.ReadFull(rand, rndNum[:])")
	}

	var D [][32]byte
	D = append(D, rndNum)
	D = append(D, secret...)

	var rsDigest512 [64]byte
	var C [32]byte

	// hash by sha512
	h := sha512.New()

	h.Write(rndNum[:])
	for _, sec := range secret {
		h.Write(sec[:])
	}
	h.Sum(rsDigest512[:0])

	// hash by sha256
	h = sha256.New()

	h.Write(rsDigest512[:])
	h.Sum(C[:0])

	return C, D
}

func Verify(C [32]byte, D [][32]byte) bool {
	var rsDigest512 [64]byte
	var rsDigest256 [32]byte

	// hash by sha512
	h := sha512.New()

	for _, sec := range D {
		h.Write(sec[:])
	}
	h.Sum(rsDigest512[:0])

	// hash by sha256
	h = sha256.New()

	h.Write(rsDigest512[:])
	h.Sum(rsDigest256[:0])

	if bytes.Equal(C[:], rsDigest256[:]) {
		return true
	} else {
		return false
	}
}
