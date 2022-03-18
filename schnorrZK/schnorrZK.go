package schnorrZK

import (
	"bytes"
	cryptorand "crypto/rand"
	"crypto/sha512"
	"fmt"
	ed "github.com/jnxchang/go-thresholdeddsa/edwards25519"
	"io"
)

func Prove(sk [32]byte) [64]byte {
	rand := cryptorand.Reader
	var rndNum [32]byte
	if _, err := io.ReadFull(rand, rndNum[:]); err != nil {
		fmt.Println("Error: io.ReadFull(rand, rndNum[:])")
	}
	var one, zero [32]byte
	one[0] = 1

	ed.ScMulAdd(&rndNum, &rndNum, &one, &zero)

	var R ed.ExtendedGroupElement
	var RBytes [32]byte
	ed.GeScalarMultBase(&R, &rndNum)
	R.ToBytes(&RBytes)

	message := []byte("hello thresholdeddsa")

	// hash by sha512
	var eDigest [64]byte
	var e [32]byte

	h := sha512.New()
	h.Write(RBytes[:])
	h.Write(message[:])
	h.Sum(eDigest[:0])

	ed.ScReduce(&e, &eDigest)

	var s [32]byte
	ed.ScMulAdd(&s, &e, &sk, &rndNum)

	var signature [64]byte
	copy(signature[:32], e[:])
	copy(signature[32:], s[:])

	return signature
}

func Verify(signature [64]byte, pk [32]byte) bool {

	var sG, X, eX, RCal ed.ExtendedGroupElement

	var sTem [32]byte
	copy(sTem[:], signature[32:])
	ed.GeScalarMultBase(&sG, &sTem)

	X.FromBytes(&pk)
	ed.FeNeg(&X.X, &X.X)
	ed.FeNeg(&X.T, &X.T)

	var eTem [32]byte
	copy(eTem[:], signature[:32])
	ed.GeScalarMult(&eX, &eTem, &X)

	ed.GeAdd(&RCal, &sG, &eX)
	var RCalBytes [32]byte
	RCal.ToBytes(&RCalBytes)

	message := []byte("hello thresholdeddsa")

	// hash by sha512
	var eCalDigest [64]byte
	var eCal [32]byte

	h := sha512.New()
	h.Write(RCalBytes[:])
	h.Write(message[:])
	h.Sum(eCalDigest[:0])

	ed.ScReduce(&eCal, &eCalDigest)

	if bytes.Equal(eCal[:], eTem[:]) {
		return true
	} else {
		return false
	}
}
