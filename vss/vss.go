package vss

import (
	"bytes"
	cryptorand "crypto/rand"
	"fmt"
	ed "github.com/jnxchang/go-thresholdeddsa/edwards25519"
	"io"
)

func Vss(secret [32]byte, ids [][32]byte, t int, n int) ([][32]byte, [][32]byte, [][32]byte) {

	var cfs, cfsBBytes, shares [][32]byte

	cfs = append(cfs, secret)

	var cfB ed.ExtendedGroupElement
	var cfBBytes [32]byte
	ed.GeScalarMultBase(&cfB, &secret)
	cfB.ToBytes(&cfBBytes)
	cfsBBytes = append(cfsBBytes, cfBBytes)

	var zero [32]byte
	var one [32]byte
	one[0] = 1
	rand := cryptorand.Reader

	for i := 1; i <= t-1; i++ {
		var rndNum [32]byte
		if _, err := io.ReadFull(rand, rndNum[:]); err != nil {
			fmt.Println("Error: io.ReadFull(rand, rndNum[:])")
		}
		ed.ScMulAdd(&rndNum, &rndNum, &one, &zero)

		cfs = append(cfs, rndNum)

		ed.GeScalarMultBase(&cfB, &rndNum)
		cfB.ToBytes(&cfBBytes)
		cfsBBytes = append(cfsBBytes, cfBBytes)
	}

	for i := 0; i < n; i++ {
		share := calculatePolynomial(cfs, ids[i])
		shares = append(shares, share)
	}

	return cfs, cfsBBytes, shares
}

func Verify(share [32]byte, id [32]byte, cfsBBytes [][32]byte) bool {
	var rlt1, rlt2, tem ed.ExtendedGroupElement

	rlt1.FromBytes(&cfsBBytes[0])

	idVal := id

	for i := 1; i < len(cfsBBytes); i++ {
		tem.FromBytes(&cfsBBytes[i])
		ed.GeScalarMult(&tem, &idVal, &tem)

		ed.GeAdd(&rlt1, &rlt1, &tem)
		ed.ScMul(&idVal, &idVal, &id)
	}

	ed.GeScalarMultBase(&rlt2, &share)

	var rlt1Bytes, rlt2Bytes [32]byte
	rlt1.ToBytes(&rlt1Bytes)
	rlt2.ToBytes(&rlt2Bytes)

	if bytes.Equal(rlt1Bytes[:], rlt2Bytes[:]) {
		return true
	} else {
		return false
	}
}

func Combine(shares [][32]byte, ids [][32]byte) [32]byte {
	var one [32]byte
	one[0] = 1

	order := ed.GetBytesOrder()
	var secret [32]byte

	for j := 0; j < len(shares); j++ {
		var times [32]byte
		times[0] = 1

		// calculate times()
		for i := 0; i < len(shares); i++ {
			if j != i {
				var time [32]byte
				ed.ScSub(&time, &ids[i], &ids[j])
				time = ed.ScModInverse(time, order)

				ed.ScMul(&time, &time, &ids[i])

				ed.ScMul(&times, &times, &time)
			}
		}

		// calculate sum(f(x) * times())
		var sTimes [32]byte
		ed.ScMul(&sTimes, &shares[j], &times)

		ed.ScAdd(&secret, &sTimes, &secret)
	}
	// fmt.Println()
	return secret
}

func calculatePolynomial(cfs [][32]byte, id [32]byte) [32]byte {
	lastIndex := len(cfs) - 1
	result := cfs[lastIndex]

	for i := lastIndex - 1; i >= 0; i-- {
		ed.ScMul(&result, &result, &id)
		ed.ScAdd(&result, &result, &cfs[i])
	}

	return result
}
