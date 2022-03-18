package main

import (
	"bytes"
	cryptorand "crypto/rand"
	"crypto/sha512"
	"fmt"
	"github.com/jnxchang/go-thresholdeddsa/commit"
	ed "github.com/jnxchang/go-thresholdeddsa/edwards25519"
	zks "github.com/jnxchang/go-thresholdeddsa/schnorrZK"
	"github.com/jnxchang/go-thresholdeddsa/vss"
	"io"
)

// Threshold
var T = 5

// number of all involved users
var N = 10

func main() {

	// 1. Key Generation

	// 1.1 output: [N]OutputKGRndOne
	outputKGRndOne := KGRndOne()

	// [N]InputKGRndTwo
	inputKGRndTwo := GetInputKGRndTwo(outputKGRndOne)

	// 1.2 output [N]OutputKGRndTwo
	outputKGRndTwo := KGRndTwo(inputKGRndTwo)

	// [N]InputKGRndThree
	inputKGRndThree := GetInputKGRndThree(outputKGRndOne, outputKGRndTwo)

	// 1.3 output: [N]OutputKGRndThree
	outputKGRndThree := KGRndThree(inputKGRndThree)

	// 2. Sign
	message := []byte("hello thresholdeddsa")

	// [T]InputSignRndOne
	inputSignRndOne := GetInputSignRndOne(message, outputKGRndOne)

	// 2.1 output: [T]OutputSignRndOne
	outputSignRndOne := SignRndOne(inputSignRndOne)

	// [T]InputSignRndTwo
	inputSignRndTwo := GetInputSignRndTwo(message, outputKGRndOne, outputKGRndThree, outputSignRndOne)

	// 2.2 output: [T]OutputSignRndTwo
	outputSignRndTwo := SignRndTwo(inputSignRndTwo)

	// [T]InputSignRndThree
	inputSignRndThree := GetInputSignRndThree(message, outputKGRndThree, outputSignRndTwo)

	// 2.3 output: [T]OutputSignRndThree
	outputSignRndThree := SignRndThree(inputSignRndThree)

	// [T]InputSignRndFour
	inputSignRndFour := GetInputSignRndFour(outputSignRndTwo, outputSignRndThree)

	// 2.4 output: [T]OutputSignRndFour
	outputSignRndFour := SignRndFour(inputSignRndFour)

	// 3. Verification

	// [T]InputVerify
	inputVerifys := GetInputVerify(message, outputKGRndThree, outputSignRndFour)

	for _, input := range inputVerifys {
		var pass = Verify(input)
		fmt.Println(pass)
	}
}

// ### specific protocol process and datastruct #########################################################################################################################################################

type OutputKGRndOne struct {
	Sk   [32]byte
	Pk   [32]byte
	CPk  [32]byte
	DPk  [64]byte
	ZkPk [64]byte
	Id   [32]byte
}

type InputKGRndTwo struct {
	// receive from broadcast
	CPk  [][32]byte
	DPk  [][64]byte
	Id   [][32]byte
	ZkPk [][64]byte

	Sk [32]byte
}

type OutputKGRndTwo struct {
	Shares        [][32]byte
	CoefficientsB [][32]byte
}

type InputKGRndThree struct {
	// receive from broadcast
	DPk           [][64]byte
	Id            [][32]byte
	CoefficientsB [][][32]byte

	// receive from send
	Shares [][32]byte
}

type OutputKGRndThree struct {
	// threshold Final Sk
	TSk     [32]byte
	FinalPk [32]byte
}

type InputSignRndOne struct {
	Message []byte
	Sk      [32]byte
}

type OutputSignRndOne struct {
	CR  [32]byte
	DR  [64]byte
	ZkR [64]byte
	Rr  [32]byte
}

type InputSignRndTwo struct {
	// receive from broadcast
	CR  [][32]byte
	DR  [][64]byte
	Id  [][32]byte
	ZkR [][64]byte

	TSk     [32]byte
	Rr      [32]byte
	Message []byte
	FinalPk [32]byte
}

type OutputSignRndTwo struct {
	FinalR [32]byte
	S      [32]byte
	CSB    [32]byte
	DSB    [64]byte
}

type InputSignRndThree struct {
	// receive from broadcast
	CSB [][32]byte
	DSB [][64]byte

	Message []byte
	FinalPk [32]byte
	FinalR  [32]byte
	S       [32]byte
}

type OutputSignRndThree struct {
	S [32]byte
}

type InputSignRndFour struct {
	// receive from broadcast
	S [][32]byte

	FinalR [32]byte
}

type OutputSignRndFour struct {
	FinalR [32]byte
	FinalS [32]byte
}

type InputVerify struct {
	FinalR  [32]byte
	FinalS  [32]byte
	Message []byte
	FinalPk [32]byte
}

func GetInputKGRndTwo(outputKGRndOne []OutputKGRndOne) []InputKGRndTwo {
	var CPk [][32]byte
	var DPk [][64]byte
	var Id [][32]byte
	var ZkPk [][64]byte

	for _, output := range outputKGRndOne {
		CPk = append(CPk, output.CPk)
		DPk = append(DPk, output.DPk)
		Id = append(Id, output.Id)
		ZkPk = append(ZkPk, output.ZkPk)
	}

	var inputKGRndTwo InputKGRndTwo
	var inputKGRndTwos []InputKGRndTwo

	for _, output := range outputKGRndOne {
		inputKGRndTwo = InputKGRndTwo{CPk: CPk, DPk: DPk, Id: Id, ZkPk: ZkPk, Sk: output.Sk}
		inputKGRndTwos = append(inputKGRndTwos, inputKGRndTwo)
	}

	return inputKGRndTwos
}

func GetInputKGRndThree(outputKGRndOne []OutputKGRndOne, outputKGRndTwo []OutputKGRndTwo) []InputKGRndThree {
	var DPk [][64]byte
	var Id [][32]byte
	var CoefficientsB [][][32]byte

	for _, output := range outputKGRndOne {
		DPk = append(DPk, output.DPk)
		Id = append(Id, output.Id)
	}

	for _, output := range outputKGRndTwo {
		CoefficientsB = append(CoefficientsB, output.CoefficientsB)
	}

	var inputKGRndThree InputKGRndThree
	var inputKGRndThrees []InputKGRndThree

	for i := 0; i < len(outputKGRndTwo); i++ {
		var shares [][32]byte

		for _, out := range outputKGRndTwo {
			shares = append(shares, out.Shares[i])
		}

		inputKGRndThree = InputKGRndThree{DPk: DPk, Id: Id, CoefficientsB: CoefficientsB, Shares: shares}
		inputKGRndThrees = append(inputKGRndThrees, inputKGRndThree)
	}

	return inputKGRndThrees
}

func GetInputSignRndOne(message []byte, outputKGRndOne []OutputKGRndOne) []InputSignRndOne {
	var inputSignRndOne InputSignRndOne
	var inputSignRndOnes []InputSignRndOne

	for i := 0; i < T; i++ {
		inputSignRndOne = InputSignRndOne{Message: message, Sk: outputKGRndOne[i].Sk}
		inputSignRndOnes = append(inputSignRndOnes, inputSignRndOne)
	}
	return inputSignRndOnes
}

func GetInputSignRndTwo(message []byte, outputKGRndOne []OutputKGRndOne, outputKGRndThree []OutputKGRndThree, outputSignRndOne []OutputSignRndOne) []InputSignRndTwo {
	var CR [][32]byte
	var DR [][64]byte
	var Id [][32]byte
	var ZkR [][64]byte

	for i := 0; i < T; i++ {
		CR = append(CR, outputSignRndOne[i].CR)
		DR = append(DR, outputSignRndOne[i].DR)
		ZkR = append(ZkR, outputSignRndOne[i].ZkR)
	}

	for i := 0; i < T; i++ {
		Id = append(Id, outputKGRndOne[i].Id)
	}

	var inputSignRndTwo InputSignRndTwo
	var inputSignRndTwos []InputSignRndTwo

	for i := 0; i < T; i++ {
		inputSignRndTwo = InputSignRndTwo{CR: CR, DR: DR, Id: Id, ZkR: ZkR, TSk: outputKGRndThree[i].TSk, Rr: outputSignRndOne[i].Rr, Message: message, FinalPk: outputKGRndThree[i].FinalPk}
		inputSignRndTwos = append(inputSignRndTwos, inputSignRndTwo)
	}
	return inputSignRndTwos
}

func GetInputSignRndThree(message []byte, outputKGRndThree []OutputKGRndThree, outputSignRndTwo []OutputSignRndTwo) []InputSignRndThree {
	var CSB [][32]byte
	var DSB [][64]byte

	for i := 0; i < T; i++ {
		CSB = append(CSB, outputSignRndTwo[i].CSB)
		DSB = append(DSB, outputSignRndTwo[i].DSB)
	}

	var inputSignRndThree InputSignRndThree
	var inputSignRndThrees []InputSignRndThree

	for i := 0; i < T; i++ {
		inputSignRndThree = InputSignRndThree{CSB: CSB, DSB: DSB, Message: message, FinalPk: outputKGRndThree[i].FinalPk, FinalR: outputSignRndTwo[i].FinalR, S: outputSignRndTwo[i].S}
		inputSignRndThrees = append(inputSignRndThrees, inputSignRndThree)
	}
	return inputSignRndThrees
}

func GetInputSignRndFour(outputSignRndTwo []OutputSignRndTwo, outputSignRndThree []OutputSignRndThree) []InputSignRndFour {
	var S [][32]byte

	for i := 0; i < T; i++ {
		S = append(S, outputSignRndThree[i].S)
	}

	var inputSignRndFour InputSignRndFour
	var inputSignRndFours []InputSignRndFour

	for i := 0; i < T; i++ {
		inputSignRndFour = InputSignRndFour{S: S, FinalR: outputSignRndTwo[i].FinalR}
		inputSignRndFours = append(inputSignRndFours, inputSignRndFour)
	}
	return inputSignRndFours
}

func GetInputVerify(message []byte, outputKGRndThree []OutputKGRndThree, outputSignRndFour []OutputSignRndFour) []InputVerify {
	var inputVerify InputVerify
	var inputVerifys []InputVerify

	for i := 0; i < T; i++ {
		inputVerify = InputVerify{FinalR: outputSignRndFour[i].FinalR, FinalS: outputSignRndFour[i].FinalS, Message: message, FinalPk: outputKGRndThree[i].FinalPk}
		inputVerifys = append(inputVerifys, inputVerify)
	}
	return inputVerifys
}

// @input: none
// @output: [N]OutputKGRndOne
func KGRndOne() []OutputKGRndOne {

	var output []OutputKGRndOne
	var outputKGRndOne OutputKGRndOne

	for loopi := 0; loopi < N; loopi++ {

		// 1.1-1.2 generate 32-bits privatekey', then bit calculation to privatekey
		rand := cryptorand.Reader

		var sk [32]byte
		var pk [32]byte
		var skTem [64]byte

		if _, err := io.ReadFull(rand, sk[:]); err != nil {
			fmt.Println("Error: io.ReadFull(rand, sk)")
		}

		sk[0] &= 248
		sk[31] &= 127
		sk[31] |= 64

		copy(skTem[:], sk[:])
		ed.ScReduce(&sk, &skTem)

		// 1.3 publicKey

		var A ed.ExtendedGroupElement
		ed.GeScalarMultBase(&A, &sk)

		A.ToBytes(&pk)

		CPk, DPk := commit.Commit(pk)

		zkPk := zks.Prove(sk)

		// 1.4
		var id [32]byte
		if _, err := io.ReadFull(rand, id[:]); err != nil {
			fmt.Println("Error: io.ReadFull(rand, seed)")
		}
		var zero [32]byte
		var one [32]byte
		one[0] = 1
		ed.ScMulAdd(&id, &id, &one, &zero)

		outputKGRndOne = OutputKGRndOne{Sk: sk, Pk: pk, CPk: CPk, DPk: DPk, ZkPk: zkPk, Id: id}
		output = append(output, outputKGRndOne)
	}

	return output
}

// @input: [N]InputKGRndTwo
// @output: [N]OutputKGRndTwo

func KGRndTwo(input []InputKGRndTwo) []OutputKGRndTwo {

	var output []OutputKGRndTwo
	var outputKGRndTwo OutputKGRndTwo

	for loopi := 0; loopi < N; loopi++ {
		// 2.1 broadcast DSk

		// 2.2 receive all others' DSk

		// 2.3 verify all others' commitment
		for loopn := 0; loopn < len(input[loopi].CPk); loopn++ {
			CPkFlag := commit.Verify(input[loopi].CPk[loopn], input[loopi].DPk[loopn])
			if !CPkFlag {
				fmt.Println("Error: Commitment(PK) Not Pass at User: %d", loopn)
			}
		}

		// 2.4 verify all others' zkSchnorr
		for loopn := 0; loopn < len(input[loopi].ZkPk); loopn++ {
			var temPk [32]byte
			copy(temPk[:], (input[loopi].DPk[loopn])[32:])

			zkPkFlag := zks.Verify(input[loopi].ZkPk[loopn], temPk)
			if !zkPkFlag {
				fmt.Println("Error: ZeroKnowledge Proof (Pk) Not Pass at User: %d", loopn)
			}
		}

		// 2.5 calculate a = SHA256(PkU1, {PkU2, PkU3})
		var a [32]byte
		var aDigest [64]byte

		var PkSet []byte
		for loopn := 0; loopn < len(input[loopi].DPk); loopn++ {
			var temPk [32]byte
			copy(temPk[:], (input[loopi].DPk[loopn])[32:])

			PkSet = append(PkSet[:], (temPk[:])...)
		}

		h := sha512.New()
		h.Write((input[loopi].DPk[loopi])[32:])
		h.Write(PkSet)
		h.Sum(aDigest[:0])
		ed.ScReduce(&a, &aDigest)

		// 2.6 calculate ask
		var ask [32]byte
		var temSk [32]byte
		copy(temSk[:], input[loopi].Sk[:32])
		ed.ScMul(&ask, &a, &temSk)

		// 2.7 calculate vss
		_, cfsBBytes, shares := vss.Vss(ask, input[loopi].Id, T, N)

		// 2.8
		outputKGRndTwo = OutputKGRndTwo{Shares: shares, CoefficientsB: cfsBBytes}
		output = append(output, outputKGRndTwo)
	}

	return output
}

// @input: [N]InputKGRndThree
// @output: [N]OutputKGRndThree

func KGRndThree(input []InputKGRndThree) []OutputKGRndThree {

	var output []OutputKGRndThree
	var outputKGRndThree OutputKGRndThree

	for loopi := 0; loopi < N; loopi++ {

		// 3.1 verify share
		for loopn := 0; loopn < len(input[loopi].Shares); loopn++ {
			shareUFlag := vss.Verify(input[loopi].Shares[loopn], input[loopi].Id[loopi], input[loopi].CoefficientsB[loopn])

			if !shareUFlag {
				fmt.Println("Error: VSS Share Verification Not Pass at User: %d", loopn)
			}
		}

		// 3.2 verify share2
		var a [32]byte
		var aDigest [64]byte

		var PkSet []byte
		for loopn := 0; loopn < len(input[loopi].DPk); loopn++ {
			var temPk [32]byte
			copy(temPk[:], (input[loopi].DPk[loopn])[32:])

			PkSet = append(PkSet[:], (temPk[:])...)
		}

		h := sha512.New()
		for loopn := 0; loopn < len(input[loopi].DPk); loopn++ {
			var temPk [32]byte
			copy(temPk[:], (input[loopi].DPk[loopn])[32:])

			h.Reset()
			h.Write(temPk[:])
			h.Write(PkSet)
			h.Sum(aDigest[:0])
			ed.ScReduce(&a, &aDigest)

			var askB, A ed.ExtendedGroupElement
			A.FromBytes(&temPk)
			ed.GeScalarMult(&askB, &a, &A)

			var askBBytes [32]byte
			askB.ToBytes(&askBBytes)

			if !bytes.Equal(askBBytes[:], (input[loopi].CoefficientsB[loopn][0])[:]) {
				fmt.Println("Error: VSS Coefficient Verification Not Pass at User: %d", loopn)
			}
		}

		// 3.3 calculate tSk
		var tSk [32]byte
		for loopn := 0; loopn < len(input[loopi].Shares); loopn++ {
			ed.ScAdd(&tSk, &tSk, &input[loopi].Shares[loopn])
		}

		// 3.4 calculate pk
		var finalPk ed.ExtendedGroupElement
		var finalPkBytes [32]byte

		for loopn := 0; loopn < len(input[loopi].DPk); loopn++ {
			var temPk [32]byte
			copy(temPk[:], (input[loopi].DPk[loopn])[32:])

			h.Reset()
			h.Write(temPk[:])
			h.Write(PkSet)
			h.Sum(aDigest[:0])
			ed.ScReduce(&a, &aDigest)

			var askB, A ed.ExtendedGroupElement
			A.FromBytes(&temPk)
			ed.GeScalarMult(&askB, &a, &A)

			if loopn == 0 {
				finalPk = askB
			} else {
				ed.GeAdd(&finalPk, &finalPk, &askB)
			}
		}

		finalPk.ToBytes(&finalPkBytes)

		outputKGRndThree = OutputKGRndThree{TSk: tSk, FinalPk: finalPkBytes}
		output = append(output, outputKGRndThree)
	}

	return output
}

// @input: [N]InputSignRndOne
// @output: [N]OutputSignRndOne

func SignRndOne(input []InputSignRndOne) []OutputSignRndOne {

	var output []OutputSignRndOne
	var outputSignRndOne OutputSignRndOne

	for loopi := 0; loopi < T; loopi++ {

		// 1. calculate R
		var r [32]byte
		var rTem [64]byte
		var RBytes [32]byte

		rand := cryptorand.Reader
		if _, err := io.ReadFull(rand, r[:]); err != nil {
			fmt.Println("Error: io.ReadFull(rand, r)")
		}
		copy(rTem[:], r[:])
		ed.ScReduce(&r, &rTem)

		var R ed.ExtendedGroupElement
		ed.GeScalarMultBase(&R, &r)

		// 2. commit(R)
		R.ToBytes(&RBytes)
		CR, DR := commit.Commit(RBytes)

		// 3. zkSchnorr(rU1)
		zkR := zks.Prove(r)

		outputSignRndOne = OutputSignRndOne{CR: CR, DR: DR, ZkR: zkR, Rr: r}
		output = append(output, outputSignRndOne)
	}

	return output
}

// @input: [N]InputSignRndTwo
// @output: [N]OutputSignRndTwo

func SignRndTwo(input []InputSignRndTwo) []OutputSignRndTwo {

	var output []OutputSignRndTwo
	var outputSignRndTwo OutputSignRndTwo

	for loopi := 0; loopi < T; loopi++ {

		// 2.1 broadcast DR

		// 2.2 receive others' DR

		// 2.3 verify all others' commitment
		for loopn := 0; loopn < len(input[loopi].CR); loopn++ {
			CRFlag := commit.Verify(input[loopi].CR[loopn], input[loopi].DR[loopn])
			if !CRFlag {
				fmt.Println("Error: Commitment(R) Not Pass at User: %d", loopn)
			}
		}

		// 2.4 verify all others' zkSchnorr
		for loopn := 0; loopn < len(input[loopi].ZkR); loopn++ {
			var temR [32]byte
			copy(temR[:], (input[loopi].DR[loopn])[32:])

			zkRFlag := zks.Verify(input[loopi].ZkR[loopn], temR)
			if !zkRFlag {
				fmt.Println("Error: ZeroKnowledge Proof (R) Not Pass at User: %d", loopn)
			}
		}

		// 2.5 calculate R'
		var FinalR, temR ed.ExtendedGroupElement
		var FinalRBytes [32]byte
		for loopn := 0; loopn < len(input[loopi].DR); loopn++ {
			var temRBytes [32]byte
			copy(temRBytes[:], (input[loopi].DR[loopn])[32:])
			temR.FromBytes(&temRBytes)
			if loopn == 0 {
				FinalR = temR
			} else {
				ed.GeAdd(&FinalR, &FinalR, &temR)
			}
		}
		FinalR.ToBytes(&FinalRBytes)

		// 2.6 calculate k=H(FinalRBytes||pk||M)
		var k [32]byte
		var kDigest [64]byte

		h := sha512.New()
		h.Write(FinalRBytes[:])
		h.Write(input[loopi].FinalPk[:])
		h.Write(input[loopi].Message[:])
		h.Sum(kDigest[:0])

		ed.ScReduce(&k, &kDigest)

		// 2.7 calculate lambda1
		var lambda [32]byte
		lambda[0] = 1
		order := ed.GetBytesOrder()

		for loopn := 0; loopn < len(input[loopi].Id); loopn++ {
			if loopn != loopi {
				var time [32]byte
				ed.ScSub(&time, &input[loopi].Id[loopn], &input[loopi].Id[loopi])
				time = ed.ScModInverse(time, order)
				ed.ScMul(&time, &time, &input[loopi].Id[loopn])

				ed.ScMul(&lambda, &lambda, &time)
			}
		}

		// 2.8 calculate s = r + k*lambda1*tSk
		var s [32]byte

		ed.ScMul(&s, &lambda, &input[loopi].TSk)
		ed.ScMul(&s, &s, &k)
		ed.ScAdd(&s, &s, &input[loopi].Rr)

		// 2.9 calculate sBBytes
		var sBBytes [32]byte
		var sB ed.ExtendedGroupElement
		ed.GeScalarMultBase(&sB, &s)
		sB.ToBytes(&sBBytes)

		// 2.10 commit(sBBytes)
		CSB, DSB := commit.Commit(sBBytes)

		// 2.11
		outputSignRndTwo = OutputSignRndTwo{FinalR: FinalRBytes, S: s, CSB: CSB, DSB: DSB}
		output = append(output, outputSignRndTwo)
	}

	return output
}

// @input: [N]InputSignRndThree
// @output: [N]OutputSignRndThree

func SignRndThree(input []InputSignRndThree) []OutputSignRndThree {

	var output []OutputSignRndThree
	var outputSignRndThree OutputSignRndThree

	for loopi := 0; loopi < T; loopi++ {

		// 3.1 broadcast DSUB

		// 3.2 receive others' DSUB

		// 2.3 verify all others' commitment
		for loopn := 0; loopn < len(input[loopi].CSB); loopn++ {
			CSBFlag := commit.Verify(input[loopi].CSB[loopn], input[loopi].DSB[loopn])
			if !CSBFlag {
				fmt.Println("Error: Commitment(SB) Not Pass at User: %d", loopn)
			}
		}

		// 3.4 calculate sB
		var sB, temSB ed.ExtendedGroupElement
		for loopn := 0; loopn < len(input[loopi].DSB); loopn++ {
			var temSBBytes [32]byte
			copy(temSBBytes[:], (input[loopi].DSB[loopn])[32:])
			temSB.FromBytes(&temSBBytes)

			if loopn == 0 {
				sB = temSB
			} else {
				ed.GeAdd(&sB, &sB, &temSB)
			}
		}

		// 3.5 calculate k
		var k [32]byte
		var kDigest [64]byte

		h := sha512.New()
		h.Write(input[loopi].FinalR[:])
		h.Write(input[loopi].FinalPk[:])
		h.Write(input[loopi].Message[:])
		h.Sum(kDigest[:0])

		ed.ScReduce(&k, &kDigest)

		// 3.6 calculate sBCal
		var FinalR, sBCal, FinalPkB ed.ExtendedGroupElement
		FinalR.FromBytes(&(input[loopi].FinalR))
		FinalPkB.FromBytes(&(input[loopi].FinalPk))
		ed.GeScalarMult(&sBCal, &k, &FinalPkB)
		ed.GeAdd(&sBCal, &sBCal, &FinalR)

		// 3.7 verify equation
		var sBBytes, sBCalBytes [32]byte
		sB.ToBytes(&sBBytes)
		sBCal.ToBytes(&sBCalBytes)

		if !bytes.Equal(sBBytes[:], sBCalBytes[:]) {
			fmt.Println("Error: Not Pass Verification (SB = SBCal) at User: %d", loopi)
		}

		outputSignRndThree = OutputSignRndThree{S: input[loopi].S}
		output = append(output, outputSignRndThree)
	}

	return output
}

// @input: [N]InputSignRndFour
// @output: [N]OutputSignRndFour

func SignRndFour(input []InputSignRndFour) []OutputSignRndFour {

	var output []OutputSignRndFour
	var outputSignRndFour OutputSignRndFour

	for loopi := 0; loopi < T; loopi++ {

		var FinalS [32]byte
		for loopn := 0; loopn < len(input[loopi].S); loopn++ {
			ed.ScAdd(&FinalS, &FinalS, &input[loopi].S[loopn])
		}

		outputSignRndFour = OutputSignRndFour{FinalR: input[loopi].FinalR, FinalS: FinalS}
		output = append(output, outputSignRndFour)
	}

	return output
}

// @input: InputVerify
// @output: bool

func Verify(input InputVerify) bool {
	// 1. calculate k
	var k [32]byte
	var kDigest [64]byte

	h := sha512.New()
	h.Write(input.FinalR[:])
	h.Write(input.FinalPk[:])
	h.Write(input.Message[:])
	h.Sum(kDigest[:0])

	ed.ScReduce(&k, &kDigest)

	// 2. verify the equation
	var R, pkB, sB, sBCal ed.ExtendedGroupElement
	pkB.FromBytes(&(input.FinalPk))
	R.FromBytes(&(input.FinalR))

	ed.GeScalarMult(&sBCal, &k, &pkB)
	ed.GeAdd(&sBCal, &R, &sBCal)

	ed.GeScalarMultBase(&sB, &(input.FinalS))

	var sBBytes, sBCalBytes [32]byte
	sB.ToBytes(&sBBytes)
	sBCal.ToBytes(&sBCalBytes)

	pass := bytes.Equal(sBBytes[:], sBCalBytes[:])

	return pass
}
