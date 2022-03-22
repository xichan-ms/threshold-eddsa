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

	ids := IDsGenerate()

	// 1. Key Generation

	// 1.1 output: [N]OutputKGRndOne
	outputKGRndOne := KGRndOne(ids)

	// [N]InputKGRndTwo
	inputKGRndTwo := GetInputKGRndTwo(outputKGRndOne)

	// 1.2 output [N]OutputKGRndTwo
	outputKGRndTwo := KGRndTwo(inputKGRndTwo)

	// [N]InputKGRndThree
	inputKGRndThree := GetInputKGRndThree(outputKGRndOne, outputKGRndTwo, ids)

	// 1.3 output: [N]OutputKGRndThree
	outputKGRndThree := KGRndThree(inputKGRndThree, ids)

	// 2. Sign
	message := []byte("hello thresholdeddsa")

	// 2.1 output: [T]OutputSignRndOne
	outputSignRndOne := SignRndOne()

	// [T]InputSignRndTwo
	inputSignRndTwo := GetInputSignRndTwo(outputSignRndOne)

	// 2.2 output: [T]OutputSignRndTwo
	outputSignRndTwo := SignRndTwo(inputSignRndTwo)

	// [T]InputSignRndThree
	inputSignRndThree := GetInputSignRndThree(message, outputKGRndThree, outputSignRndOne, outputSignRndTwo)

	// 2.3 output: [T]OutputSignRndThree
	outputSignRndThree := SignRndThree(inputSignRndThree, ids)

	// [T]InputSignRndFour
	inputSignRndFour := GetInputSignRndFour(message, outputKGRndThree, outputSignRndTwo, outputSignRndThree)

	// 2.4 output: [T]OutputSignRndFour
	// outputSignRndFour := SignRndFour(inputSignRndFour)
	SignRndFour(inputSignRndFour)

}

// ### specific protocol process and datastruct #########################################################################################################################################################

type OutputKGRndOne struct {
	Sk   [32]byte
	Pk   [32]byte
	CcfsB  [32]byte // broadcast
	DcfsB  [][32]byte
	Shares [][32]byte
}

type InputKGRndTwo struct {
	Sk [32]byte
	DcfsB  [][32]byte
	Shares [][32]byte
}

type OutputKGRndTwo struct {
	ZkPk [64]byte // broadcast
	DcfsB  [][32]byte // broadcast
	Shares [][32]byte // send privately
}

type InputKGRndThree struct {
	// receive from broadcast
	CcfsBs  [][32]byte
	DcfsBs  [][][32]byte
	ZkPks [][64]byte

	// receive from send
	Shares [][32]byte
}

type OutputKGRndThree struct {
	// threshold Final Sk
	Ssk     [32]byte
	FinalPk [32]byte
}

type OutputSignRndOne struct {
	Rs	[32]byte
	CR  [32]byte
	DR	[][32]byte
}

type InputSignRndTwo struct {
	Rs     [32]byte
	DR	[][32]byte
}

type OutputSignRndTwo struct {
	ZkR [64]byte
}

type InputSignRndThree struct {
	// receive from broadcast
	CRs [][32]byte
	DRs [][][32]byte
	ZkRs [][64]byte

	FinalPk [32]byte
	Message []byte
	Ssk [32]byte
	Rs [32]byte
}

type OutputSignRndThree struct {
	Ss [32]byte
	FinalR [32]byte
}

type InputSignRndFour struct {
	// receive from broadcast
	Sss [][32]byte
	FinalR [32]byte
	Message []byte
	FinalPk [32]byte
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
	var inputKGRndTwo InputKGRndTwo
	var inputKGRndTwos []InputKGRndTwo

	for _, output := range outputKGRndOne {
		inputKGRndTwo = InputKGRndTwo{DcfsB: output.DcfsB, Sk: output.Sk, Shares: output.Shares}
		inputKGRndTwos = append(inputKGRndTwos, inputKGRndTwo)
	}

	return inputKGRndTwos
}

func GetInputKGRndThree(outputKGRndOne []OutputKGRndOne, outputKGRndTwo []OutputKGRndTwo, ids [][32]byte) []InputKGRndThree {
	var CcfsBs [][32]byte
	var DcfsBs [][][32]byte
	var ZkPks [][64]byte

	for _, output := range outputKGRndOne {
		CcfsBs = append(CcfsBs, output.CcfsB)
	}
	
	for _, output := range outputKGRndTwo {
		DcfsBs = append(DcfsBs, output.DcfsB)
		ZkPks = append(ZkPks, output.ZkPk)
	}

	var inputKGRndThree InputKGRndThree
	var inputKGRndThrees []InputKGRndThree

	for i := 0; i < len(outputKGRndTwo); i++ {
		var shares [][32]byte

		for _, out := range outputKGRndTwo {
			shares = append(shares, out.Shares[i])
		}

		inputKGRndThree = InputKGRndThree{CcfsBs: CcfsBs, DcfsBs: DcfsBs, ZkPks: ZkPks, Shares: shares}
		inputKGRndThrees = append(inputKGRndThrees, inputKGRndThree)
	}

	return inputKGRndThrees
}

func GetInputSignRndTwo(outputSignRndOne []OutputSignRndOne) []InputSignRndTwo {
	
	var inputSignRndTwo InputSignRndTwo
	var inputSignRndTwos []InputSignRndTwo

	for i := 0; i < T; i++ {
		inputSignRndTwo = InputSignRndTwo{Rs: outputSignRndOne[i].Rs, DR: outputSignRndOne[i].DR}
		inputSignRndTwos = append(inputSignRndTwos, inputSignRndTwo)
	}
	return inputSignRndTwos
}

func GetInputSignRndThree(message []byte, outputKGRndThree []OutputKGRndThree, outputSignRndOne []OutputSignRndOne, utputSignRndTwo []OutputSignRndTwo) []InputSignRndThree {
	var CRs [][32]byte
	var DRs [][][32]byte
	var ZkRs [][64]byte

	for i := 0; i < T; i++ {
		CRs = append(CRs, outputSignRndOne[i].CR)
		DRs = append(DRs, outputSignRndOne[i].DR)
		ZkRs = append(ZkRs, utputSignRndTwo[i].ZkR)
	}

	var inputSignRndThree InputSignRndThree
	var inputSignRndThrees []InputSignRndThree

	for i := 0; i < T; i++ {
		inputSignRndThree = InputSignRndThree{CRs: CRs, DRs: DRs, ZkRs: ZkRs, FinalPk: outputKGRndThree[i].FinalPk, Message: message, Ssk: outputKGRndThree[i].Ssk, Rs: outputSignRndOne[i].Rs}
		inputSignRndThrees = append(inputSignRndThrees, inputSignRndThree)
	}
	return inputSignRndThrees
}

func GetInputSignRndFour(message []byte, outputKGRndThree []OutputKGRndThree, outputSignRndTwo []OutputSignRndTwo, outputSignRndThree []OutputSignRndThree) []InputSignRndFour {
	var Sss [][32]byte

	for i := 0; i < T; i++ {
		Sss = append(Sss, outputSignRndThree[i].Ss)
	}

	var inputSignRndFour InputSignRndFour
	var inputSignRndFours []InputSignRndFour

	for i := 0; i < T; i++ {
		inputSignRndFour = InputSignRndFour{Sss: Sss, FinalR: outputSignRndThree[i].FinalR, Message: message, FinalPk: outputKGRndThree[i].FinalPk}
		inputSignRndFours = append(inputSignRndFours, inputSignRndFour)
	}
	return inputSignRndFours
}

func IDsGenerate() [][32]byte{

	var IDs [][32]byte
	rand := cryptorand.Reader

	for loopi := 0; loopi < N; loopi++ {
		var id [32]byte
		var idTem [64]byte

		if _, err := io.ReadFull(rand, id[:]); err != nil {
			fmt.Println("Error: io.ReadFull(rand, id)")
		}

		copy(idTem[:], id[:])
		ed.ScReduce(&id, &idTem)

		IDs = append(IDs, id)
	}

	return IDs
}

// @input: none
// @output: [N]OutputKGRndOne
func KGRndOne(ids [][32]byte) []OutputKGRndOne {

	var output []OutputKGRndOne
	var outputKGRndOne OutputKGRndOne

	for loopi := 0; loopi < N; loopi++ {

		// 1.1-1.2 generate 32-bits privatekey', then do bit calculation to privatekey
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

		// 1.3.2 calculate vss and commitment
		_, cfsBBytes, shares := vss.Vss(sk, ids, T, N)

		CcfsB, DcfsB := commit.Commit(cfsBBytes)

		outputKGRndOne = OutputKGRndOne{Sk: sk, Pk: pk, CcfsB: CcfsB, DcfsB: DcfsB, Shares: shares}
		output = append(output, outputKGRndOne)

		// [broadcast CcfsB]
	}

	return output
}

// @input: [N]InputKGRndTwo
// @output: [N]OutputKGRndTwo

func KGRndTwo(input []InputKGRndTwo) []OutputKGRndTwo {

	var output []OutputKGRndTwo
	var outputKGRndTwo OutputKGRndTwo

	for loopi := 0; loopi < N; loopi++ {
		// 2.1 [broadcast DcfsB]

		// 2.2 calculate zk and [broadcast zkPk]
		zkPk := zks.Prove(input[loopi].Sk)

		// 2.3 [send shares] to corresponding person

		outputKGRndTwo = OutputKGRndTwo{ZkPk: zkPk, DcfsB: input[loopi].DcfsB, Shares: input[loopi].Shares}
		output = append(output, outputKGRndTwo)
	}

	return output
}

// @input: [N]InputKGRndThree
// @output: [N]OutputKGRndThree

func KGRndThree(input []InputKGRndThree, ids [][32]byte) []OutputKGRndThree {

	var output []OutputKGRndThree
	var outputKGRndThree OutputKGRndThree

	for loopi := 0; loopi < N; loopi++ {

		// verify all others' commitment
		for loopn := 0; loopn < len(input[loopi].CcfsBs); loopn++ {
			CcfsBFlag := commit.Verify(input[loopi].CcfsBs[loopn], input[loopi].DcfsBs[loopn])
			if !CcfsBFlag {
				fmt.Println("Error: Commitment(cfsB) Not Pass at User: %d", loopn)
			}
		}

		// verify all others' zkSchnorr
		for loopn := 0; loopn < len(input[loopi].ZkPks); loopn++ {
			temPk := input[loopi].DcfsBs[loopn][1]

			zkPkFlag := zks.Verify(input[loopi].ZkPks[loopn], temPk)
			if !zkPkFlag {
				fmt.Println("Error: ZeroKnowledge Proof (Pk) Not Pass at User: %d", loopn)
			}
		}

		// 3.1 verify share
		for loopn := 0; loopn < len(input[loopi].Shares); loopn++ {
			shareUFlag := vss.Verify(input[loopi].Shares[loopn], ids[loopi], input[loopi].DcfsBs[loopn][1:])

			if !shareUFlag {
				fmt.Println("Error: VSS Share Verification Not Pass at User: %d", loopn)
			}
		}

		// 3.3 calculate sk share
		var ssk [32]byte
		for loopn := 0; loopn < len(input[loopi].Shares); loopn++ {
			ed.ScAdd(&ssk, &ssk, &input[loopi].Shares[loopn])
		}

		// 3.4 calculate pk
		var finalPk ed.ExtendedGroupElement
		var finalPkBytes [32]byte

		for loopn := 0; loopn < len(input[loopi].DcfsBs); loopn++ {
			temPk := input[loopi].DcfsBs[loopn][1]

			var PK ed.ExtendedGroupElement
			PK.FromBytes(&temPk)

			if loopn == 0 {
				finalPk = PK
			} else {
				ed.GeAdd(&finalPk, &finalPk, &PK)
			}
		}

		finalPk.ToBytes(&finalPkBytes)

		outputKGRndThree = OutputKGRndThree{Ssk: ssk, FinalPk: finalPkBytes}
		output = append(output, outputKGRndThree)
	}

	return output
}

// @input: [N]InputSignRndOne
// @output: [N]OutputSignRndOne

func SignRndOne() []OutputSignRndOne {

	var output []OutputSignRndOne
	var outputSignRndOne OutputSignRndOne

	for loopi := 0; loopi < T; loopi++ {

		// 1. select r share (Rs)
		var r [32]byte
		var rTem [64]byte
		var RBytes [32]byte
		var commitValues [][32]byte

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
		commitValues = append(commitValues, RBytes)
		CR, DR := commit.Commit(commitValues)

		outputSignRndOne = OutputSignRndOne{CR: CR, DR: DR, Rs: r}
		output = append(output, outputSignRndOne)

		// [broadcast] CR
	}

	return output
}

// @input: [N]InputSignRndTwo
// @output: [N]OutputSignRndTwo

func SignRndTwo(input []InputSignRndTwo) []OutputSignRndTwo {

	var output []OutputSignRndTwo
	var outputSignRndTwo OutputSignRndTwo

	for loopi := 0; loopi < T; loopi++ {

		// 2.1 [broadcast] DR

		// 2.2 zkSchnorr(rU1)
		zkR := zks.Prove(input[loopi].Rs)
		
		// [broadcast] zkR

		// 2.3
		outputSignRndTwo = OutputSignRndTwo{ZkR: zkR}
		output = append(output, outputSignRndTwo)
	}

	return output
}

// @input: [N]InputSignRndThree
// @output: [N]OutputSignRndThree

func SignRndThree(input []InputSignRndThree, ids [][32]byte) []OutputSignRndThree {

	var output []OutputSignRndThree
	var outputSignRndThree OutputSignRndThree

	for loopi := 0; loopi < T; loopi++ {

		// verify all others'commit
		for loopn := 0; loopn < len(input[loopi].CRs); loopn++ {
			CRFlag := commit.Verify(input[loopi].CRs[loopn], input[loopi].DRs[loopn])
			if !CRFlag {
				fmt.Println("Error: Commitment(R) Not Pass at User: %d", loopn)
			}
		}

		// verify all others'zk
		for loopn := 0; loopn < len(input[loopi].ZkRs); loopn++ {
			temR := input[loopi].DRs[loopn][1]

			zkRFlag := zks.Verify(input[loopi].ZkRs[loopn], temR)
			if !zkRFlag {
				fmt.Println("Error: ZeroKnowledge Proof (R) Not Pass at User: %d", loopn)
			}
		}

		// calculate R
		var FinalR, temR ed.ExtendedGroupElement
		var FinalRBytes [32]byte
		for loopn := 0; loopn < len(input[loopi].DRs); loopn++ {
			temRBytes := input[loopi].DRs[loopn][1]
			temR.FromBytes(&temRBytes)
			if loopn == 0 {
				FinalR = temR
			} else {
				ed.GeAdd(&FinalR, &FinalR, &temR)
			}
		}
		FinalR.ToBytes(&FinalRBytes)

		// calculate k = H(finalR || finalPk || message)
		var k [32]byte
		var kDigest [64]byte

		h := sha512.New()
		h.Write(FinalRBytes[:])
		h.Write(input[loopi].FinalPk[:])
		h.Write(input[loopi].Message[:])
		h.Sum(kDigest[:0])

		ed.ScReduce(&k, &kDigest)

		// calculate lambda1
		var lambda [32]byte
		lambda[0] = 1
		order := ed.GetBytesOrder()

		for loopn := 0; loopn < T; loopn++ {
			if loopn != loopi {
				var time [32]byte
				ed.ScSub(&time, &ids[loopn], &ids[loopi])
				time = ed.ScModInverse(time, order)
				ed.ScMul(&time, &time, &ids[loopn])

				ed.ScMul(&lambda, &lambda, &time)
			}
		}

		// calculate s share (ss) = Rs + k * lambda1 * Ssk
		var Ss [32]byte
		ed.ScMul(&Ss, &lambda, &input[loopi].Ssk)
		ed.ScMul(&Ss, &Ss, &k)
		ed.ScAdd(&Ss, &Ss, &input[loopi].Rs)

		// [broadcast] Ss

		outputSignRndThree = OutputSignRndThree{Ss: Ss, FinalR: FinalRBytes}
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
		for loopn := 0; loopn < len(input[loopi].Sss); loopn++ {
			ed.ScAdd(&FinalS, &FinalS, &input[loopi].Sss[loopn])
		}

		outputSignRndFour = OutputSignRndFour{FinalR: input[loopi].FinalR, FinalS: FinalS}

		sigFlag := Verify(outputSignRndFour, input[loopi].Message, input[loopi].FinalPk)
		if !sigFlag {
			fmt.Println("Error: signature (finalR, finalS) Not Pass at User: %d", loopi)
		}

		output = append(output, outputSignRndFour)
	}

	fmt.Println("all valid.")
	return output
}

// @input: InputVerify
// @output: bool

func Verify(outputSignRndFour OutputSignRndFour, message []byte, finalPk [32]byte) bool {
	// 1. calculate k
	var k [32]byte
	var kDigest [64]byte

	h := sha512.New()
	h.Write(outputSignRndFour.FinalR[:])
	h.Write(finalPk[:])
	h.Write(message[:])
	h.Sum(kDigest[:0])

	ed.ScReduce(&k, &kDigest)

	// 2. verify the equation
	var R, pkB, sB, sBCal ed.ExtendedGroupElement
	pkB.FromBytes(&finalPk)
	R.FromBytes(&(outputSignRndFour.FinalR))

	ed.GeScalarMult(&sBCal, &k, &pkB)
	ed.GeAdd(&sBCal, &R, &sBCal)

	ed.GeScalarMultBase(&sB, &(outputSignRndFour.FinalS))

	var sBBytes, sBCalBytes [32]byte
	sB.ToBytes(&sBBytes)
	sBCal.ToBytes(&sBCalBytes)

	pass := bytes.Equal(sBBytes[:], sBCalBytes[:])

	return pass
}
