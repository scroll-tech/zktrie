package zktrie

import (
	"fmt"
	"math/big"
	"testing"
)

func setupENV() {
	InitHashScheme(func(arr []*big.Int) (*big.Int, error) {
		lcEff := big.NewInt(65536)
		qString := "21888242871839275222246405745257275088548364400416034343698204186575808495617"
		Q, ok := new(big.Int).SetString(qString, 10)
		if !ok {
			panic(fmt.Sprintf("Bad base 10 string %s", qString))
		}
		sum := big.NewInt(0)
		for _, bi := range arr {
			nbi := new(big.Int).Mul(bi, bi)
			sum = sum.Mul(sum, sum)
			sum = sum.Mul(sum, lcEff)
			sum = sum.Add(sum, nbi)
		}
		return sum.Mod(sum, Q), nil
	})
}

func TestZkTrieTypes(t *testing.T) {
	setupENV()

	t.Run("TestNewByte32", testNewByte32)
	t.Run("TestDummyHash", testDummyHash)
	t.Run("TestCheckBigIntInField", testCheckBigIntInField)
	t.Run("TestNewHashAndBigIntFromBytes", testNewHashAndBigIntFromBytes)
	t.Run("TestNewHashFromBigIntAndString", testNewHashFromBigIntAndString)
	t.Run("TestSetBitBigEndian", testSetBitBigEndian)
	t.Run("TestBitManipulations", testBitManipulations)
	t.Run("TestBigEndianBitsToBigInt", testBigEndianBitsToBigInt)
	t.Run("TestToSecureKey", testToSecureKey)
	t.Run("TestToSecureKeyBytes", testToSecureKeyBytes)
	t.Run("TestReverseByteOrder", testReverseByteOrder)
	t.Run("TestHashElems", testHashElems)
	t.Run("TestPreHandlingElems", testPreHandlingElems)
}
