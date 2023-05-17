package zktrie

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetBitBigEndian(t *testing.T) {
	bitmap := make([]byte, 8)

	SetBitBigEndian(bitmap, 3)
	SetBitBigEndian(bitmap, 15)
	SetBitBigEndian(bitmap, 27)
	SetBitBigEndian(bitmap, 63)

	expected := []byte{0x80, 0x0, 0x0, 0x0, 0x8, 0x0, 0x80, 0x8}
	assert.Equal(t, expected, bitmap)
}

func TestBitManipulations(t *testing.T) {
	bitmap := []byte{0b10101010, 0b01010101}

	bitResults := make([]bool, 16)
	for i := uint(0); i < 16; i++ {
		bitResults[i] = TestBit(bitmap, i)
	}

	expectedBitResults := []bool{
		false, true, false, true, false, true, false, true,
		true, false, true, false, true, false, true, false,
	}
	assert.Equal(t, expectedBitResults, bitResults)

	bitResultsBigEndian := make([]bool, 16)
	for i := uint(0); i < 16; i++ {
		bitResultsBigEndian[i] = TestBitBigEndian(bitmap, i)
	}

	expectedBitResultsBigEndian := []bool{
		true, false, true, false, true, false, true, false,
		false, true, false, true, false, true, false, true,
	}
	assert.Equal(t, expectedBitResultsBigEndian, bitResultsBigEndian)
}

func TestBigEndianBitsToBigInt(t *testing.T) {
	bits := []bool{true, false, true, false, true, false, true, false}
	result := BigEndianBitsToBigInt(bits)
	expected := big.NewInt(170)
	assert.Equal(t, expected, result)
}

func TestToSecureKey(t *testing.T) {
	secureKey, err := ToSecureKey([]byte("testKey"))
	assert.NoError(t, err)
	assert.Equal(t, big.NewInt(5634124374), secureKey)
}

func TestToSecureKeyBytes(t *testing.T) {
	secureKeyBytes, err := ToSecureKeyBytes([]byte("testKey"))
	assert.NoError(t, err)
	assert.Equal(t, []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x4f, 0xd1, 0xea, 0x56}, secureKeyBytes.Bytes())
}

func TestReverseByteOrder(t *testing.T) {
	assert.Equal(t, []byte{5, 4, 3, 2, 1}, ReverseByteOrder([]byte{1, 2, 3, 4, 5}))
}

func TestHashElems(t *testing.T) {
	fst := big.NewInt(5)
	snd := big.NewInt(3)
	elems := []*big.Int{big.NewInt(2)}

	result, err := HashElems(fst, snd, elems...)
	assert.NoError(t, err)
	assert.Equal(t, "0000000000000000000000000000000000000000000000000000000032357c84", result.Hex())

	elems = append(elems, big.NewInt(1), big.NewInt(4))
	result, err = HashElems(fst, snd, elems...)
	assert.NoError(t, err)
	assert.Equal(t, "000000000000000000000000000000000000000000000000000000006cd45985", result.Hex())
}

func TestPreHandlingElems(t *testing.T) {
	flagArray := uint32(0b1010)
	elems := []Byte32{
		*NewByte32FromBytes([]byte("test1")),
		*NewByte32FromBytes([]byte("test2")),
		*NewByte32FromBytes([]byte("test3")),
		*NewByte32FromBytes([]byte("test4")),
	}

	result, err := PreHandlingElems(flagArray, elems)
	assert.NoError(t, err)
	assert.Equal(t, "0000000000000000000000000000000000000000000000000000000064beb06b", result.Hex())

	elems = elems[:1]
	result, err = PreHandlingElems(flagArray, elems)
	assert.NoError(t, err)
	assert.Equal(t, "0000000000000000000000000000000000000000000000000000007465737431", result.Hex())
}
