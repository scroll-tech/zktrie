package zktrie

import (
	"math/big"
	"strconv"
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
	assert.Equal(t, "17571106468431745531706442476067603634164190589809290674663620802670121169536", secureKey.String())
}

func TestToSecureKeyBytes(t *testing.T) {
	secureKeyBytes, err := ToSecureKeyBytes([]byte("testKey"))
	assert.NoError(t, err)
	assert.Equal(t, []byte{0x26, 0xd8, 0xe4, 0xd1, 0xde, 0xf3, 0xac, 0x54, 0x62, 0x1d, 0x56, 0x24, 0x94, 0xf2, 0x63, 0x8b, 0x96, 0x74, 0x4c, 0x3b, 0xd6, 0x91, 0x3f, 0x49, 0xa6, 0xe6, 0x9d, 0x42, 0xb3, 0x6b, 0xb2, 0x80}, secureKeyBytes.Bytes())
}

func TestReverseByteOrder(t *testing.T) {
	assert.Equal(t, []byte{5, 4, 3, 2, 1}, ReverseByteOrder([]byte{1, 2, 3, 4, 5}))
}

func TestHashElems(t *testing.T) {
	fst := big.NewInt(5)
	snd := big.NewInt(3)
	elems := make([]*big.Int, 32)
	for i := range elems {
		elems[i] = big.NewInt(int64(i + 1))
	}

	result, err := HashElems(fst, snd, elems...)
	assert.NoError(t, err)
	assert.Equal(t, "2b918b092488dfd40bbafc1381447755b1846b13b3f846f0631a517d91710ebb", result.Hex())
}

func TestPreHandlingElems(t *testing.T) {
	flagArray := uint32(0b10101010101010101010101010101010)
	elems := make([]Byte32, 32)
	for i := range elems {
		elems[i] = *NewByte32FromBytes([]byte("test" + strconv.Itoa(i+1)))
	}

	result, err := PreHandlingElems(flagArray, elems)
	assert.NoError(t, err)
	assert.Equal(t, "1bc868a5ce9d19e154039ab7b24b08b260ffbd3f7279244eed4fb9293a1ae719", result.Hex())

	elems = elems[:1]
	result, err = PreHandlingElems(flagArray, elems)
	assert.NoError(t, err)
	assert.Equal(t, "0000000000000000000000000000000000000000000000000000007465737431", result.Hex())
}
