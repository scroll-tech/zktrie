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
	assert.Equal(t, "38357272897674900411107081535936389234910988338891909398812022532881453900469", secureKey.String())
}

func TestToSecureKeyBytes(t *testing.T) {
	secureKeyBytes, err := ToSecureKeyBytes([]byte("testKey"))
	assert.NoError(t, err)
	assert.Equal(t, []byte{0x54, 0xcd, 0x72, 0x75, 0x8e, 0x77, 0xe1, 0xc, 0xdb, 0xa8, 0xf4, 0x86, 0x3a, 0xdb, 0x35, 0xba, 0x69, 0x56, 0xda, 0x2b, 0xcb, 0xb8, 0x4c, 0x4c, 0xf5, 0x59, 0x1e, 0x80, 0xfd, 0xc3, 0x62, 0xb5}, secureKeyBytes.Bytes())
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
	assert.Equal(t, "481ef46d7a6ddd6be6672ac7fa9cc7512513e282da1b0150c0d0cc5921862d65", result.Hex())
}

func TestPreHandlingElems(t *testing.T) {
	flagArray := uint32(0b10101010101010101010101010101010)
	elems := make([]Byte32, 32)
	for i := range elems {
		elems[i] = *NewByte32FromBytes([]byte("test" + strconv.Itoa(i+1)))
	}

	result, err := PreHandlingElems(flagArray, elems)
	assert.NoError(t, err)
	assert.Equal(t, "5aa16cff7cef7e6a1af00a9bd9f155016e6cae06936e871745de8fd8bb33b742", result.Hex())

	elems = elems[:1]
	result, err = PreHandlingElems(flagArray, elems)
	assert.NoError(t, err)
	assert.Equal(t, "0000000000000000000000000000000000000000000000000000007465737431", result.Hex())
}
