package zktrie

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func init() {
	var lcEff *big.Int
	var prime = int64(5915587277)

	testHash := func(arr []*big.Int) (*big.Int, error) {
		sum := big.NewInt(0)
		for _, bi := range arr {
			nbi := big.NewInt(0).Mul(bi, bi)
			sum = sum.Mul(sum, sum)
			sum = sum.Mul(sum, lcEff)
			sum = sum.Add(sum, nbi)
		}
		return sum.Mod(sum, big.NewInt(prime)), nil
	}

	lcEff = big.NewInt(65536)
	InitHashScheme(testHash)
}

func TestByte32Hash(t *testing.T) {
	b := new(Byte32)
	for i := 0; i < 32; i++ {
		b[i] = byte(i)
	}
	hash, err := b.Hash()
	assert.NoError(t, err)
	assert.Equal(t, big.NewInt(2201952636), hash)
}

func TestByte32Bytes(t *testing.T) {
	b := new(Byte32)
	expectedValue := make([]byte, 32)
	for i := 0; i < 32; i++ {
		value := byte(i)
		b[i] = value
		expectedValue[i] = value
	}
	assert.Equal(t, expectedValue, b.Bytes())
}

func TestNewByte32FromBytes(t *testing.T) {
	var tests = []struct {
		input []byte
		want  Byte32
	}{
		{[]byte{1, 2, 3, 4}, [32]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4}},
		{[]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34}, [32]byte{3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34}},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.want, *NewByte32FromBytes(tt.input))
	}
}

func TestNewByte32FromBytesPaddingZero(t *testing.T) {
	var tests = []struct {
		input []byte
		want  Byte32
	}{
		{
			[]byte{1, 2, 3, 4},
			[32]byte{1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			[]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34},
			[32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
		},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.want, *NewByte32FromBytesPaddingZero(tt.input))
	}
}
