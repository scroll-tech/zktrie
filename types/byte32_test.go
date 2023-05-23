package zktrie

import (
	"bytes"
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

func TestNewByte32FromBytesAndPaddingZero(t *testing.T) {
	var tests = []struct {
		input               []byte
		expected            []byte
		expectedPaddingZero []byte
		expectedHash        *big.Int
		expectedHashPadding *big.Int
	}{
		{bytes.Repeat([]byte{1}, 4),
			[]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1},
			[]byte{1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			big.NewInt(4964305546),
			big.NewInt(3764529366),
		},
		{bytes.Repeat([]byte{1}, 34),
			[]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
			[]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
			big.NewInt(3086631147),
			big.NewInt(3086631147),
		},
	}

	for _, tt := range tests {
		byte32Result := NewByte32FromBytes(tt.input)
		byte32PaddingResult := NewByte32FromBytesPaddingZero(tt.input)
		assert.Equal(t, tt.expected, byte32Result.Bytes())
		assert.Equal(t, tt.expectedPaddingZero, byte32PaddingResult.Bytes())
		hashResult, err := byte32Result.Hash()
		assert.NoError(t, err)
		hashPaddingResult, err := byte32PaddingResult.Hash()
		assert.NoError(t, err)
		assert.Equal(t, tt.expectedHash, hashResult)
		assert.Equal(t, tt.expectedHashPadding, hashPaddingResult)
	}
}
