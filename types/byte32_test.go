package zktrie

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func init() {
	lcEff := big.NewInt(65536)
	prime, _ := new(big.Int).SetString("115792089237316195423570985008687907853269984665640564039457584007908834671663", 10)

	testHash := func(arr []*big.Int) (*big.Int, error) {
		sum := big.NewInt(0)
		for _, bi := range arr {
			nbi := new(big.Int).Mul(bi, bi)
			sum = sum.Mul(sum, sum)
			sum = sum.Mul(sum, lcEff)
			sum = sum.Add(sum, nbi)
		}
		return sum.Mod(sum, prime), nil
	}

	InitHashScheme(testHash)
}

func TestNewByte32(t *testing.T) {
	var tests = []struct {
		input               []byte
		expected            []byte
		expectedPaddingZero []byte
		expectedHash        string
		expectedHashPadding string
	}{
		{bytes.Repeat([]byte{1}, 4),
			[]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1},
			[]byte{1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			"283686952174081",
			"10854753567005534538060156430056055935965300469302387031436241414646986205738",
		},
		{bytes.Repeat([]byte{1}, 34),
			[]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
			[]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
			"87978124945399561094017330311065670766621950515520257782675953699248863509509",
			"87978124945399561094017330311065670766621950515520257782675953699248863509509",
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
		assert.Equal(t, tt.expectedHash, hashResult.String())
		assert.Equal(t, tt.expectedHashPadding, hashPaddingResult.String())
	}
}
