package zktrie

import (
	"bytes"
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func setupENV() {
	InitHashScheme(func(arr []*big.Int, domain *big.Int) (*big.Int, error) {
		lcEff := big.NewInt(65536)
		qString := "21888242871839275222246405745257275088548364400416034343698204186575808495617"
		Q, ok := new(big.Int).SetString(qString, 10)
		if !ok {
			panic(fmt.Sprintf("Bad base 10 string %s", qString))
		}
		sum := domain
		for _, bi := range arr {
			nbi := new(big.Int).Mul(bi, bi)
			sum.Mul(sum, sum)
			sum.Mul(sum, lcEff)
			sum.Add(sum, nbi)
		}
		return sum.Mod(sum, Q), nil
	})
}

func TestMain(m *testing.M) {
	setupENV()
	os.Exit(m.Run())
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
			"19342813114117753747472897",
			"4198633341355723145865718849633731687852896197776343461751712629107518959468",
		},
		{bytes.Repeat([]byte{1}, 34),
			[]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
			[]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
			"19162873132136764367682277409313605623778997630491468285254908822491098844002",
			"19162873132136764367682277409313605623778997630491468285254908822491098844002",
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
