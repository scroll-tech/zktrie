package zktrie

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func testNewByte32(t *testing.T) {
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
			"20010362096352638085534787914500932877927900211706681493864651868302326347127",
		},
		{bytes.Repeat([]byte{1}, 34),
			[]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
			[]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
			"6354311849456090336844591885925614854128215188934214047178633565777297101249",
			"6354311849456090336844591885925614854128215188934214047178633565777297101249",
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
