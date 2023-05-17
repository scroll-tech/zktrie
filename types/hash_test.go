package zktrie

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDummyHash(t *testing.T) {
	result, err := dummyHash([]*big.Int{})
	assert.Equal(t, big.NewInt(0), result)
	assert.Equal(t, hashNotInitErr, err)
}

func TestCheckBigIntInField(t *testing.T) {
	bi := big.NewInt(0)
	assert.True(t, CheckBigIntInField(bi))

	bi = new(big.Int).Sub(Q, big.NewInt(1))
	assert.True(t, CheckBigIntInField(bi))

	bi = new(big.Int).Set(Q)
	assert.False(t, CheckBigIntInField(bi))
}

func TestHashToBigInt(t *testing.T) {
	h := &Hash{}
	for i := 0; i < 32; i++ {
		h[i] = byte(i)
	}
	assert.Equal(t, "14074904626401341155369551180448584754667373453244490859944217516317499064576", h.BigInt().String())
}

func TestNewHashFromBigInt(t *testing.T) {
	bi := big.NewInt(12345)
	h := NewHashFromBigInt(bi)
	assert.Equal(t, "0000000000000000000000000000000000000000000000000000000000003039", h.Hex())
	assert.Equal(t, "12345", h.String())
}

func TestNewHashFromBytes(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	h := NewHashFromBytes(b)
	assert.Equal(t, "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20", h.Hex())
	assert.Equal(t, "45586735...", h.String())
}

func TestNewHashFromString(t *testing.T) {
	s := "12345"
	h, err := NewHashFromString(s)
	assert.NoError(t, err)
	assert.Equal(t, "0000000000000000000000000000000000000000000000000000000000003039", h.Hex())
	assert.Equal(t, "12345", h.String())
}

func TestNewHashFromCheckedBytes(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	h, err := NewHashFromCheckedBytes(b)
	assert.NoError(t, err)
	assert.Equal(t, NewHashFromBytes(b), h)

	short := []byte{1, 2, 3}
	_, err = NewHashFromCheckedBytes(short)
	assert.Error(t, err)
	assert.Equal(t, fmt.Sprintf("expected %d bytes, but got %d bytes", HashByteLen, len(short)), err.Error())
}

func TestNewBigIntFromHashBytes(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	bi, err := NewBigIntFromHashBytes(b)
	assert.NoError(t, err)
	assert.Equal(t, new(big.Int).SetBytes(b), bi)

	short := []byte{1, 2, 3}
	_, err = NewBigIntFromHashBytes(short)
	assert.Error(t, err)
	assert.Equal(t, fmt.Sprintf("expected %d bytes, but got %d bytes", HashByteLen, len(short)), err.Error())

	outOfField := make([]byte, HashByteLen)
	outOfField[0] = byte(255)
	_, err = NewBigIntFromHashBytes(outOfField)
	assert.Error(t, err)
	assert.Equal(t, "NewBigIntFromHashBytes: Value not inside the Finite Field", err.Error())
}

func TestMarshalAndUnmarshalText(t *testing.T) {
	h1 := &Hash{}
	for i := 0; i < 32; i++ {
		h1[i] = byte(i)
	}
	text, err := h1.MarshalText()
	assert.NoError(t, err)
	assert.Equal(t, "14074904626401341155369551180448584754667373453244490859944217516317499064576", h1.BigInt().String())

	h2 := &Hash{}
	err = h2.UnmarshalText(text)
	assert.NoError(t, err)

	assert.Equal(t, h1, h2)
}
