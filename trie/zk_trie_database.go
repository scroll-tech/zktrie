package trie

import (
	"math/big"
)

type ZktrieDatabase interface {
	updatePreimage(preimage []byte, hashField *big.Int)
	put(k, v []byte) error
	get(key []byte) ([]byte, error)
}
