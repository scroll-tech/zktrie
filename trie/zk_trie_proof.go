package trie

import (
	"bytes"

	zkt "github.com/scroll-tech/zktrie/types"
)

var magicSMTBytes []byte

func init() {
	magicSMTBytes = []byte("THIS IS SOME MAGIC BYTES FOR SMT m1rRXgP2xpDI")
}

func ProofMagicBytes() []byte { return magicSMTBytes }

// DecodeProof try to decode a node bytes, return can be nil for any non-node data (magic code)
func DecodeSMTProof(data []byte) (*Node, error) {

	if bytes.Equal(magicSMTBytes, data) {
		//skip magic bytes node
		return nil, nil
	}

	return NewNodeFromBytes(data)
}

// Prove constructs a merkle proof for SMT, it respect the protocol used by the ethereum-trie
// but save the node data with a compact form
func (mt *ZkTrieImpl) prove(kHash *zkt.Hash, fromLevel uint, writeNode func(*Node) error) error {

	path := getPath(mt.maxLevels, kHash[:])
	var nodes []*Node
	tn := mt.rootHash
	for i := 0; i < mt.maxLevels; i++ {
		n, err := mt.GetNode(tn)
		if err != nil {
			return err
		}

		finished := true
		switch n.Type {
		case NodeTypeEmpty:
		case NodeTypeLeaf:
			// notice even we found a leaf whose entry didn't match the expected k,
			// we still include it as the proof of absence
		case NodeTypeParent:
			finished = false
			if path[i] {
				tn = n.ChildR
			} else {
				tn = n.ChildL
			}
		default:
			return ErrInvalidNodeFound
		}

		nodes = append(nodes, n)
		if finished {
			break
		}
	}

	for _, n := range nodes {
		if fromLevel > 0 {
			fromLevel--
			continue
		}

		// TODO: notice here we may have broken some implicit on the proofDb:
		// the key is not kecca(value) and it even can not be derived from
		// the value by any means without a actually decoding
		if err := writeNode(n); err != nil {
			return err
		}
	}

	return nil
}
