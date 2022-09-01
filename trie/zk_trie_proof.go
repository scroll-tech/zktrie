package trie

import (
	zkt "github.com/scroll-tech/zktrie-util/types"
)

var magicSMTBytes []byte

func init() {
	magicSMTBytes = []byte("THIS IS SOME MAGIC BYTES FOR SMT m1rRXgP2xpDI")
}

// Prove constructs a merkle proof for SMT, it respect the protocol used by the ethereum-trie
// but save the node data with a compact form
func (mt *ZkTrieImpl) prove(kHash *zkt.Hash, fromLevel uint, writeNode func(*Node) error) error {

	path := getPath(mt.maxLevels, kHash[:])
	var nodes []*Node
	tn := mt.rootKey
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
		case NodeTypeMiddle:
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
