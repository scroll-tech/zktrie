// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package trie

import (
	"math/big"

	zkt "github.com/scroll-tech/zktrie/types"
)

// ZkTrie wraps a trie with key hashing. In a secure trie, all
// access operations hash the key using keccak256. This prevents
// calling code from creating long chains of nodes that
// increase the access time.
//
// Contrary to a regular trie, a ZkTrie can only be created with
// New and must have an attached database. The database also stores
// the preimage of each key.
//
// ZkTrie is not safe for concurrent use.
type ZkTrie struct {
	tree *ZkTrieImpl
}

// NodeKeyValidBytes is the number of least significant bytes in the node key
// that are considered valid, and thus, limits the trie depth to be
// NodeKeyValidBytes * 8.
// We need to truncate the node key because the key is the output of the
// Poseidon hash and the space doesn't fully occupy the range of power of two.
// It can lead to an ambiguous bit representation of the key and thus cause
// a soundness issue in the circuit.
const NodeKeyValidBytes = 31

// NewSecure creates a trie
// SecureBinaryTrie bypasses all the buffer mechanism in *Database, it directly uses the
// underlying diskdb
func NewZkTrie(root zkt.Byte32, db ZktrieDatabase) (*ZkTrie, error) {
	maxLevels := NodeKeyValidBytes * 8
	tree, err := NewZkTrieImplWithRoot((db), zkt.NewHashFromBytes(root.Bytes()), maxLevels)
	if err != nil {
		return nil, err
	}
	return &ZkTrie{
		tree: tree,
	}, nil
}

// TryGet returns the value for key stored in the trie.
// The value bytes must not be modified by the caller.
// If a node was not found in the database, a MissingNodeError is returned.
func (t *ZkTrie) TryGet(key []byte) ([]byte, error) {
	k, err := zkt.ToSecureKey(key)
	if err != nil {
		return nil, err
	}

	return t.tree.TryGet(zkt.NewHashFromBigInt(k))
}

// Tree exposed underlying ZkTrieImpl
func (t *ZkTrie) Tree() *ZkTrieImpl {
	return t.tree
}

// TryGetNode attempts to retrieve a trie node by compact-encoded path. It is not
// possible to use keybyte-encoding as the path might contain odd nibbles.
func (t *ZkTrie) TryGetNode(path []byte) ([]byte, int, error) {
	panic("unimplemented")
}

func (t *ZkTrie) updatePreimage(preimage []byte, hashField *big.Int) {
	t.tree.db.UpdatePreimage(preimage, hashField)
}

// TryUpdate associates key with value in the trie. Subsequent calls to
// Get will return value. If value has length zero, any existing value
// is deleted from the trie and calls to Get will return nil.
//
// The value bytes must not be modified by the caller while they are
// stored in the trie.
//
// If a node was not found in the database, a MissingNodeError is returned.
//
// NOTE: value is restricted to length of bytes32.
func (t *ZkTrie) TryUpdate(key []byte, vFlag uint32, vPreimage []zkt.Byte32) error {
	k, err := zkt.ToSecureKey(key)
	if err != nil {
		return err
	}
	t.updatePreimage(key, k)
	return t.tree.TryUpdate(zkt.NewHashFromBigInt(k), vFlag, vPreimage)
}

// TryDelete removes any existing value for key from the trie.
// If a node was not found in the database, a MissingNodeError is returned.
func (t *ZkTrie) TryDelete(key []byte) error {
	k, err := zkt.ToSecureKey(key)
	if err != nil {
		return err
	}

	kHash := zkt.NewHashFromBigInt(k)
	//mitigate the create-delete issue: do not delete unexisted key
	if r, _ := t.tree.TryGet(kHash); r == nil {
		return nil
	}

	return t.tree.TryDelete(kHash)
}

// Hash returns the root hash of SecureBinaryTrie. It does not write to the
// database and can be used even if the trie doesn't have one.
func (t *ZkTrie) Hash() []byte {
	return t.tree.rootHash.Bytes()
}

// Copy returns a copy of SecureBinaryTrie.
func (t *ZkTrie) Copy() *ZkTrie {
	cpy, err := NewZkTrieImplWithRoot(t.tree.db, t.tree.rootHash, t.tree.maxLevels)
	if err != nil {
		panic("clone trie failed")
	}
	return &ZkTrie{
		tree: cpy,
	}
}

// Prove constructs a merkle proof for key. The result contains all encoded nodes
// on the path to the value at key. The value itself is also included in the last
// node and can be retrieved by verifying the proof.
//
// If the trie does not contain a value for key, the returned proof contains all
// nodes of the longest existing prefix of the key (at least the root node), ending
// with the node that proves the absence of the key.
func (t *ZkTrie) Prove(key []byte, fromLevel uint, writeNode func(*Node) error) error {
	// notice Prove in secure trie "pass through" the key instead of secure it
	// this keep consistent behavior with geth's secure trie
	k, err := zkt.NewHashFromCheckedBytes(key)
	if err != nil {
		return err
	}
	err = t.tree.prove(k, fromLevel, func(n *Node) error {
		if n.Type == NodeTypeLeaf {
			n.KeyPreimage = zkt.NewByte32FromBytesPaddingZero(key)
		}
		return writeNode(n)
	})
	if err != nil {
		return err
	}

	// we put this special kv pair in db so we can distinguish the type and
	// make suitable Proof
	return nil
}
