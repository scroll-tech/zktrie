package trie

import (
	"testing"

	zkt "github.com/scroll-tech/zktrie/types"
	"github.com/stretchr/testify/assert"
)

func testNewZkTrie(t *testing.T) {
	root := zkt.Byte32{}
	db := NewZkTrieMemoryDb()
	zkTrie, err := NewZkTrie(root, db)
	assert.NoError(t, err)
	assert.Equal(t, zkt.HashZero.Bytes(), zkTrie.Hash())
	assert.Equal(t, zkt.HashZero.Bytes(), zkTrie.Tree().rootHash.Bytes())

	root = zkt.Byte32{1}
	zkTrie, err = NewZkTrie(root, db)
	assert.Equal(t, ErrKeyNotFound, err)
	assert.Nil(t, zkTrie)
}

func testZkTrie_GetUpdateDelete(t *testing.T) {
	root := zkt.Byte32{}
	db := NewZkTrieMemoryDb()
	zkTrie, err := NewZkTrie(root, db)
	assert.NoError(t, err)

	val, err := zkTrie.TryGet([]byte("key"))
	assert.NoError(t, err)
	assert.Nil(t, val)
	assert.Equal(t, zkt.HashZero.Bytes(), zkTrie.Hash())

	err = zkTrie.TryUpdate([]byte("key"), 1, []zkt.Byte32{{1}})
	assert.NoError(t, err)
	assert.Equal(t, []byte{0x30, 0x1b, 0x5e, 0x80, 0x74, 0x88, 0xfb, 0xe2, 0x43, 0x82, 0x92, 0x51, 0xe4, 0xae, 0xd9, 0x9a, 0xc3, 0xd6, 0x4, 0x90, 0xc1, 0x30, 0x14, 0x88, 0x97, 0xde, 0x59, 0x4c, 0xfb, 0x75, 0xca, 0x3e}, zkTrie.Hash())

	val, err = zkTrie.TryGet([]byte("key"))
	assert.NoError(t, err)
	assert.Equal(t, (&zkt.Byte32{1}).Bytes(), val)

	err = zkTrie.TryDelete([]byte("key"))
	assert.NoError(t, err)
	assert.Equal(t, zkt.HashZero.Bytes(), zkTrie.Hash())

	val, err = zkTrie.TryGet([]byte("key"))
	assert.NoError(t, err)
	assert.Nil(t, val)
}

func testZkTrie_Copy(t *testing.T) {
	root := zkt.Byte32{}
	db := NewZkTrieMemoryDb()
	zkTrie, err := NewZkTrie(root, db)
	assert.NoError(t, err)

	zkTrie.TryUpdate([]byte("key"), 1, []zkt.Byte32{{1}})

	copyTrie := zkTrie.Copy()
	val, err := copyTrie.TryGet([]byte("key"))
	assert.NoError(t, err)
	assert.Equal(t, (&zkt.Byte32{1}).Bytes(), val)
}

func testZkTrie_ProveAndProveWithDeletion(t *testing.T) {
	root := zkt.Byte32{}
	db := NewZkTrieMemoryDb()
	zkTrie, err := NewZkTrie(root, db)
	assert.NoError(t, err)

	keys := []string{"key1", "key2", "key3", "key4", "key5"}
	for i, keyStr := range keys {
		key := make([]byte, 32)
		copy(key, []byte(keyStr))

		err := zkTrie.TryUpdate(key, uint32(i+1), []zkt.Byte32{{byte(uint32(i + 1))}})
		assert.NoError(t, err)

		writeNode := func(n *Node) error {
			return nil
		}

		onHit := func(n *Node, sib *Node) {
		}

		k, err := zkt.ToSecureKey(key)
		assert.NoError(t, err)

		for j := 0; j <= i; j++ {
			err = zkTrie.ProveWithDeletion(zkt.NewHashFromBigInt(k).Bytes(), uint(j), writeNode, onHit)
			assert.NoError(t, err)

			err = zkTrie.Prove(zkt.NewHashFromBigInt(k).Bytes(), uint(j), writeNode)
			assert.NoError(t, err)
		}
	}
}
