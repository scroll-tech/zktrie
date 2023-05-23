package trie

import (
	"fmt"
	"math/big"
	"testing"

	zkt "github.com/scroll-tech/zktrie/types"
	"github.com/stretchr/testify/assert"
)

func TestNewEmptyNode(t *testing.T) {
	node := NewEmptyNode()
	assert.Equal(t, NodeTypeEmpty, node.Type)

	hash, err := node.NodeHash()
	assert.NoError(t, err)
	assert.Equal(t, &zkt.HashZero, hash)
}

func TestNewLeafNode(t *testing.T) {
	k := zkt.NewHashFromBytes([]byte{1, 2, 3, 4, 5})
	vp := make([]zkt.Byte32, 1)
	node := NewLeafNode(k, 1, vp)
	assert.Equal(t, NodeTypeLeaf, node.Type)
	assert.Equal(t, uint32(1), node.CompressedFlags)
	assert.Equal(t, vp, node.ValuePreimage)

	hash, err := node.NodeHash()
	assert.NoError(t, err)
	assert.Equal(t, "11de0a8aa076bd8ae4fe7641f8be3fff040d0818b1bfbb5822b96a7455db5e34", hash.Hex())
}

func TestNewParentNode(t *testing.T) {
	l := zkt.NewHashFromBytes([]byte{1, 2, 3, 4, 5})
	r := zkt.NewHashFromBytes([]byte{5, 4, 3, 2, 1})
	node := NewParentNode(l, r)
	assert.Equal(t, NodeTypeParent, node.Type)
	assert.Equal(t, l, node.ChildL)
	assert.Equal(t, r, node.ChildR)

	hash, err := node.NodeHash()
	assert.NoError(t, err)
	assert.Equal(t, "00000000000000000000000000010824794d0612b8ca3c8fed1f3366e67b0401", hash.Hex())
}

func TestNewParentNodeWithEmptyChild(t *testing.T) {
	l := zkt.NewHashFromBytes([]byte{1, 2, 3, 4, 5})
	r, err := NewEmptyNode().NodeHash()
	assert.NoError(t, err)
	node := NewParentNode(l, r)

	assert.Equal(t, NodeTypeParent, node.Type)
	assert.Equal(t, l, node.ChildL)
	assert.Equal(t, r, node.ChildR)

	hash, err := node.NodeHash()
	assert.NoError(t, err)
	assert.Equal(t, "00000000000000000000000000010824794d0612b8ca3c76c4f10743d2710000", hash.Hex())
}

func TestNewNodeFromBytes(t *testing.T) {
	t.Run("ParentNode", func(t *testing.T) {
		k1 := zkt.NewHashFromBytes([]byte{1, 2, 3, 4, 5})
		k2 := zkt.NewHashFromBytes([]byte{6, 7, 8, 9, 0})
		node := NewParentNode(k1, k2)
		b := node.Value()

		node, err := NewNodeFromBytes(b)
		assert.NoError(t, err)

		assert.Equal(t, NodeTypeParent, node.Type)
		assert.Equal(t, k1, node.ChildL)
		assert.Equal(t, k2, node.ChildR)

		hash, err := node.NodeHash()
		assert.NoError(t, err)
		assert.Equal(t, "00000000000000000000000000010824794d0612b8ca3c9b1982e40262c20000", hash.Hex())
	})

	t.Run("LeafNode", func(t *testing.T) {
		k := zkt.NewHashFromBytes([]byte{1, 2, 3, 4, 5})
		vp := make([]zkt.Byte32, 1)
		node := NewLeafNode(k, 1, vp)

		node.KeyPreimage = zkt.NewByte32FromBytes([]byte{6, 7, 8, 9, 10})

		nodeBytes := node.Value()
		newNode, err := NewNodeFromBytes(nodeBytes)
		assert.NoError(t, err)

		assert.Equal(t, node.Type, newNode.Type)
		assert.Equal(t, node.NodeKey, newNode.NodeKey)
		assert.Equal(t, node.ValuePreimage, newNode.ValuePreimage)
		assert.Equal(t, node.KeyPreimage, newNode.KeyPreimage)

		hash, err := node.NodeHash()
		assert.NoError(t, err)
		assert.Equal(t, "11de0a8aa076bd8ae4fe7641f8be3fff040d0818b1bfbb5822b96a7455db5e34", hash.Hex())
	})

	t.Run("EmptyNode", func(t *testing.T) {
		node := NewEmptyNode()
		b := node.Value()

		node, err := NewNodeFromBytes(b)
		assert.NoError(t, err)

		assert.Equal(t, NodeTypeEmpty, node.Type)

		hash, err := node.NodeHash()
		assert.NoError(t, err)
		assert.Equal(t, &zkt.HashZero, hash)
	})

	t.Run("BadSize", func(t *testing.T) {
		testCases := [][]byte{
			{},
			{0, 1, 2},
			func() []byte {
				b := make([]byte, zkt.HashByteLen+3)
				b[0] = byte(NodeTypeLeaf)
				return b
			}(),
			func() []byte {
				k := zkt.NewHashFromBytes([]byte{1, 2, 3, 4, 5})
				vp := make([]zkt.Byte32, 1)
				node := NewLeafNode(k, 1, vp)
				b := node.Value()
				return b[:len(b)-32]
			}(),
			func() []byte {
				k := zkt.NewHashFromBytes([]byte{1, 2, 3, 4, 5})
				vp := make([]zkt.Byte32, 1)
				node := NewLeafNode(k, 1, vp)
				node.KeyPreimage = zkt.NewByte32FromBytes([]byte{6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37})

				b := node.Value()
				return b[:len(b)-1]
			}(),
		}

		for _, b := range testCases {
			node, err := NewNodeFromBytes(b)
			assert.ErrorIs(t, err, ErrNodeBytesBadSize)
			assert.Nil(t, node)
		}
	})

	t.Run("InvalidType", func(t *testing.T) {
		b := []byte{255}

		node, err := NewNodeFromBytes(b)
		assert.ErrorIs(t, err, ErrInvalidNodeFound)
		assert.Nil(t, node)
	})
}

func TestNodeHash(t *testing.T) {
	childL := zkt.NewHashFromBytes(big.NewInt(123456789).Bytes())
	childR := zkt.NewHashFromBytes(big.NewInt(987654321).Bytes())
	parent := NewParentNode(childL, childR)
	parentHash, err := parent.NodeHash()
	assert.NoError(t, err)
	assert.Equal(t, "000000000000000000000000000000000b741c46157667065459d04f0d7d4a61", parentHash.Hex())

	kHash := zkt.NewHashFromBytes(big.NewInt(123456789).Bytes())
	vPreimageByte32 := zkt.NewByte32FromBytes(big.NewInt(987654321).Bytes())
	vPreimage := []zkt.Byte32{*vPreimageByte32}
	leaf := NewLeafNode(kHash, 1, vPreimage)
	leafHash, err := leaf.NodeHash()
	assert.NoError(t, err)
	assert.Equal(t, "000000832f17a884b8d4898785b3c9102f088cb8d04984da8d3f45f0129538c1", leafHash.Hex())
	valueHash, err := zkt.PreHandlingElems(1, vPreimage)
	assert.NoError(t, err)
	assert.Equal(t, "0000000000000000000000000000000000000000000000000d8988a9f1cc4a61", valueHash.Hex())

	node := &Node{Type: 99}
	invalidNodeHash, err := node.NodeHash()
	assert.NoError(t, err)
	assert.Equal(t, &zkt.HashZero, invalidNodeHash)
}

func TestValueHash(t *testing.T) {
	k := zkt.NewHashFromBytes([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32})
	valuePreimage := make([]zkt.Byte32, 5)
	valuePreimage[0] = *zkt.NewByte32FromBytes([]byte("This is the first value"))
	valuePreimage[1] = *zkt.NewByte32FromBytes([]byte("This is the second value"))
	valuePreimage[2] = *zkt.NewByte32FromBytes([]byte("This is the third value"))
	valuePreimage[3] = *zkt.NewByte32FromBytes([]byte("This is the fourth value"))
	valuePreimage[4] = *zkt.NewByte32FromBytes([]byte("This is the fifth value"))
	node := NewLeafNode(k, 0, valuePreimage)

	hash, err := node.ValueHash()
	assert.NoError(t, err)
	assert.Equal(t, "1b8c86dd277f539299508c05279ed02204bb8ef4e2a37b831c2114adc49409a9", hash.Hex())
}

func TestNonLeafValueHash(t *testing.T) {
	childL := zkt.NewHashFromBytes(big.NewInt(123456789).Bytes())
	childR := zkt.NewHashFromBytes(big.NewInt(987654321).Bytes())
	parent := NewParentNode(childL, childR)

	hash, err := parent.ValueHash()
	assert.NoError(t, err)
	assert.Equal(t, &zkt.HashZero, hash)

	emptyNode := NewEmptyNode()

	hash, err = emptyNode.ValueHash()
	assert.NoError(t, err)
	assert.Equal(t, &zkt.HashZero, hash)
}

func TestNodeData(t *testing.T) {
	k := zkt.NewHashFromBytes([]byte{1, 2, 3, 4, 5})
	vpBytes := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	vp := []zkt.Byte32{*zkt.NewByte32FromBytes(vpBytes)}
	node := NewLeafNode(k, 1, vp)
	assert.Equal(t, vpBytes, node.Data())

	parentNode := NewParentNode(k, k)
	assert.Nil(t, parentNode.Data())
}

func TestCanonicalValue(t *testing.T) {
	k := zkt.NewHashFromBytes([]byte{1, 2, 3, 4, 5})
	vp := make([]zkt.Byte32, 1)

	node := NewLeafNode(k, 1, vp)
	canonicalValue := node.CanonicalValue()
	assert.Equal(t, []byte{0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, canonicalValue)

	parentNode := NewParentNode(k, k)
	canonicalValue = parentNode.CanonicalValue()
	assert.Equal(t, []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5}, canonicalValue)

	emptyNode := &Node{Type: NodeTypeEmpty}
	assert.Equal(t, []byte{byte(emptyNode.Type)}, emptyNode.CanonicalValue())

	invalidNode := &Node{Type: 99}
	assert.Equal(t, []byte{}, invalidNode.CanonicalValue())
}

func TestValue(t *testing.T) {
	k := zkt.NewHashFromBytes([]byte{1, 2, 3, 4, 5})
	vp := make([]zkt.Byte32, 1)
	node := NewLeafNode(k, 1, vp)

	value := node.Value()
	assert.Equal(t, []byte{0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, value)

	node.KeyPreimage = zkt.NewByte32FromBytes([]byte{6, 7, 8, 9, 10})
	value = node.Value()
	assert.Equal(t, []byte{0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x20, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x6, 0x7, 0x8, 0x9, 0xa}, value)
}

func TestNodeString(t *testing.T) {
	k := zkt.NewHashFromBytes([]byte{1, 2, 3, 4, 5})
	vp := make([]zkt.Byte32, 1)

	leafNode := NewLeafNode(k, 1, vp)
	assert.Equal(t, fmt.Sprintf("Leaf I:%v Items: %d, First:%v", leafNode.NodeKey, len(leafNode.ValuePreimage), leafNode.ValuePreimage[0]), leafNode.String())

	parentNode := NewParentNode(k, k)
	assert.Equal(t, fmt.Sprintf("Parent L:%s R:%s", parentNode.ChildL, parentNode.ChildR), parentNode.String())

	emptyNode := NewEmptyNode()
	assert.Equal(t, "Empty", emptyNode.String())

	invalidNode := &Node{Type: 99}
	assert.Equal(t, "Invalid Node", invalidNode.String())
}
