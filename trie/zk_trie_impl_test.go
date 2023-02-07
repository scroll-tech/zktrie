package trie

import (
	"math/big"
	"testing"

	zkt "github.com/scroll-tech/zktrie/types"
	"github.com/stretchr/testify/assert"
)

var lcEff *big.Int
var prime = int64(5915587277)

func dummyHash(arr []*big.Int) (*big.Int, error) {

	sum := big.NewInt(0)

	for _, bi := range arr {
		nbi := big.NewInt(0).Mul(bi, bi)
		sum = sum.Mul(sum, sum)
		sum = sum.Mul(sum, lcEff)
		sum = sum.Add(sum, nbi)
	}
	return sum.Mod(sum, big.NewInt(prime)), nil
}

func init() {
	lcEff = big.NewInt(65536)

	zkt.InitHashScheme(dummyHash)
}

// we do not need zktrie impl anymore, only made a wrapper for adapting testing
type zkTrieImplTestWrapper struct {
	*ZkTrieImpl
}

func newZkTrieImpl(storage ZktrieDatabase, maxLevels int) (*zkTrieImplTestWrapper, error) {
	return newZkTrieImplWithRoot(storage, &zkt.HashZero, maxLevels)
}

// NewZkTrieImplWithRoot loads a new ZkTrieImpl. If in the storage already exists one
// will open that one, if not, will create a new one.
func newZkTrieImplWithRoot(storage ZktrieDatabase, root *zkt.Hash, maxLevels int) (*zkTrieImplTestWrapper, error) {
	impl, err := NewZkTrieImplWithRoot(storage, root, maxLevels)
	if err != nil {
		return nil, err
	}

	return &zkTrieImplTestWrapper{impl}, nil
}

func (mt *zkTrieImplTestWrapper) AddWord(kPreimage, vPreimage *zkt.Byte32) error {

	if v, _ := mt.TryGet(kPreimage[:]); v != nil {
		return ErrEntryIndexAlreadyExists
	}

	return mt.ZkTrieImpl.TryUpdate(zkt.NewHashFromBytes(kPreimage[:]), 1, []zkt.Byte32{*vPreimage})
}

func (mt *zkTrieImplTestWrapper) GetLeafNodeByWord(kPreimage *zkt.Byte32) (*Node, error) {
	return mt.ZkTrieImpl.GetLeafNode(zkt.NewHashFromBytes(kPreimage[:]))
}

func (mt *zkTrieImplTestWrapper) UpdateWord(kPreimage, vPreimage *zkt.Byte32) error {
	return mt.ZkTrieImpl.TryUpdate(zkt.NewHashFromBytes(kPreimage[:]), 1, []zkt.Byte32{*vPreimage})
}

func (mt *zkTrieImplTestWrapper) DeleteWord(kPreimage *zkt.Byte32) error {
	return mt.ZkTrieImpl.TryDelete(zkt.NewHashFromBytes(kPreimage[:]))
}

func (mt *zkTrieImplTestWrapper) TryGet(key []byte) ([]byte, error) {
	return mt.ZkTrieImpl.TryGet(zkt.NewHashFromBytes(key))
}

type Fatalable interface {
	Fatal(args ...interface{})
}

func newTestingMerkle(f Fatalable, numLevels int) *zkTrieImplTestWrapper {
	mt, err := newZkTrieImpl(NewZkTrieMemoryDb(), numLevels)
	if err != nil {
		f.Fatal(err)
		return nil
	}
	return mt
}

func TestMerkleTree_AddUpdateGetWord(t *testing.T) {
	mt := newTestingMerkle(t, 10)
	err := mt.AddWord(zkt.NewByte32FromBytes([]byte{1}), &zkt.Byte32{2})
	assert.Nil(t, err)
	err = mt.AddWord(zkt.NewByte32FromBytes([]byte{3}), &zkt.Byte32{4})
	assert.Nil(t, err)
	err = mt.AddWord(zkt.NewByte32FromBytes([]byte{5}), &zkt.Byte32{6})
	assert.Nil(t, err)
	err = mt.AddWord(zkt.NewByte32FromBytes([]byte{5}), &zkt.Byte32{7})
	assert.Equal(t, ErrEntryIndexAlreadyExists, err)

	node, err := mt.GetLeafNodeByWord(zkt.NewByte32FromBytes([]byte{1}))
	assert.Nil(t, err)
	assert.Equal(t, len(node.ValuePreimage), 1)
	assert.Equal(t, (&zkt.Byte32{2})[:], node.ValuePreimage[0][:])
	node, err = mt.GetLeafNodeByWord(zkt.NewByte32FromBytes([]byte{3}))
	assert.Nil(t, err)
	assert.Equal(t, len(node.ValuePreimage), 1)
	assert.Equal(t, (&zkt.Byte32{4})[:], node.ValuePreimage[0][:])
	node, err = mt.GetLeafNodeByWord(zkt.NewByte32FromBytes([]byte{5}))
	assert.Nil(t, err)
	assert.Equal(t, len(node.ValuePreimage), 1)
	assert.Equal(t, (&zkt.Byte32{6})[:], node.ValuePreimage[0][:])

	err = mt.UpdateWord(zkt.NewByte32FromBytes([]byte{1}), &zkt.Byte32{7})
	assert.Nil(t, err)
	err = mt.UpdateWord(zkt.NewByte32FromBytes([]byte{3}), &zkt.Byte32{8})
	assert.Nil(t, err)
	err = mt.UpdateWord(zkt.NewByte32FromBytes([]byte{5}), &zkt.Byte32{9})
	assert.Nil(t, err)

	node, err = mt.GetLeafNodeByWord(zkt.NewByte32FromBytes([]byte{1}))
	assert.Nil(t, err)
	assert.Equal(t, len(node.ValuePreimage), 1)
	assert.Equal(t, (&zkt.Byte32{7})[:], node.ValuePreimage[0][:])
	node, err = mt.GetLeafNodeByWord(zkt.NewByte32FromBytes([]byte{3}))
	assert.Nil(t, err)
	assert.Equal(t, len(node.ValuePreimage), 1)
	assert.Equal(t, (&zkt.Byte32{8})[:], node.ValuePreimage[0][:])
	node, err = mt.GetLeafNodeByWord(zkt.NewByte32FromBytes([]byte{5}))
	assert.Nil(t, err)
	assert.Equal(t, len(node.ValuePreimage), 1)
	assert.Equal(t, (&zkt.Byte32{9})[:], node.ValuePreimage[0][:])
	_, err = mt.GetLeafNodeByWord(&zkt.Byte32{100})
	assert.Equal(t, ErrKeyNotFound, err)
}

func TestMerkleTree_Deletion(t *testing.T) {
	mt := newTestingMerkle(t, 10)

	var count int = 6
	var hashes [][]byte
	hashes = append(hashes, mt.Root().Bytes())
	for i := 0; i < count; i++ {
		err := mt.AddWord(zkt.NewByte32FromBytes([]byte{byte(i)}), &zkt.Byte32{byte(i)})
		assert.NoError(t, err)
		hashes = append(hashes, mt.Root().Bytes())
	}

	// binary.LittleEndian.PutUint64(key, uint64(0xffffff))
	// err := trie1.TryDelete(key)
	// assert.Equal(t, err, zktrie.ErrKeyNotFound)

	for i := count - 1; i >= 0; i-- {
		err := mt.DeleteWord(zkt.NewByte32FromBytes([]byte{byte(i)}))
		assert.NoError(t, err)
		assert.Equal(t, hashes[i], mt.Root().Bytes())
	}
}

func TestMerkleTree_Deletion2(t *testing.T) {
	mt := newTestingMerkle(t, 10)
	key1 := zkt.NewByte32FromBytes([]byte{67}) //0b1000011
	err := mt.AddWord(key1, &zkt.Byte32{67})
	rootPhase1 := mt.Root().Bytes()
	assert.Nil(t, err)
	key2 := zkt.NewByte32FromBytes([]byte{131}) //0b10000011
	err = mt.AddWord(key2, &zkt.Byte32{131})
	assert.Nil(t, err)
	rootPhase2 := mt.Root().Bytes()

	assertKeyDepth := func(key *zkt.Byte32, expectedDep int) {
		levelCnt := 0
		err := mt.prove(zkt.NewHashFromBytes(key[:]), 0,
			func(*Node) error {
				levelCnt++
				return nil
			},
		)
		assert.Nil(t, err)
		assert.Equal(t, expectedDep, levelCnt)
	}

	assertKeyDepth(key1, 8)
	assertKeyDepth(key2, 8)

	err = mt.DeleteWord(key2)
	assert.Nil(t, err)

	assertKeyDepth(key1, 1)
	assert.Equal(t, rootPhase1, mt.Root().Bytes())

	err = mt.AddWord(key2, &zkt.Byte32{131})
	assert.Nil(t, err)
	assert.Equal(t, rootPhase2, mt.Root().Bytes())
	assertKeyDepth(key1, 8)

	// delete node with parent sibling (fail before a410f14)
	key3 := zkt.NewByte32FromBytes([]byte{19}) //0b10011
	err = mt.AddWord(key3, &zkt.Byte32{19})
	assert.Nil(t, err)

	err = mt.DeleteWord(key3)
	assert.Nil(t, err)
	assertKeyDepth(key1, 8)
	assert.Equal(t, rootPhase2, mt.Root().Bytes())

	key4 := zkt.NewByte32FromBytes([]byte{4}) //0b100, so it is 2 level node (fail before d1c735)
	err = mt.AddWord(key4, &zkt.Byte32{4})
	assert.Nil(t, err)

	assertKeyDepth(key4, 2)

	err = mt.DeleteWord(key4)
	assert.Nil(t, err)
	assert.Equal(t, rootPhase2, mt.Root().Bytes())
}
