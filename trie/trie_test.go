package trie

import (
	"fmt"
	"math/big"
	"testing"

	zkt "github.com/scroll-tech/zktrie/types"
)

func setupENV() {
	zkt.InitHashScheme(func(arr []*big.Int) (*big.Int, error) {
		lcEff := big.NewInt(65536)
		qString := "21888242871839275222246405745257275088548364400416034343698204186575808495617"
		Q, ok := new(big.Int).SetString(qString, 10)
		if !ok {
			panic(fmt.Sprintf("Bad base 10 string %s", qString))
		}
		sum := big.NewInt(0)
		for _, bi := range arr {
			nbi := new(big.Int).Mul(bi, bi)
			sum = sum.Mul(sum, sum)
			sum = sum.Mul(sum, lcEff)
			sum = sum.Add(sum, nbi)
		}
		return sum.Mod(sum, Q), nil
	})
}

func TestZkTrie(t *testing.T) {
	setupENV()

	t.Run("TestDatabase", testDatabase)
	t.Run("TestMerkleTree_Init", testMerkleTree_Init)
	t.Run("TestMerkleTree_AddUpdateGetWord", testMerkleTree_AddUpdateGetWord)
	t.Run("TestMerkleTree_Deletion", testMerkleTree_Deletion)
	t.Run("TestZkTrieImpl_Add", testZkTrieImpl_Add)
	t.Run("TestZkTrieImpl_Update", testZkTrieImpl_Update)
	t.Run("TestZkTrieImpl_Delete", testZkTrieImpl_Delete)
	t.Run("TestMerkleTree_BuildAndVerifyZkTrieProof", testMerkleTree_BuildAndVerifyZkTrieProof)
	t.Run("TestMerkleTree_GraphViz", testMerkleTree_GraphViz)
	t.Run("TestNewZkTrie", testNewZkTrie)
	t.Run("TestZkTrie_GetUpdateDelete", testZkTrie_GetUpdateDelete)
	t.Run("TestZkTrie_Copy", testZkTrie_Copy)
	t.Run("TestZkTrie_ProveAndProveWithDeletion", testZkTrie_ProveAndProveWithDeletion)
	t.Run("TestDecodeSMTProof", testDecodeSMTProof)
	t.Run("TestNewNode", testNewNode)
	t.Run("TestNewNodeFromBytes", testNewNodeFromBytes)
	t.Run("TestNodeValueAndData", testNodeValueAndData)
	t.Run("TestNodeString", testNodeString)
}
