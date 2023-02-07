package trie

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/big"

	zkt "github.com/scroll-tech/zktrie/types"
)

const (
	// proofFlagsLen is the byte length of the flags in the proof header
	// (first 32 bytes).
	proofFlagsLen = 2
)

var (
	// ErrNodeKeyAlreadyExists is used when a node key already exists.
	ErrInvalidField = errors.New("Key not inside the Finite Field")
	// ErrNodeKeyAlreadyExists is used when a node key already exists.
	ErrNodeKeyAlreadyExists = errors.New("key already exists")
	// ErrKeyNotFound is used when a key is not found in the ZkTrieImpl.
	ErrKeyNotFound = errors.New("key not found in ZkTrieImpl")
	// ErrNodeBytesBadSize is used when the data of a node has an incorrect
	// size and can't be parsed.
	ErrNodeBytesBadSize = errors.New("node data has incorrect size in the DB")
	// ErrReachedMaxLevel is used when a traversal of the MT reaches the
	// maximum level.
	ErrReachedMaxLevel = errors.New("reached maximum level of the merkle tree")
	// ErrInvalidNodeFound is used when an invalid node is found and can't
	// be parsed.
	ErrInvalidNodeFound = errors.New("found an invalid node in the DB")
	// ErrInvalidProofBytes is used when a serialized proof is invalid.
	ErrInvalidProofBytes = errors.New("the serialized proof is invalid")
	// ErrEntryIndexAlreadyExists is used when the entry index already
	// exists in the tree.
	ErrEntryIndexAlreadyExists = errors.New("the entry index already exists in the tree")
	// ErrNotWritable is used when the ZkTrieImpl is not writable and a
	// write function is called
	ErrNotWritable = errors.New("merkle Tree not writable")

	dbKeyRootNode = []byte("currentroot")
)

// ZkTrieImpl is the struct with the main elements of the ZkTrieImpl
type ZkTrieImpl struct {
	db        ZktrieDatabase
	rootHash  *zkt.Hash
	writable  bool
	maxLevels int
	Debug     bool
}

func NewZkTrieImpl(storage ZktrieDatabase, maxLevels int) (*ZkTrieImpl, error) {
	return NewZkTrieImplWithRoot(storage, &zkt.HashZero, maxLevels)
}

// NewZkTrieImplWithRoot loads a new ZkTrieImpl. If in the storage already exists one
// will open that one, if not, will create a new one.
func NewZkTrieImplWithRoot(storage ZktrieDatabase, root *zkt.Hash, maxLevels int) (*ZkTrieImpl, error) {
	mt := ZkTrieImpl{db: storage, maxLevels: maxLevels, writable: true}
	mt.rootHash = root
	if *root != zkt.HashZero {
		_, err := mt.GetNode(mt.rootHash)
		if err != nil {
			return nil, err
		}
	}
	return &mt, nil
}

// Root returns the MerkleRoot
func (mt *ZkTrieImpl) Root() *zkt.Hash {
	if mt.Debug {
		_, err := mt.GetNode(mt.rootHash)
		if err != nil {
			panic(fmt.Errorf("load trie root failed hash %v", mt.rootHash.Bytes()))
		}
	}
	return mt.rootHash
}

// MaxLevels returns the MT maximum level
func (mt *ZkTrieImpl) MaxLevels() int {
	return mt.maxLevels
}

// TryUpdate updates a nodeKey & value into the ZkTrieImpl. Where the `k` determines the
// path from the Root to the Leaf. This also return the updated leaf node
func (mt *ZkTrieImpl) TryUpdate(nodeKey *zkt.Hash, vFlag uint32, vPreimage []zkt.Byte32) error {
	// verify that the ZkTrieImpl is writable
	if !mt.writable {
		return ErrNotWritable
	}

	// verify that k are valid and fit inside the Finite Field.
	if !zkt.CheckBigIntInField(nodeKey.BigInt()) {
		return ErrInvalidField
	}

	newLeafNode := NewLeafNode(nodeKey, vFlag, vPreimage)
	path := getPath(mt.maxLevels, nodeKey[:])

	// precalc NodeHash of new leaf here
	if _, err := newLeafNode.NodeHash(); err != nil {
		return err
	}

	newRootHash, err := mt.addLeaf(newLeafNode, mt.rootHash, 0, path, true)
	// sanity check
	if err == ErrEntryIndexAlreadyExists {
		panic("Encounter unexpected errortype: ErrEntryIndexAlreadyExists")
	} else if err != nil {
		return err
	}
	mt.rootHash = newRootHash
	err = mt.dbInsert(dbKeyRootNode, DBEntryTypeRoot, mt.rootHash[:])
	if err != nil {
		return err
	}

	return nil
}

// pushLeaf recursively pushes an existing oldLeaf down until its path diverges
// from newLeaf, at which point both leafs are stored, all while updating the
// path. pushLeaf returns the node hash of the parent of the oldLeaf and newLeaf
func (mt *ZkTrieImpl) pushLeaf(newLeaf *Node, oldLeaf *Node, lvl int,
	pathNewLeaf []bool, pathOldLeaf []bool) (*zkt.Hash, error) {
	if lvl > mt.maxLevels-2 {
		return nil, ErrReachedMaxLevel
	}
	var newParentNode *Node
	if pathNewLeaf[lvl] == pathOldLeaf[lvl] { // We need to go deeper!
		nextKey, err := mt.pushLeaf(newLeaf, oldLeaf, lvl+1, pathNewLeaf, pathOldLeaf)
		if err != nil {
			return nil, err
		}
		if pathNewLeaf[lvl] { // go right
			newParentNode = NewParentNode(&zkt.HashZero, nextKey)
		} else { // go left
			newParentNode = NewParentNode(nextKey, &zkt.HashZero)
		}
		return mt.addNode(newParentNode)
	}
	oldLeafHash, err := oldLeaf.NodeHash()
	if err != nil {
		return nil, err
	}
	newLeafHash, err := newLeaf.NodeHash()
	if err != nil {
		return nil, err
	}

	if pathNewLeaf[lvl] {
		newParentNode = NewParentNode(oldLeafHash, newLeafHash)
	} else {
		newParentNode = NewParentNode(newLeafHash, oldLeafHash)
	}
	// We can add newLeaf now.  We don't need to add oldLeaf because it's
	// already in the tree.
	_, err = mt.addNode(newLeaf)
	if err != nil {
		return nil, err
	}
	return mt.addNode(newParentNode)
}

// addLeaf recursively adds a newLeaf in the MT while updating the path, and returns the node hash
// of the new added leaf.
func (mt *ZkTrieImpl) addLeaf(newLeaf *Node, key *zkt.Hash,
	lvl int, path []bool, forceUpdate bool) (*zkt.Hash, error) {
	var err error
	var nextKey *zkt.Hash
	if lvl > mt.maxLevels-1 {
		return nil, ErrReachedMaxLevel
	}
	n, err := mt.GetNode(key)
	if err != nil {
		fmt.Printf("addLeaf:GetNode err %v key %v root %v level %v\n", err, key, mt.rootHash, lvl)
		fmt.Printf("root %v\n", mt.Root())
		return nil, err
	}
	switch n.Type {
	case NodeTypeEmpty:
		// We can add newLeaf now
		{
			r, e := mt.addNode(newLeaf)
			if e != nil {
				fmt.Println("err on NodeTypeEmpty mt.addNode ", e)
			}
			return r, e
		}
	case NodeTypeLeaf:
		// Check if leaf node found contains the leaf node we are
		// trying to add
		if bytes.Equal(n.NodeKey[:], newLeaf.NodeKey[:]) {
			hash, err := n.NodeHash()
			if err != nil {
				fmt.Println("err on obtain key of duplicated entry", err)
				return nil, err
			}
			if bytes.Equal(hash[:], newLeaf.nodeHash[:]) {
				// do nothing, duplicate entry
				// FIXME more optimization may needed here
				return hash, nil
			} else if forceUpdate {
				return mt.updateNode(newLeaf)
			}

			fmt.Printf("ErrEntryIndexAlreadyExists nodeKey %v n.Key() %v newLeaf.Key() %v\n",
				n.NodeKey, hash, newLeaf.nodeHash)
			return nil, ErrEntryIndexAlreadyExists

		}
		pathOldLeaf := getPath(mt.maxLevels, n.NodeKey[:])
		// We need to push newLeaf down until its path diverges from
		// n's path
		return mt.pushLeaf(newLeaf, n, lvl, path, pathOldLeaf)
	case NodeTypeParent:
		// We need to go deeper, continue traversing the tree, left or
		// right depending on path
		var newParentNode *Node
		if path[lvl] { // go right
			nextKey, err = mt.addLeaf(newLeaf, n.ChildR, lvl+1, path, forceUpdate)
			newParentNode = NewParentNode(n.ChildL, nextKey)
		} else { // go left
			nextKey, err = mt.addLeaf(newLeaf, n.ChildL, lvl+1, path, forceUpdate)
			newParentNode = NewParentNode(nextKey, n.ChildR)
		}
		if err != nil {
			fmt.Printf("addLeaf: GetNode err %v level %v\n", err, lvl)
			return nil, err
		}
		// Update the node to reflect the modified child
		return mt.addNode(newParentNode)
	default:
		return nil, ErrInvalidNodeFound
	}
}

// addNode adds a node into the MT.  Empty nodes are not stored in the tree;
// they are all the same and assumed to always exist.
func (mt *ZkTrieImpl) addNode(n *Node) (*zkt.Hash, error) {
	// verify that the ZkTrieImpl is writable
	if !mt.writable {
		return nil, ErrNotWritable
	}
	if n.Type == NodeTypeEmpty {
		return n.NodeHash()
	}
	hash, err := n.NodeHash()
	if err != nil {
		return nil, err
	}
	v := n.CanonicalValue()
	// Check that the node key doesn't already exist
	oldV, err := mt.db.Get(hash[:])
	if err == nil {
		if !bytes.Equal(oldV, v) {
			fmt.Printf("Encounter conflicted node hash: %x, old value %x and new %x\n", hash, oldV, v)
			return nil, ErrNodeKeyAlreadyExists
		} else {
			// duplicated
			return hash, nil
		}
	}
	err = mt.db.Put(hash[:], v)
	return hash, err
}

// updateNode updates an existing node in the MT.  Empty nodes are not stored
// in the tree; they are all the same and assumed to always exist.
func (mt *ZkTrieImpl) updateNode(n *Node) (*zkt.Hash, error) {
	// verify that the ZkTrieImpl is writable
	if !mt.writable {
		return nil, ErrNotWritable
	}
	if n.Type == NodeTypeEmpty {
		return n.NodeHash()
	}
	hash, err := n.NodeHash()
	if err != nil {
		return nil, err
	}
	v := n.CanonicalValue()
	err = mt.db.Put(hash[:], v)
	return hash, err
}

func (mt *ZkTrieImpl) tryGet(nodeKey *zkt.Hash) (*Node, []*zkt.Hash, error) {

	path := getPath(mt.maxLevels, nodeKey[:])
	nextHash := mt.rootHash
	var siblings []*zkt.Hash
	for i := 0; i < mt.maxLevels; i++ {
		n, err := mt.GetNode(nextHash)
		if err != nil {
			return nil, nil, err
		}
		switch n.Type {
		case NodeTypeEmpty:
			return NewEmptyNode(), siblings, ErrKeyNotFound
		case NodeTypeLeaf:
			if bytes.Equal(nodeKey[:], n.NodeKey[:]) {
				return n, siblings, nil
			}
			return n, siblings, ErrKeyNotFound
		case NodeTypeParent:
			if path[i] {
				nextHash = n.ChildR
				siblings = append(siblings, n.ChildL)
			} else {
				nextHash = n.ChildL
				siblings = append(siblings, n.ChildR)
			}
		default:
			return nil, nil, ErrInvalidNodeFound
		}
	}

	return nil, siblings, ErrReachedMaxLevel
}

// TryGet returns the value for key stored in the trie.
// The value bytes must not be modified by the caller.
// If a node was not found in the database, a MissingNodeError is returned.
func (mt *ZkTrieImpl) TryGet(nodeKey *zkt.Hash) ([]byte, error) {

	node, _, err := mt.tryGet(nodeKey)
	if err == ErrKeyNotFound {
		// according to https://github.com/ethereum/go-ethereum/blob/37f9d25ba027356457953eab5f181c98b46e9988/trie/trie.go#L135
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return node.Data(), nil
}

// Delete removes the specified Key from the ZkTrieImpl and updates the path
// from the deleted key to the Root with the new values.  This method removes
// the key from the ZkTrieImpl, but does not remove the old nodes from the
// key-value database; this means that if the tree is accessed by an old Root
// where the key was not deleted yet, the key will still exist. If is desired
// to remove the key-values from the database that are not under the current
// Root, an option could be to dump all the leafs (using mt.DumpLeafs) and
// import them in a new ZkTrieImpl in a new database (using
// mt.ImportDumpedLeafs), but this will lose all the Root history of the
// ZkTrieImpl
func (mt *ZkTrieImpl) TryDelete(nodeKey *zkt.Hash) error {
	// verify that the ZkTrieImpl is writable
	if !mt.writable {
		return ErrNotWritable
	}

	// verify that k is valid and fit inside the Finite Field.
	if !zkt.CheckBigIntInField(nodeKey.BigInt()) {
		return ErrInvalidField
	}

	path := getPath(mt.maxLevels, nodeKey[:])

	nextHash := mt.rootHash
	siblings := []*zkt.Hash{}
	for i := 0; i < mt.maxLevels; i++ {
		n, err := mt.GetNode(nextHash)
		if err != nil {
			return err
		}
		switch n.Type {
		case NodeTypeEmpty:
			return ErrKeyNotFound
		case NodeTypeLeaf:
			if bytes.Equal(nodeKey[:], n.NodeKey[:]) {
				// remove and go up with the sibling
				err = mt.rmAndUpload(path, nodeKey, siblings)
				return err
			}
			return ErrKeyNotFound
		case NodeTypeParent:
			if path[i] {
				nextHash = n.ChildR
				siblings = append(siblings, n.ChildL)
			} else {
				nextHash = n.ChildL
				siblings = append(siblings, n.ChildR)
			}
		default:
			return ErrInvalidNodeFound
		}
	}

	return ErrKeyNotFound
}

// rmAndUpload removes the key, and goes up until the root updating all the
// nodes with the new values.
func (mt *ZkTrieImpl) rmAndUpload(path []bool, nodeKey *zkt.Hash, siblings []*zkt.Hash) (err error) {

	var finalRoot *zkt.Hash
	defer func() {
		if err == nil {
			if finalRoot == nil {
				panic("finalRoot is not set yet")
			}
			mt.rootHash = finalRoot
			err = mt.dbInsert(dbKeyRootNode, DBEntryTypeRoot, mt.rootHash[:])
		}
	}()

	// if we have no siblings, it mean the target node is the only node in trie
	if len(siblings) == 0 {
		finalRoot = &zkt.HashZero
		return
	}

	toUpload := siblings[len(siblings)-1]
	if uploadNode, getErr := mt.GetNode(toUpload); getErr != nil {
		return getErr
	} else if uploadNode.Type == NodeTypeParent {
		// for parent node, simply recalc the path
		finalRoot, err = mt.recalculatePathUntilRoot(path, NewEmptyNode(),
			siblings)
		return
	}

	if len(siblings) < 2 { //nolint:gomnd
		finalRoot = siblings[0]
		return
	}

	for i := len(siblings) - 2; i >= 0; i-- { //nolint:gomnd
		if !bytes.Equal(siblings[i][:], zkt.HashZero[:]) {
			var newNode *Node
			if path[i] {
				newNode = NewParentNode(siblings[i], toUpload)
			} else {
				newNode = NewParentNode(toUpload, siblings[i])
			}
			_, err = mt.addNode(newNode)
			if err != ErrNodeKeyAlreadyExists && err != nil {
				return err
			}
			// go up until the root
			finalRoot, err = mt.recalculatePathUntilRoot(path, newNode,
				siblings[:i])
			return
		}
	}

	// if all sibling is zero, stop and store the sibling of the
	// deleted leaf as root
	finalRoot = toUpload
	return
}

// recalculatePathUntilRoot recalculates the nodes until the Root
func (mt *ZkTrieImpl) recalculatePathUntilRoot(path []bool, node *Node,
	siblings []*zkt.Hash) (*zkt.Hash, error) {
	for i := len(siblings) - 1; i >= 0; i-- {
		nodeHash, err := node.NodeHash()
		if err != nil {
			return nil, err
		}
		if path[i] {
			node = NewParentNode(siblings[i], nodeHash)
		} else {
			node = NewParentNode(nodeHash, siblings[i])
		}
		_, err = mt.addNode(node)
		if err != ErrNodeKeyAlreadyExists && err != nil {
			return nil, err
		}
	}

	// return last node added, which is the root
	nodeHash, err := node.NodeHash()
	return nodeHash, err
}

// dbInsert is a helper function to insert a node into a key in an open db
// transaction.
func (mt *ZkTrieImpl) dbInsert(k []byte, t NodeType, data []byte) error {
	v := append([]byte{byte(t)}, data...)
	return mt.db.Put(k, v)
}

// GetLeafNode is more underlying method than TryGet, which obtain an leaf node
// or nil if not exist
func (mt *ZkTrieImpl) GetLeafNode(key *zkt.Hash) (*Node, error) {
	n, _, err := mt.tryGet(key)
	return n, err
}

// GetNode gets a node by key from the MT.  Empty nodes are not stored in the
// tree; they are all the same and assumed to always exist.
// <del>for non exist key, return (NewEmptyNode(), nil)</del>
func (mt *ZkTrieImpl) GetNode(key *zkt.Hash) (*Node, error) {
	if bytes.Equal(key[:], zkt.HashZero[:]) {
		return NewEmptyNode(), nil
	}
	nBytes, err := mt.db.Get(key[:])
	if err == ErrKeyNotFound {
		//return NewEmptyNode(), nil
		return nil, ErrKeyNotFound
	} else if err != nil {
		return nil, err
	}
	return NewNodeFromBytes(nBytes)
}

// getPath returns the binary path, from the root to the leaf.
func getPath(numLevels int, k []byte) []bool {
	path := make([]bool, numLevels)
	for n := 0; n < numLevels; n++ {
		path[n] = zkt.TestBit(k[:], uint(n))
	}
	return path
}

// NodeAux contains the auxiliary node used in a non-existence proof.
type NodeAux struct {
	Key   *zkt.Hash
	Value *zkt.Hash
}

// Proof defines the required elements for a MT proof of existence or
// non-existence.
type Proof struct {
	// existence indicates wether this is a proof of existence or
	// non-existence.
	Existence bool
	// depth indicates how deep in the tree the proof goes.
	depth uint
	// notempties is a bitmap of non-empty Siblings found in Siblings.
	notempties [zkt.HashByteLen - proofFlagsLen]byte
	// Siblings is a list of non-empty sibling keys.
	Siblings []*zkt.Hash
	// Key is the key of leaf in existence case
	Key     *zkt.Hash
	NodeAux *NodeAux
}

// BuildZkTrieProof prove uniformed way to turn some data collections into Proof struct
func BuildZkTrieProof(rootHash *zkt.Hash, k *big.Int, lvl int, getNode func(key *zkt.Hash) (*Node, error)) (*Proof,
	*Node, error) {

	p := &Proof{}
	var siblingHash *zkt.Hash

	kHash := zkt.NewHashFromBigInt(k)
	path := getPath(lvl, kHash[:])

	nextHash := rootHash
	for p.depth = 0; p.depth < uint(lvl); p.depth++ {
		n, err := getNode(nextHash)
		if err != nil {
			return nil, nil, err
		}
		switch n.Type {
		case NodeTypeEmpty:
			return p, n, nil
		case NodeTypeLeaf:
			if bytes.Equal(kHash[:], n.NodeKey[:]) {
				p.Existence = true
				return p, n, nil
			}
			// We found a leaf whose entry didn't match hIndex
			p.NodeAux = &NodeAux{Key: n.NodeKey, Value: n.valueHash}
			return p, n, nil
		case NodeTypeParent:
			if path[p.depth] {
				nextHash = n.ChildR
				siblingHash = n.ChildL
			} else {
				nextHash = n.ChildL
				siblingHash = n.ChildR
			}
		default:
			return nil, nil, ErrInvalidNodeFound
		}
		if !bytes.Equal(siblingHash[:], zkt.HashZero[:]) {
			zkt.SetBitBigEndian(p.notempties[:], p.depth)
			p.Siblings = append(p.Siblings, siblingHash)
		}
	}
	return nil, nil, ErrKeyNotFound

}

// VerifyProof verifies the Merkle Proof for the entry and root.
func VerifyProofZkTrie(rootHash *zkt.Hash, proof *Proof, node *Node) bool {
	nodeHash, err := node.NodeHash()
	if err != nil {
		return false
	}

	rootFromProof, err := proof.Verify(nodeHash, node.NodeKey)
	if err != nil {
		return false
	}
	return bytes.Equal(rootHash[:], rootFromProof[:])
}

// Verify the proof and calculate the root, nodeHash can be nil when try to verify
// an nonexistent proof
func (proof *Proof) Verify(nodeHash, nodeKey *zkt.Hash) (*zkt.Hash, error) {
	if proof.Existence {
		if nodeHash == nil {
			return nil, ErrKeyNotFound
		}
		return proof.rootFromProof(nodeHash, nodeKey)
	} else {
		if proof.NodeAux == nil {
			return proof.rootFromProof(&zkt.HashZero, nodeKey)
		} else {
			if bytes.Equal(nodeKey[:], proof.NodeAux.Key[:]) {
				return nil, fmt.Errorf("non-existence proof being checked against hIndex equal to nodeAux")
			}
			midHash, err := LeafHash(proof.NodeAux.Key, proof.NodeAux.Value)
			if err != nil {
				return nil, err
			}
			return proof.rootFromProof(midHash, nodeKey)
		}
	}

}

func (proof *Proof) rootFromProof(nodeHash, nodeKey *zkt.Hash) (*zkt.Hash, error) {
	var err error

	sibIdx := len(proof.Siblings) - 1
	path := getPath(int(proof.depth), nodeKey[:])
	var siblingHash *zkt.Hash
	for lvl := int(proof.depth) - 1; lvl >= 0; lvl-- {
		if zkt.TestBitBigEndian(proof.notempties[:], uint(lvl)) {
			siblingHash = proof.Siblings[sibIdx]
			sibIdx--
		} else {
			siblingHash = &zkt.HashZero
		}
		if path[lvl] {
			nodeHash, err = NewParentNode(siblingHash, nodeHash).NodeHash()
			if err != nil {
				return nil, err
			}
		} else {
			nodeHash, err = NewParentNode(nodeHash, siblingHash).NodeHash()
			if err != nil {
				return nil, err
			}
		}
	}
	return nodeHash, nil
}

// walk is a helper recursive function to iterate over all tree branches
func (mt *ZkTrieImpl) walk(key *zkt.Hash, f func(*Node)) error {
	n, err := mt.GetNode(key)
	if err != nil {
		return err
	}
	switch n.Type {
	case NodeTypeEmpty:
		f(n)
	case NodeTypeLeaf:
		f(n)
	case NodeTypeParent:
		f(n)
		if err := mt.walk(n.ChildL, f); err != nil {
			return err
		}
		if err := mt.walk(n.ChildR, f); err != nil {
			return err
		}
	default:
		return ErrInvalidNodeFound
	}
	return nil
}

// Walk iterates over all the branches of a ZkTrieImpl with the given rootHash
// if rootHash is nil, it will get the current RootHash of the current state of
// the ZkTrieImpl.  For each node, it calls the f function given in the
// parameters.  See some examples of the Walk function usage in the
// ZkTrieImpl.go and merkletree_test.go
func (mt *ZkTrieImpl) Walk(rootHash *zkt.Hash, f func(*Node)) error {
	if rootHash == nil {
		rootHash = mt.Root()
	}
	err := mt.walk(rootHash, f)
	return err
}

// GraphViz uses Walk function to generate a string GraphViz representation of
// the tree and writes it to w
func (mt *ZkTrieImpl) GraphViz(w io.Writer, rootHash *zkt.Hash) error {
	fmt.Fprintf(w, `digraph hierarchy {
node [fontname=Monospace,fontsize=10,shape=box]
`)
	cnt := 0
	var errIn error
	err := mt.Walk(rootHash, func(n *Node) {
		hash, err := n.NodeHash()
		if err != nil {
			errIn = err
		}
		switch n.Type {
		case NodeTypeEmpty:
		case NodeTypeLeaf:
			fmt.Fprintf(w, "\"%v\" [style=filled];\n", hash.String())
		case NodeTypeParent:
			lr := [2]string{n.ChildL.String(), n.ChildR.String()}
			emptyNodes := ""
			for i := range lr {
				if lr[i] == "0" {
					lr[i] = fmt.Sprintf("empty%v", cnt)
					emptyNodes += fmt.Sprintf("\"%v\" [style=dashed,label=0];\n", lr[i])
					cnt++
				}
			}
			fmt.Fprintf(w, "\"%v\" -> {\"%v\" \"%v\"}\n", hash.String(), lr[0], lr[1])
			fmt.Fprint(w, emptyNodes)
		default:
		}
	})
	fmt.Fprintf(w, "}\n")
	if errIn != nil {
		return errIn
	}
	return err
}

// PrintGraphViz prints directly the GraphViz() output
func (mt *ZkTrieImpl) PrintGraphViz(rootHash *zkt.Hash) error {
	if rootHash == nil {
		rootHash = mt.Root()
	}
	w := bytes.NewBufferString("")
	fmt.Fprintf(w,
		"--------\nGraphViz of the ZkTrieImpl with RootHash "+rootHash.BigInt().String()+"\n")
	err := mt.GraphViz(w, nil)
	if err != nil {
		return err
	}
	fmt.Fprintf(w,
		"End of GraphViz of the ZkTrieImpl with RootHash "+rootHash.BigInt().String()+"\n--------\n")

	fmt.Println(w)
	return nil
}
