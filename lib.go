package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef char* (*hashF)(unsigned char*, unsigned char*, unsigned char*);
typedef void (*proveWriteF)(unsigned char*, int, void*);

extern hashF hash_scheme;

char* bridge_hash(unsigned char* a, unsigned char* b, unsigned char* domain, unsigned char* out);
void init_hash_scheme(hashF f);
void bridge_prove_write(proveWriteF f, unsigned char* key, unsigned char* val, int size, void* param);

*/
import "C"
import (
	"errors"
	"fmt"
	"math/big"
	"runtime/cgo"
	"unsafe"

	"github.com/scroll-tech/zktrie/trie"
	zkt "github.com/scroll-tech/zktrie/types"
)

var zeros = [32]byte{}

func hash_external(inp []*big.Int, domain *big.Int) (*big.Int, error) {
	if len(inp) != 2 {
		return big.NewInt(0), errors.New("invalid input size")
	}
	a := zkt.ReverseByteOrder(inp[0].Bytes())
	b := zkt.ReverseByteOrder(inp[1].Bytes())
	dm := zkt.ReverseByteOrder(domain.Bytes())

	a = append(a, zeros[0:(32-len(a))]...)
	b = append(b, zeros[0:(32-len(b))]...)
	dm = append(dm, zeros[0:(32-len(dm))]...)

	c := make([]byte, 32)

	err := C.bridge_hash((*C.uchar)(&a[0]), (*C.uchar)(&b[0]), (*C.uchar)(&dm[0]), (*C.uchar)(&c[0]))

	if err != nil {
		return big.NewInt(0), errors.New(C.GoString(err))
	}

	return big.NewInt(0).SetBytes(zkt.ReverseByteOrder(c)), nil
}

//export TestHashScheme
func TestHashScheme() {
	h1, err := hash_external([]*big.Int{big.NewInt(1), big.NewInt(2)}, big.NewInt(0))
	if err != nil {
		panic(err)
	}
	expected := big.NewInt(0)
	expected.UnmarshalText([]byte("7853200120776062878684798364095072458815029376092732009249414926327459813530"))
	if h1.Cmp(expected) != 0 {
		panic(fmt.Errorf("unexpected poseidon hash value: %s", h1))
	}

	h2, err := hash_external([]*big.Int{big.NewInt(1), big.NewInt(2)}, big.NewInt(256))
	if err != nil {
		panic(err)
	}
	expected.UnmarshalText([]byte("2362370911616048355006851495576377379220050231129891536935411970097789775493"))
	if h2.Cmp(expected) != 0 {
		panic(fmt.Errorf("unexpected poseidon hash value: %s", h1))
	}
}

// notice the function must use C calling convention
//
//export InitHashScheme
func InitHashScheme(f unsafe.Pointer) {
	hash_f := C.hashF(f)
	C.init_hash_scheme(hash_f)
	zkt.InitHashScheme(hash_external)
}

// parse raw bytes and create the trie node
//
//export NewTrieNode
func NewTrieNode(data *C.char, sz C.int) C.uintptr_t {
	bt := C.GoBytes(unsafe.Pointer(data), sz)
	n, err := trie.NewNodeFromBytes(bt)
	if err != nil {
		return 0
	}

	// calculate key for caching
	if _, err := n.NodeHash(); err != nil {
		return 0
	}

	return C.uintptr_t(cgo.NewHandle(n))
}

// obtain the key hash, must be free by caller
//
//export TrieNodeHash
func TrieNodeHash(pN C.uintptr_t) unsafe.Pointer {
	h := cgo.Handle(pN)
	n := h.Value().(*trie.Node)

	hash, _ := n.NodeHash()
	return C.CBytes(hash.Bytes())
}

// obtain the data of node if it is leaf, must be free by caller
// or nil for other type
// if val_sz is not 0 and the value size is not equal to val_sz,
// it is also return nil
//
//export TrieNodeData
func TrieNodeData(pN C.uintptr_t, val_sz C.int) unsafe.Pointer {
	h := cgo.Handle(pN)
	n := h.Value().(*trie.Node)

	if d := n.Data(); d != nil {
		// safety check
		if expected_sz := int(val_sz); expected_sz != 0 && len(d) != int(val_sz) {
			return nil
		}

		return C.CBytes(d)
	} else {
		return nil
	}
}

// test if the node is tip type (i.e. leaf or empty)
//
//export TrieNodeIsTip
func TrieNodeIsTip(pN C.uintptr_t) C.int {
	h := cgo.Handle(pN)
	n := h.Value().(*trie.Node)

	if n.IsTerminal() {
		return 1
	} else {
		return 0
	}
}

// obtain the value hash for leaf node (must be free by caller), or nil for other
//
//export TrieLeafNodeValueHash
func TrieLeafNodeValueHash(pN C.uintptr_t) unsafe.Pointer {
	h := cgo.Handle(pN)
	n := h.Value().(*trie.Node)

	if n.Type != trie.NodeTypeLeaf_New {
		return nil
	}

	valueHash, _ := n.ValueHash()
	return C.CBytes(valueHash.Bytes())
}

// free created trie node
//
//export FreeTrieNode
func FreeTrieNode(p C.uintptr_t) { freeObject(p) }

// create memory db
//
//export NewMemoryDb
func NewMemoryDb() C.uintptr_t {
	// it break the cgo's enforcement (C code can not store Go pointer after return)
	// but it should be ok for we have kept reference in the global object
	ret := trie.NewZkTrieMemoryDb()

	return C.uintptr_t(cgo.NewHandle(ret))
}

func freeObject(p C.uintptr_t) {
	h := cgo.Handle(p)
	h.Delete()
}

// free created memory db
//
//export FreeMemoryDb
func FreeMemoryDb(p C.uintptr_t) { freeObject(p) }

// free created trie
//
//export FreeZkTrie
func FreeZkTrie(p C.uintptr_t) { freeObject(p) }

// free buffers being returned, like error strings or trie value
//
//export FreeBuffer
func FreeBuffer(p unsafe.Pointer) {
	C.free(p)
}

// flush db with encoded trie-node bytes
// used for initialize the database, in a thread-unsafe fashion
//
//export InitDbByNode
func InitDbByNode(pDb C.uintptr_t, data *C.uchar, sz C.int) *C.char {
	h := cgo.Handle(pDb)
	db := h.Value().(*trie.Database)

	bt := C.GoBytes(unsafe.Pointer(data), sz)
	n, err := trie.DecodeSMTProof(bt)
	if err != nil {
		return C.CString(err.Error())
	} else if n == nil {
		//skip magic string
		return nil
	}

	hash, err := n.NodeHash()
	if err != nil {
		return C.CString(err.Error())
	}

	db.Init(hash[:], n.CanonicalValue())
	return nil
}

// the input root must be 32bytes (or more, but only first 32bytes would be recognized)
//
//export NewZkTrie
func NewZkTrie(root_c *C.uchar, pDb C.uintptr_t) C.uintptr_t {
	h := cgo.Handle(pDb)
	db := h.Value().(*trie.Database)
	root := C.GoBytes(unsafe.Pointer(root_c), 32)

	zktrie, err := trie.NewZkTrie(*zkt.NewByte32FromBytes(root), db)
	if err != nil {
		return 0
	}

	return C.uintptr_t(cgo.NewHandle(zktrie))
}

// currently it is caller's responsibility to distinguish what
// the returned buffer is byte32 or encoded account data (4x32bytes fields for original account
// or 6x32bytes fields for 'dual-codehash' extended account)
//
//export TrieGet
func TrieGet(p C.uintptr_t, key_c *C.uchar, key_sz C.int) unsafe.Pointer {
	h := cgo.Handle(p)
	tr := h.Value().(*trie.ZkTrie)
	key := C.GoBytes(unsafe.Pointer(key_c), key_sz)

	v, err := tr.TryGet(key)
	if v == nil || err != nil {
		return nil
	}
	//sanity check
	if val_sz := len(v); val_sz != 32 && val_sz != 32*4 && val_sz != 32*5 {
		// unexpected val size which is to be recognized by caller, so just filter it
		return nil
	}

	return C.CBytes(v)
}

// variant of TrieGet that specifies the expected value size for safety; if the actual value
// size does not match the expected value size, it returns nil instead of leading to undefined
// behavior.
//
//export TrieGetSize
func TrieGetSize(p C.uintptr_t, key_c *C.uchar, key_sz C.int, val_sz C.int) unsafe.Pointer {
	h := cgo.Handle(p)
	tr := h.Value().(*trie.ZkTrie)
	key := C.GoBytes(unsafe.Pointer(key_c), key_sz)

	v, err := tr.TryGet(key)
	if v == nil || err != nil {
		return nil
	}

	// safety check
	if len(v) != int(val_sz) {
		return nil
	}

	return C.CBytes(v)
}

// update only accept encoded buffer, and flag is derived automatically from buffer size (account data or store val)
//
//export TrieUpdate
func TrieUpdate(p C.uintptr_t, key_c *C.uchar, key_sz C.int, val_c *C.uchar, val_sz C.int) *C.char {

	if val_sz != 32 && val_sz != 128 && val_sz != 160 {
		return C.CString("unexpected buffer type")
	}

	var vFlag uint32
	if val_sz == 160 {
		vFlag = 8
	} else if val_sz == 128 {
		vFlag = 4
	} else {
		vFlag = 1
	}

	h := cgo.Handle(p)
	tr := h.Value().(*trie.ZkTrie)
	key := C.GoBytes(unsafe.Pointer(key_c), key_sz)
	var vals []zkt.Byte32
	start_ptr := uintptr(unsafe.Pointer(val_c))
	for i := 0; i < int(val_sz); i += 32 {
		vals = append(vals, *zkt.NewByte32FromBytes(C.GoBytes(unsafe.Pointer(start_ptr), 32)))
		start_ptr += 32
	}

	err := tr.TryUpdate(key, vFlag, vals)
	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}

// delete leaf, silently omit any error
//
//export TrieDelete
func TrieDelete(p C.uintptr_t, key_c *C.uchar, key_sz C.int) {
	h := cgo.Handle(p)
	tr := h.Value().(*trie.ZkTrie)
	key := C.GoBytes(unsafe.Pointer(key_c), key_sz)
	tr.TryDelete(key)
}

// output prove, only the val part is output for callback
//
//export TrieProve
func TrieProve(p C.uintptr_t, key_c *C.uchar, key_sz C.int, callback unsafe.Pointer, cb_param unsafe.Pointer) *C.char {
	h := cgo.Handle(p)
	tr := h.Value().(*trie.ZkTrie)
	key := C.GoBytes(unsafe.Pointer(key_c), key_sz)
	s_key, err := zkt.ToSecureKeyBytes(key)
	if err != nil {
		return C.CString(err.Error())
	}

	err = tr.Prove(s_key.Bytes(), 0, func(n *trie.Node) error {

		dt := n.Value()

		C.bridge_prove_write(
			C.proveWriteF(callback),
			nil, //do not need to prove node key
			(*C.uchar)(&dt[0]),
			C.int(len(dt)),
			cb_param,
		)

		return nil
	})
	if err != nil {
		return C.CString(err.Error())
	}

	tailingLine := trie.ProofMagicBytes()
	C.bridge_prove_write(
		C.proveWriteF(callback),
		nil, //do not need to prove node key
		(*C.uchar)(&tailingLine[0]),
		C.int(len(tailingLine)),
		cb_param,
	)

	return nil
}

// obtain the hash
//
//export TrieRoot
func TrieRoot(p C.uintptr_t) unsafe.Pointer {
	h := cgo.Handle(p)
	tr := h.Value().(*trie.ZkTrie)
	return C.CBytes(tr.Hash())
}

func main() {}
