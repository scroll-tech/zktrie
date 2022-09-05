package main

/*
#include <stdio.h>
#include <stdlib.h>

typedef char* (*hashF)(unsigned char*, unsigned char*, unsigned char*);
typedef void (*proveWriteF)(unsigned char*, int, void*);

extern hashF hash_scheme;

char* bridge_hash(unsigned char* a, unsigned char* b, unsigned char* out);
void init_hash_scheme(hashF f);
void bridge_prove_write(proveWriteF f, unsigned char* key, unsigned char* val, int size, void* param);

*/
import "C"
import (
	"errors"
	"math/big"
	"sync"
	"unsafe"

	"github.com/scroll-tech/zktrie-util/trie"
	zkt "github.com/scroll-tech/zktrie-util/types"
)

var zeros = [32]byte{}

type globalCollect struct {
	sync.Mutex
	dbs   map[*trie.Database]struct{}
	tries map[*trie.ZkTrie]struct{}
}

var globalCollection *globalCollect

func init() {
	globalCollection = &globalCollect{
		dbs:   make(map[*trie.Database]struct{}),
		tries: make(map[*trie.ZkTrie]struct{}),
	}
}

func hash_external(inp []*big.Int) (*big.Int, error) {
	if len(inp) != 2 {
		return big.NewInt(0), errors.New("invalid input size")
	}
	a := zkt.ReverseByteOrder(inp[0].Bytes())
	b := zkt.ReverseByteOrder(inp[1].Bytes())

	a = append(a, zeros[0:(32-len(a))]...)
	b = append(b, zeros[0:(32-len(a))]...)
	c := make([]byte, 32)

	err := C.bridge_hash((*C.uchar)(&a[0]), (*C.uchar)(&b[0]), (*C.uchar)(&c[0]))

	if err != nil {
		return big.NewInt(0), errors.New(C.GoString(err))
	}

	return big.NewInt(0).SetBytes(zkt.ReverseByteOrder(c)), nil
}

//export TestHashScheme
func TestHashScheme() {
	h1, err := hash_external([]*big.Int{big.NewInt(1), big.NewInt(2)})
	if err != nil {
		panic(err)
	}
	expected := big.NewInt(0)
	expected.UnmarshalText([]byte("7853200120776062878684798364095072458815029376092732009249414926327459813530"))
	if h1.Cmp(expected) != 0 {
		panic(h1)
	}
}

// notice the function must use C calling convention
//export InitHashScheme
func InitHashScheme(f unsafe.Pointer) {
	hash_f := C.hashF(f)
	C.init_hash_scheme(hash_f)
}

// create memory db
//export NewMemoryDb
func NewMemoryDb() unsafe.Pointer {
	// it break the cgo's enforcement (C code can not store Go pointer after return)
	// but it should be ok for we have kept reference in the global object
	ret := trie.NewZkTrieMemoryDb()
	globalCollection.Lock()
	defer globalCollection.Unlock()
	globalCollection.dbs[ret] = struct{}{}

	return unsafe.Pointer(ret)
}

// free created memory db
//export FreeMemoryDb
func FreeMemoryDb(p unsafe.Pointer) {
	db := (*trie.Database)(p)
	globalCollection.Lock()
	defer globalCollection.Unlock()
	if _, existed := globalCollection.dbs[db]; !existed {
		panic("try free unassigned db object")
	}
	delete(globalCollection.dbs, db)
}

// free buffers being returned, like error strings or trie value
//export FreeBuffer
func FreeBuffer(p unsafe.Pointer) {
	C.free(p)
}

// flush db with encoded trie-node bytes
//export InitDbByNode
func InitDbByNode(pDb unsafe.Pointer, data *C.uchar, sz C.int) *C.char {
	db := (*trie.Database)(pDb)

	bt := C.GoBytes(unsafe.Pointer(data), sz)
	n, err := trie.DecodeSMTProof(bt)
	if err != nil {
		return C.CString(err.Error())
	}

	k, err := n.Key()
	if err != nil {
		return C.CString(err.Error())
	}
	db.Init(k[:], bt)

	return nil

}

// the input root must be 32bytes (or more, but only first 32bytes would be recognized)
//export NewZkTrie
func NewZkTrie(root_c *C.uchar, pDb unsafe.Pointer) unsafe.Pointer {
	db := (*trie.Database)(pDb)
	root := C.GoBytes(unsafe.Pointer(root_c), 32)

	zktrie, err := trie.NewZkTrie(*zkt.NewByte32FromBytes(root), db)
	if err != nil {
		return nil
	}

	globalCollection.Lock()
	defer globalCollection.Unlock()

	globalCollection.tries[zktrie] = struct{}{}

	return unsafe.Pointer(zktrie)
}

// free created zktrie
//export FreeZkTrie
func FreeZkTrie(p unsafe.Pointer) {
	tr := (*trie.ZkTrie)(p)
	globalCollection.Lock()
	defer globalCollection.Unlock()
	if _, existed := globalCollection.tries[tr]; !existed {
		panic("try free unassigned zktrie object")
	}
	delete(globalCollection.tries, tr)
}

// currently it is caller's responsibility to distinguish what
// the returned buffer is byte32 or encoded account data (4x32bytes fields)
//export TrieGet
func TrieGet(p unsafe.Pointer, key_c *C.uchar, key_sz C.int) unsafe.Pointer {
	tr := (*trie.ZkTrie)(p)
	key := C.GoBytes(unsafe.Pointer(key_c), key_sz)

	v, err := tr.TryGet(key)
	if v == nil || err != nil {
		return nil
	}
	//sanity check
	if val_sz := len(v); val_sz != 32 && val_sz != 32*4 {
		// unexpected val size which is to be recognized by caller, so just filter it
		return nil
	}

	return C.CBytes(v)
}

// update only accept encoded buffer, and flag is derived automatically from buffer size (account data or store val)
//export TrieUpdate
func TrieUpdate(p unsafe.Pointer, key_c *C.uchar, key_sz C.int, val_c *C.uchar, val_sz C.int) *C.char {

	if val_sz != 32 && val_sz != 128 {
		return C.CString("unexpected buffer type")
	}

	var vFlag uint32
	if val_sz == 128 {
		vFlag = 4
	} else {
		vFlag = 1
	}

	tr := (*trie.ZkTrie)(p)
	key := C.GoBytes(unsafe.Pointer(key_c), key_sz)
	var vals []zkt.Byte32
	start_ptr := uintptr(unsafe.Pointer(val_c))
	for i := 0; i < int(key_sz); i += 32 {
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
//export TrieDelete
func TrieDelete(p unsafe.Pointer, key_c *C.uchar, key_sz C.int) {
	tr := (*trie.ZkTrie)(p)
	key := C.GoBytes(unsafe.Pointer(key_c), key_sz)
	tr.TryDelete(key)
}

// output prove, only the val part is output for callback
//export TrieProve
func TrieProve(p unsafe.Pointer, key_c *C.uchar, key_sz C.int, callback unsafe.Pointer, cb_param unsafe.Pointer) *C.char {
	tr := (*trie.ZkTrie)(p)
	key := C.GoBytes(unsafe.Pointer(key_c), key_sz)
	err := tr.Prove(key, 0, func(n *trie.Node) error {

		dt := n.Data()

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
	return nil
}

func main() {}
