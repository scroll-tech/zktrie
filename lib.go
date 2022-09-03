package main

/*
#include <stdio.h>

typedef char* (*hashF)(unsigned char*, unsigned char*, unsigned char*);

extern hashF hash_scheme;

char* bridge_hash(unsigned char* a, unsigned char* b, unsigned char* out);
void init_hash_scheme(hashF f);

*/
import "C"
import (
	"errors"
	"math/big"
	"unsafe"

	zkt "github.com/scroll-tech/zktrie-util/types"
)

var zeros = [32]byte{}

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

// currently it is caller's responsibility to distinguish what
// the returned buffer is (byte32 or account data)
func NewTrie(C.int, *C.char) unsafe.Pointer {
	return nil
}

// currently it is caller's responsibility to distinguish what
// the returned buffer is (byte32 or account data)
func TrieGet(*C.char, C.int, *C.char) unsafe.Pointer {
	return nil
}

func main() {}
