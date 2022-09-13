# zktrie

Wrap the zktrie go module in [l2geth](http://github.com/scroll-tech/go-ethereum) for rust

## Usage

We must init the crate with a poseidon hash scheme before any actions:

```rust

extern "C" fn hash_scheme(a: *const u8, b: *const u8, out: *mut u8) -> *const i8 {
    /*
        implement of poseidon hash which accept two 32-bytes buffer `a` and `b` as integer of finite field
        
        and write the output hashed integer to the mutable 32-bytes buffer `out`

        for any error, return them via a message with `&'static str`, or return ptr::null for success

        **all the integer is little endian represent**
    */
}

zktrie_util::init_hash_scheme(hash_scheme);

```

All the zktrie can share one unerlying database, which can be initialized by putting the encoded trie node data directly

```rust

let mut db = ZkMemoryDb::new();

/* for some trie node data encoded as bytes `buf` */
db.add_node_bytes(&buf).unwrap();

```

We must prove the root for a trie to create it, the corresponding root node must have been input in the database

```rust
let root = hex::decode("079a038fbf78f25a2590e5a1d2fa34ce5e5f30e9a332713b43fa0e51b8770ab8")
    .unwrap();
let root: Hash = root.as_slice().try_into().unwrap();

let mut trie = db.new_trie(&root).unwrap();
```

The trie can be updated by a single 32-bytes buffer if it is storage trie, or a `[[u8;32];4]` array for the account data `{nonce, balance, codehash, storageRoot}` if it is account trie

```rust
let acc_buf = hex::decode("4cb1aB63aF5D8931Ce09673EbD8ae2ce16fD6571").unwrap();
let code_hash: [u8;32] = hex::decode("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").unwrap().as_slice().try_into().unwrap();

/* update an externally-owned account (so its storageRoot is all zero and code_hash equal to keccak256(nil)) */
let newacc: AccountData = [nonce, balance, code_hash, [0; FIELDSIZE]];
trie.update_account(&acc_buf, &newacc).unwrap();

```

The root and mpt path for an address can be query from trie by `ZkTrie::root` and `ZkTrie::prove`

## Installation

Add `Cargo.toml` under `[dependencies]`:

```toml
[dependencies]
zktrie = { git = "https://https://github.com/scroll-tech/zktrie.git" }
```

## License

Licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

