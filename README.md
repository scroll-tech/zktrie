# zktrie

zktrie is a binary poseidon trie used in Scroll Network.

Go and Rust implementations are provided inside this repo.

## Design Doc

See the technical [docs here](docs/zktrie.md).

## Example codes

[Rust example code](https://github.com/scroll-tech/stateless-block-verifier/blob/56b4aaf1d89a297a16a2934f579a116de024d213/src/executor.rs#L103)  
[Go example code](https://github.com/scroll-tech/go-ethereum/blob/develop/trie/zk_trie.go)

## Rust Usage

We must init the crate with a poseidon hash scheme before any actions.  [This](https://github.com/scroll-tech/zkevm-circuits/blob/e5c5522d544ce936290ef53e00c2d17a0e9b8d0b/zktrie/src/state/builder.rs#L17) is an example


All the zktrie can share one underlying database, which can be initialized by putting the encoded trie node data directly

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


## License

Licensed under either of

- Apache License 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
- MIT License (http://opensource.org/licenses/MIT)

at your discretion.
