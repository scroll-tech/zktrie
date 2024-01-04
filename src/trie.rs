use crate::types::{Hashable};
use crate::raw::{ZkTrieImpl, ImplError};
use crate::db::ZktrieDatabase;

// ZkTrie wraps a trie with key hashing. In a secure trie, all
// access operations hash the key using keccak256. This prevents
// calling code from creating long chains of nodes that
// increase the access time.
//
// Contrary to a regular trie, a ZkTrie can only be created with
// New and must have an attached database. The database also stores
// the preimage of each key.
//
// ZkTrie is not safe for concurrent use.

#[derive (Clone)]
pub struct ZkTrie<H: Hashable, DB: ZktrieDatabase> {
	tree: ZkTrieImpl<H, DB>,
}

// NODE_KEY_VALID_BYTES is the number of least significant bytes in the node key
// that are considered valid to addressing the leaf node, and thus limits the
// maximum trie depth to NODE_KEY_VALID_BYTES * 8.
// We need to truncate the node key because the key is the output of Poseidon
// hash and the key space doesn't fully occupy the range of power of two. It can
// lead to an ambiguous bit representation of the key in the finite field
// causing a soundness issue in the zk circuit.
const NODE_KEY_VALID_BYTES: u32 = 31;

impl<H: Hashable, DB: ZktrieDatabase> ZkTrie<H, DB> {
	// NewSecure creates a trie
	// SecureBinaryTrie bypasses all the buffer mechanism in *Database, it directly uses the
	// underlying diskdb
	pub fn new_zktrie(root: H, db: DB) -> Result<Self, ImplError> {
		let max_levels = NODE_KEY_VALID_BYTES * 8;
		let tr = ZkTrieImpl::new_zktrie_impl_with_root(db, root, max_levels);
		let t = ZkTrie {
			tree: tr?,
		};
		Ok(t)
	}

	// TryGet returns the value for key stored in the trie.
	// The value bytes must not be modified by the caller.
	// If a node was not found in the database, a MissingNodeError is returned.
	pub fn try_get(&self, key: &Vec<u8>) -> Vec<u8> {
		let k = H::hash_from_bytes(key).unwrap();
		let node = self.tree.get_node(&k);
		if node.is_ok() {
			node.unwrap().data().unwrap()
		} else {
			vec![]
		}
	}

	// Tree exposed underlying ZkTrieImpl
	pub fn tree(&self) -> ZkTrieImpl<H, DB> {
		self.tree.clone()
	}

	// TryUpdate associates key with value in the trie. Subsequent calls to
	// Get will return value. If value has length zero, any existing value
	// is deleted from the trie and calls to Get will return nil.
	//
	// The value bytes must not be modified by the caller while they are
	// stored in the trie.
	//
	// If a node was not found in the database, a MissingNodeError is returned.
	//
	// NOTE: value is restricted to length of bytes32.
	pub fn try_update(&mut self, key: &Vec<u8>, v_flag: u32, v_preimage: Vec<[u8; 32]>) -> Result<(), ImplError> {
		let k = H::hash_from_bytes(key).unwrap();
		self.tree.try_update(&k, v_flag, v_preimage)
	}

	// TryDelete removes any existing value for key from the trie.
	// If a node was not found in the database, a MissingNodeError is returned.
	pub fn try_delete(&mut self, key: &Vec<u8>) -> Result<(), ImplError> {
		let k = H::hash_from_bytes(key).unwrap();
		self.tree.try_delete(&k)
	}

	// Hash returns the root hash of SecureBinaryTrie. It does not write to the
	// database and can be used even if the trie doesn't have one.
	pub fn hash(&self) -> Vec<u8> {
		self.tree.root().to_bytes()
	}

}
