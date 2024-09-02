use crate::db::ZktrieDatabase;
use crate::raw::{ImplError, ZkTrieImpl};
use crate::types::{Hashable, Node, NodeType, TrieHashScheme};

pub trait KeyCache<H: Hashable> {
    fn get_key(&self, k: &[u8]) -> Option<&H>;
}

// ZkTrie wraps a trie with key hashing. In a secure trie, all
// access operations hash the key using keccak256. This prevents
// calling code from creating long chains of nodes that
// increase the access time.
//
// Contrary to a regular trie, a ZkTrie can only be created with
// New and must have an attached database. The database also stores
// the preimage of each key.
//

const MAX_LEVELS: usize = (NODE_KEY_VALID_BYTES * 8) as usize;

pub struct ZkTrie<H: Hashable, DB: ZktrieDatabase + KeyCache<H>> {
    tree: ZkTrieImpl<H, DB, MAX_LEVELS>,
}

// NODE_KEY_VALID_BYTES is the number of least significant bytes in the node key
// that are considered valid to addressing the leaf node, and thus limits the
// maximum trie depth to NODE_KEY_VALID_BYTES * 8.
// We need to truncate the node key because the key is the output of Poseidon
// hash and the key space doesn't fully occupy the range of power of two. It can
// lead to an ambiguous bit representation of the key in the finite field
// causing a soundness issue in the zk circuit.
const NODE_KEY_VALID_BYTES: u32 = 31;

impl<H: Hashable, DB: ZktrieDatabase + KeyCache<H>> ZkTrie<H, DB> {
    pub const MAX_LEVELS: usize = MAX_LEVELS;

    // NewSecure creates a trie
    // SecureBinaryTrie bypasses all the buffer mechanism in *Database, it directly uses the
    // underlying diskdb
    pub fn new_zktrie(root: H, db: DB) -> Result<Self, ImplError> {
        let tr = ZkTrieImpl::new_zktrie_impl_with_root(db, root);
        let t = ZkTrie { tree: tr? };
        Ok(t)
    }

    // TryGet returns the value for key stored in the trie.
    // The value bytes must not be modified by the caller.
    // If a node was not found in the database, a MissingNodeError is returned.
    pub fn try_get(&self, key: &[u8]) -> Vec<u8> {
        let node = if let Some(k) = self.tree.get_db().get_key(key) {
            self.tree.try_get(k)
        } else {
            let k = Node::<H>::hash_bytes(key).unwrap();
            self.tree.try_get(&k)
        };
        node.ok().and_then(|n| n.data()).unwrap_or_default()
    }

    // Tree exposed underlying ZkTrieImpl
    pub fn tree(self) -> ZkTrieImpl<H, DB, MAX_LEVELS> {
        self.tree
    }

    // Commit flushes the trie to database
    pub fn commit(&mut self) -> Result<(), ImplError> {
        self.tree.commit()
    }

    pub fn is_trie_dirty(&self) -> bool {
        self.tree.is_trie_dirty()
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
    pub fn try_update(
        &mut self,
        key: &[u8],
        v_flag: u32,
        v_preimage: Vec<[u8; 32]>,
    ) -> Result<(), ImplError> {
        let k = if let Some(k) = self.tree.get_db().get_key(key) {
            k.clone()
        } else {
            Node::<H>::hash_bytes(key).unwrap()
        };
        self.tree.try_update(&k, v_flag, v_preimage)
    }

    // TryDelete removes any existing value for key from the trie.
    // If a node was not found in the database, a MissingNodeError is returned.
    pub fn try_delete(&mut self, key: &[u8]) -> Result<(), ImplError> {
        let k = if let Some(k) = self.tree.get_db().get_key(key) {
            k.clone()
        } else {
            Node::<H>::hash_bytes(key).unwrap()
        };
        self.tree.try_delete(&k)
    }

    // Hash returns the root hash of SecureBinaryTrie. It does not write to the
    // database and can be used even if the trie doesn't have one.
    pub fn hash(&self) -> Vec<u8> {
        self.tree.root().to_bytes()
    }

    pub fn prepare_root(&mut self) -> Result<(), ImplError> {
        self.tree.prepare_root()?;
        Ok(())
    }

    // Prove constructs a merkle proof for key. The result contains all encoded nodes
    // on the path to the value at key. The value itself is also included in the last
    // node and can be retrieved by verifying the proof.
    //
    // If the trie does not contain a value for key, the returned proof contains all
    // nodes of the longest existing prefix of the key (at least the root node), ending
    // with the node that proves the absence of the key. and the `bool` in returned
    // tuple is false
    //
    // If the trie contain a non-empty leaf for key, the `bool` in returned tuple is true
    pub fn prove(&self, key_hash_byte: &[u8]) -> Result<(Vec<Node<H>>, bool), ImplError> {
        let key_hash = H::from_bytes(key_hash_byte)?;
        let proof = self.tree.prove(&key_hash)?;
        let mut hit = false;

        for n in &proof {
            if n.node_type == NodeType::NodeTypeLeafNew && n.node_key == key_hash {
                hit = true
            }
        }

        Ok((proof, hit))
    }
}
