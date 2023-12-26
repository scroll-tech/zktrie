use crate::db::ZktrieDatabase;
use crate::types::{Hashable, Node, NodeType};
use std::error::Error;
use std::fmt::Debug;
use std::panic;
use num_derive::FromPrimitive;
use strum_macros::Display;
use crate::types::NodeType::*;

// PROOF_FLAGS_LEN is the byte length of the flags in the proof header
// (first 32 bytes).
pub const PROOF_FLAGS_LEN:usize = 2;
pub const DBKEY_ROOT_NODE:&str = "currentroot";

#[derive (Copy, Clone, Debug, FromPrimitive, Display, PartialEq)]
pub enum ImplError {
    // ErrInvalidField is key not inside the finite field.
    ErrInvalidField,
    // ErrNodeKeyAlreadyExists is used when a node key already exists.
    ErrNodeKeyAlreadyExists,
    // ErrKeyNotFound is used when a key is not found in the ZkTrieImpl.
    ErrKeyNotFound,
    // ErrNodeBytesBadSize is used when the data of a node has an incorrect
    // size and can't be parsed.
    ErrNodeBytesBadSize,
    // ErrReachedMaxLevel is used when a traversal of the MT reaches the
    // maximum level.
    ErrReachedMaxLevel,
    // ErrInvalidNodeFound is used when an invalid node is found and can't
    // be parsed.
    ErrInvalidNodeFound,
    // ErrInvalidProofBytes is used when a serialized proof is invalid.
    ErrInvalidProofBytes,
    // ErrEntryIndexAlreadyExists is used when the entry index already
    // exists in the tree.
    ErrEntryIndexAlreadyExists,
    // ErrNotWritable is used when the ZkTrieImpl is not writable and a
    // write     pub fntion is called
    ErrNotWritable,
}

impl Error for ImplError {}

// ZkTrieImpl is the struct with the main elements of the ZkTrieImpl
#[derive (Clone)]
pub struct ZkTrieImpl<H: Hashable, DB: ZktrieDatabase> {
    db: DB,
    root_hash: H,
    writable:  bool,
    max_levels: u32,
    debug: bool,
}

impl<H: Hashable, DB: ZktrieDatabase> ZkTrieImpl<H, DB> {

    pub fn new_zktrie_impl(storage: DB, max_levels: u32) -> Result<Self, ImplError> {
        Self::new_zktrie_impl_with_root(storage, H::hash_zero(), max_levels)
    }

    /// new_zktrie_implWithRoot loads a new ZkTrieImpl. If in the storage already exists one
    /// will open that one, if not, will create a new one.
    pub fn new_zktrie_impl_with_root(storage: DB, root: H, max_levels: u32) -> Result<Self, ImplError> {
        let mt = ZkTrieImpl {
            db: storage,
            max_levels,
            writable: true,
            root_hash: root.clone(),
            debug: false,
        };

        if root != H::hash_zero() {
            mt.get_node(&mt.root_hash)?;
            Ok(mt)
        } else {
            Ok(mt)
        }
    }

    /// Root returns the MerkleRoot
    pub fn root(&self) -> H {
        if self.debug {
            self.get_node(&self.root_hash).expect(
                format!("load trie root failed hash {:?}", self.root_hash).as_str()
            );
        }
        return self.root_hash.clone()
    }

    pub fn max_levels(&self) -> u32 {
        self.max_levels
    }

    /// TryUpdate updates a node_key & value : u32o the ZkTrieImpl. Where the `k` determines the
    /// path from the Root to the Leaf. This also return the updated leaf node
    pub fn try_update(&mut self, node_key: &H, v_flag: u32, v_preimage: Vec<[u8; 32]>) -> Result<(), ImplError> {
        // verify that the ZkTrieImpl is writable
        if !self.writable {
            Err(ImplError::ErrNotWritable)
        } else if !H::check_in_field(node_key) {
            // verify that k are valid and fit inside the Finite Field.
            Err(ImplError::ErrInvalidField)
        } else {
            let mut new_leaf_node = Node::<H>::new_leaf_node(node_key.clone(), v_flag, v_preimage);
            let path = Self::get_path(self.max_levels, &node_key);
            // precalc NodeHash of new leaf here
            // The following shold not fail
            new_leaf_node.node_hash().unwrap();

            let old_hash = self.root_hash.clone();
            let ret = self.add_leaf(&mut new_leaf_node, &old_hash, 0, path, true);
            match ret {
                Err(e) => {
                    Err(e)
                },
                Ok((new_root_hash, _)) => {
                    self.root_hash = new_root_hash;
                self.db_insert(&DBKEY_ROOT_NODE.as_bytes().to_vec(), DBEntryTypeRoot, &self.root_hash.to_bytes())?;
                Ok(())
                }
            }
        }
    }

    // pushLeaf recursively pushes an existing oldLeaf down until its path diverges
    // from new_leaf, at which po: u32 both leafs are stored, all while updating the
    // path. pushLeaf returns the node hash of the parent of the oldLeaf and new_leaf
    pub fn push_leaf(
        &mut self,
        new_leaf: &mut Node<H>,
        old_leaf: &mut Node<H>,
        lvl: u32,
        path_new_leaf: &Vec<bool>,
        path_old_leaf: &Vec<bool>
    ) -> Result<H, ImplError> {
        if lvl > self.max_levels-2 {
            Err(ImplError::ErrReachedMaxLevel)
        } else if path_new_leaf[lvl as usize] == path_old_leaf[lvl as usize] { // We need to go deeper!
            let next_node_hash = self.push_leaf(new_leaf, old_leaf, lvl+1, path_new_leaf, path_old_leaf)?;
            let mut new_parent_node  = if path_new_leaf[lvl as usize] { // go right
                Node::new_parent_node(NodeTypeBranch1, H::hash_zero(), next_node_hash)
            } else { // go left
                Node::new_parent_node(NodeTypeBranch2, next_node_hash, H::hash_zero())
            };
            self.add_node(&mut new_parent_node)
        } else {
            let old_leaf_hash = old_leaf.node_hash().unwrap();
            let new_leaf_hash = new_leaf.node_hash().unwrap();
            let mut new_parent_node = if path_new_leaf[lvl as usize] {
                Node::new_parent_node(NodeTypeBranch0, old_leaf_hash, new_leaf_hash)
            } else {
                Node::new_parent_node(NodeTypeBranch0, new_leaf_hash, old_leaf_hash)
            };
            self.add_node(new_leaf)?;
            self.add_node(&mut new_parent_node)
        }
    }

// addLeaf recursively adds a new_leaf in the MT while updating the path, and returns the node hash
// of the new added leaf.
    pub fn add_leaf(
        &mut self,
        new_leaf: &mut Node<H>,
        curr_node_hash: &H,
        lvl: u32,
        path: Vec<bool>,
        force_update: bool
    ) -> Result<(H, bool), ImplError> {
        if lvl > self.max_levels-1 {
            Err(ImplError::ErrReachedMaxLevel)
        } else {
            let mut n = self.get_node(curr_node_hash)?;
            match n.node_type {
            NodeTypeEmptyNew => {
                // We can add new_leaf now
                let ret = self.add_node(new_leaf);
                match ret {
                    Err(e) => {
                        Err(e)
                    },
                    Ok(h) => {
                        Ok((h, true))
                    }
                }
            },
            NodeTypeLeafNew => {
                // Check if leaf node found contains the leaf node we are
                // trying to add
                if n.node_key == new_leaf.node_key {
                    let hash = n.node_hash().unwrap();
                    /* FIXME:
                    if err != nil {
                        //fmt.Pr: u32ln("err on obtain key of duplicated entry", err)
                        return nil, false, err
                    }
                    */
                    if hash == new_leaf.node_hash.as_ref().unwrap().clone() {
                        // do nothing, duplicate entry
                        // FIXME more optimization may needed here
                        Ok((hash, true))
                    } else if force_update {
                        let hash = self.update_node(new_leaf)?;
                        Ok((hash, true))
                    } else {
                        Err(ImplError::ErrEntryIndexAlreadyExists)
                    }
                } else {
                    let path_old_leaf = Self::get_path(self.max_levels, &n.node_key);
                    // We need to push new_leaf down until its path diverges from
                    // n's path
                    let hash = self.push_leaf(new_leaf, &mut n, lvl, &path, &path_old_leaf)?;
                    Ok((hash, false))
                }
            },
            NodeTypeBranch0 | NodeTypeBranch1 | NodeTypeBranch2 | NodeTypeBranch3 => {
                // We need to go deeper, continue traversing the tree, left or
                // right depending on path
                let mut new_node_type = n.node_type;
                let mut new_parent_node = if path[lvl as usize] { // go right
                    let (new_node_hash, terminate) = self.add_leaf(new_leaf, &n.child_right.unwrap(), lvl+1, path, force_update)?;
                    if !terminate {
                        new_node_type = new_node_type.deduce_upgrade_type(true); // go right
                    }
                    Node::<H>::new_parent_node(new_node_type, n.child_left.unwrap(), new_node_hash)
                } else { // go left
                    let (new_node_hash, terminate) = self.add_leaf(new_leaf, &n.child_left.unwrap(), lvl+1, path, force_update)?;
                    if !terminate {
                        new_node_type = new_node_type.deduce_upgrade_type(false); // go left
                    }
                    Node::<H>::new_parent_node(new_node_type, new_node_hash, n.child_right.unwrap())
                };
                let hash = self.add_node(&mut new_parent_node)?;
                Ok((hash, false))
            },
            NodeTypeEmpty | NodeTypeLeaf | NodeTypeParent =>
                panic!("encounter unsupported deprecated node type"),
            _ =>
                Err(ImplError::ErrInvalidNodeFound)
        }
    }
}

    /// addNode adds a node : u32o the MT and returns the node hash. Empty nodes are
    /// not stored in the tree since they are all the same and assumed to always exist.
    pub fn add_node(&mut self, n: &mut Node<H>) -> Result<H, ImplError> {
        // verify that the ZkTrieImpl is writable
        if !self.writable {
            Err(ImplError::ErrNotWritable)
        } else if n.node_type == NodeTypeEmpty {
            Ok(n.node_hash().unwrap())
        } else {
            let hash = n.node_hash().unwrap();
            let v = n.canonical_value();
        // Check that the node key doesn't already exist
            let old = self.db.get(&hash.to_bytes());
            match old {
                Ok(old_v) => {
                    if !(v == old_v.unwrap()) {
                        Err(ImplError::ErrNodeKeyAlreadyExists)
                    } else {
                        // duplicated
                        Ok(hash.clone())
                    }
                },
                Err(_) => {
                    self.db.put(&hash.to_bytes(), &v).unwrap();
                    Ok(hash.clone())
                }
            }
        }
    }

// updateNode updates an existing node in the MT.  Empty nodes are not stored
// in the tree; they are all the same and assumed to always exist.
    pub fn update_node(&mut self, n: &mut Node<H>) -> Result<H, ImplError> {
    // verify that the ZkTrieImpl is writable
        if !self.writable {
            Err(ImplError::ErrNotWritable)
        } else if n.node_type == NodeTypeEmptyNew {
            Ok(n.node_hash().unwrap().clone())
        } else {
            let hash = n.node_hash().unwrap();
            let v = n.canonical_value();
            self.db.put(&hash.to_bytes(), &v).unwrap();
            Ok(hash)
        }
    }

// get_node gets a node by node hash from the MT.  Empty nodes are not stored in the
// tree; they are all the same and assumed to always exist.
// <del>for non exist key, return (NewEmptyNode(), nil)</del>
    pub fn get_node(&self, node_hash: &H) -> Result<Node<H>, ImplError> {
        if node_hash.clone() == H::hash_zero() {
            Ok(Node::<H>::new_empty_node())
        } else {
            let ret = self.db.get(&node_hash.to_bytes());
            match ret {
                Ok(bytes) => {
                    Node::new_node_from_bytes(bytes.unwrap())
                },
                Err(e) => {
                    Err(e)
                }
            }
        }
    }

    pub fn try_get_with_path(&self, node_key: &H) -> Result<(Node<H>, Vec<H>), ImplError> {
        let path = Self::get_path(self.max_levels, node_key);
        let mut next_hash = self.root_hash.clone();
        let mut siblings = vec![];
        let mut node = None;

        let mut last_node_type = NodeTypeBranch3;
        for i in 0..self.max_levels {
            let n = self.get_node(&next_hash)?;
            //sanity check
            if i > 0 && n.is_terminal() {
                if last_node_type == NodeTypeBranch3 {
                    panic!("parent node has invalid type: children are not terminal")
                } else if path[i as usize -1] && last_node_type == NodeTypeBranch1 {
                    panic!("parent node has invalid type: right child is not terminal")
                } else if !path[i as usize -1] && last_node_type == NodeTypeBranch2 {
                    panic!("parent node has invalid type: left child is not terminal")
                }
            }

            last_node_type = n.node_type;
            match n.node_type {
                NodeTypeEmptyNew => {
                    node = Some(Node::<H>::new_empty_node());
                    Ok(())
                },
                NodeTypeLeafNew => {
                    if *node_key == n.node_key {
                        node = Some(n);
                        Ok(())
                    } else {
                        Err(ImplError::ErrKeyNotFound)
                    }
                },
                NodeTypeBranch0 | NodeTypeBranch1 | NodeTypeBranch2 | NodeTypeBranch3 => {
                    if path[i as usize] {
                        next_hash = n.child_right.unwrap();
                        siblings.push(n.child_left.unwrap());
                    } else {
                        next_hash = n.child_left.unwrap();
                        siblings.push(n.child_right.unwrap());
                    };
                    Ok(())
                },
                NodeTypeEmpty | NodeTypeLeaf | NodeTypeParent =>
                    panic!("encounter deprecated node types"),
                _ => Err(ImplError::ErrInvalidNodeFound)
            }?
        };
        Ok((node.unwrap(), siblings))
    }

    /// TryGet returns the value for key stored in the trie.
    /// The value bytes must not be modified by the caller.
    /// If a node was not found in the database, a MissingNodeError is returned.
    pub fn try_get(&self, node_key: &H) -> Result<Node<H>, ImplError> {
        let ret = self.try_get_with_path(node_key);
        match ret {
            Err(e) => {
                Err(e)
            },
            Ok((node, _)) => {
                Ok(node)
            }
        }
}

    /// Delete removes the specified Key from the ZkTrieImpl and updates the path
    /// from the deleted key to the Root with the new values.  This method removes
    /// the key from the ZkTrieImpl, but does not remove the old nodes from the
    /// key-value database; this means that if the tree is accessed by an old Root
    /// where the key was not deleted yet, the key will still exist. If is desired
    /// to remove the key-values from the database that are not under the current
    /// Root, an option could be to dump all the leafs (using mt.DumpLeafs) and
    /// import them in a new ZkTrieImpl in a new database (using
    /// mt.ImportDumpedLeafs), but this will lose all the Root history of the
    /// ZkTrieImpl
    pub fn try_delete(&mut self, node_key: &H) -> Result<(), ImplError> {
    // verify that the ZkTrieImpl is writable
        if !self.writable {
            Err(ImplError::ErrNotWritable)
        } else if !H::check_in_field(node_key) {
            // verify that k is valid and fit inside the Finite Field.
            Err(ImplError::ErrInvalidField)
        } else {
            let path = Self::get_path(self.max_levels, node_key);
            let mut next_hash = self.root_hash.clone();
            let mut siblings = vec![];
            let mut path_types = vec![];
            let mut found = false;
            let mut err = ImplError::ErrKeyNotFound;
            for i in 0..self.max_levels {
                let n = self.get_node(&next_hash)?;
                match n.node_type {
                    NodeTypeLeafNew =>
                    if *node_key == n.node_key {
                        // remove and go up with the sibling
                        self.rm_and_upload(path.clone(), path_types.clone(), node_key, siblings.clone())?;
                        found = true;
                        break;
                    },
                    NodeTypeBranch0 | NodeTypeBranch1 | NodeTypeBranch2 | NodeTypeBranch3 => {
                        path_types.push(n.node_type);
                        if path[i as usize] {
                            next_hash = n.child_right.unwrap();
                            siblings.push(n.child_left.unwrap());
                        } else {
                            next_hash = n.child_left.unwrap();
                            siblings.push(n.child_right.unwrap());
                        };
                    },
                    NodeTypeEmpty | NodeTypeLeaf | NodeTypeParent =>
                        panic!("encounter unsupported deprecated node type"),
                    _ => err = ImplError::ErrInvalidNodeFound
                }
            };
            if !found {
                Err(err)
            } else {
                Ok(())
            }
        }
    }

// rmAndUpload removes the key, and goes up until the root updating all the
// nodes with the new values.
    pub fn rm_and_upload(&mut self, path: Vec<bool>, path_types: Vec<NodeType>, _node_key: &H, siblings: Vec<H>) -> Result<(), ImplError> {
        let mut final_root = None;

        if path_types.len() != siblings.len() {
            panic!("unexpected argument array len {} vs {}", path_types.len(), siblings.len())
        }

        // if we have no siblings, it mean the target node is the only node in trie
        if siblings.len() == 0 {
            final_root = Some(H::hash_zero());
            Ok(())
        } else if *path_types.last().unwrap() != NodeTypeBranch0 {
            // for a node which is not "both terminated", simply recalc the path
            // notice the nodetype would not change
            final_root = Some(self.recalculate_path_until_root(
                &path,
                &path_types,
                &mut Node::<H>::new_empty_node(),
                &siblings
            )?);
            Ok(())
        } else if siblings.len() == 1 {
            final_root = Some(siblings[0].clone());
            Ok(())
        } else {
            let mut pt_remain = path_types.clone();
            pt_remain.pop();
            let pathv = path[0..path_types.len()].to_vec();
            let mut path_remain = path[0..pt_remain.len()].to_vec();
            let mut remain = siblings.clone();
            let to_upload = remain.pop().unwrap();
            for ((sib, p), ptype) in siblings.into_iter().zip(pathv).zip(path_types).rev().skip(1) {
                remain.pop();
                pt_remain.pop();
                path_remain.pop();
                if (final_root == None) && (sib != H::hash_zero()) {
                    let new_node_type = ptype.deduce_downgrade_type(p); // atRight = path[i]
                    let mut new_node = if p {
                        Node::<H>::new_parent_node(new_node_type, sib, to_upload.clone())
                    } else {
                        Node::<H>::new_parent_node(new_node_type, to_upload.clone(), sib)
                    };
                    self.add_node(&mut new_node).map_or_else(|err| {
                        if err != ImplError::ErrNodeKeyAlreadyExists {
                            Err(err)
                        } else {
                            Ok(())
                        }
                    },
                    |_| Ok(())
                    )?;
                    // go up until the root
                    final_root = Some(self.recalculate_path_until_root(&path_remain, &pt_remain,
                        &mut new_node, &remain)?);
                    Ok(())
                } else {
                    Ok(())
                }?;
            };
            if final_root == None {
                // if all sibling is zero, stop and store the sibling of the
                // deleted leaf as root
                final_root = Some(to_upload.clone());
            }
            Ok(())
        }?;
        let root = final_root.expect("finalRoot is not set yet");
        self.root_hash = root;
        self.db_insert(&DBKEY_ROOT_NODE.as_bytes().to_vec(), DBEntryTypeRoot, &self.root_hash.to_bytes())
    }

// recalculatePathUntilRoot recalculates the nodes until the Root
    pub fn recalculate_path_until_root(
        &mut self,
        path: &Vec<bool>,
        path_types: &Vec<NodeType>,
        node: &mut Node<H>,
        siblings: &Vec<H>
    ) -> Result<H, ImplError> {
        let mut n:Node<H> = node.clone();
        for ((sib, p), pt) in siblings.into_iter().zip(path).zip(path_types).rev() {
            let node_hash = n.node_hash().expect("node hash should not fail in recalculate path");
            if *p {
                n = Node::<H>::new_parent_node(pt.clone(), sib.clone(), node_hash);
            } else {
                n = Node::<H>::new_parent_node(pt.clone(), node_hash, sib.clone());
            }
            self.add_node(&mut n).map_or_else(|err| {
                if err != ImplError::ErrNodeKeyAlreadyExists {
                    Err(err)
                } else {
                    Ok(())
                }
            }, |_| {
                Ok(())
            })?;
        };
        // return last node added, which is the root
        Ok(n.node_hash().unwrap())
    }

    // dbInsert is a helper pub fntion to insert a node : u32o a key in an open db
    // transaction.
    pub fn db_insert(&mut self, k: &Vec<u8>, t: NodeType, data: &Vec<u8>) -> Result<(), ImplError> {
        let mut v = data.clone();
        v.insert(0, t as u8);
        Ok(self.db.put(k, &v).unwrap())
    }

    // get_leaf_node is more underlying method than TryGet, which obtain an leaf node
    // or nil if not exist
    pub fn get_leaf_node(&mut self, node_key: &H) -> Result<Option<Node<H>>, ImplError> {
        let ret = self.try_get(node_key);
        match ret {
            Err(e) => {
                Err(e)
            },
            Ok(node) => {
                Ok(Some(node))
            }
        }
    }

    // get_path returns the binary path, from the root to the leaf.
    pub fn get_path(num_levels: u32, key: &H) -> Vec<bool> {
        let mut path = vec![];
        for n in 0..num_levels {
            path.push(H::test_bit(key, n as usize))
        }
        path
    }
}

#[cfg(test)]
mod test {
    use crate::db::{SimpleDb};
    use crate::hash::Hash;
    use crate::raw::ImplError;
    use crate::types::Hashable;
    use super::ZkTrieImpl;

    #[test]
    fn test_merkletree_init() {
        let max_levels = 254u32;

        let db = SimpleDb::new();
        let mt = ZkTrieImpl::<Hash, SimpleDb>::new_zktrie_impl(db, max_levels);
        assert_eq!(mt.is_ok(), true);
        assert_eq!(Hash::hash_zero(), mt.unwrap().root());

        let db = SimpleDb::new();
        let mt = ZkTrieImpl::<Hash, SimpleDb>::new_zktrie_impl_with_root(db, Hash::hash_zero(), max_levels);
        assert_eq!(mt.is_ok(), true);

        let mut t = mt.unwrap();
        assert_eq!(Hash::hash_zero(), t.root());

        let h = Hash::hash_from_bytes(&[1u8;1].to_vec()).unwrap();
        let v = vec![[1u8;32], [2u8;32], [3u8;32]];
        let err = t.try_update(&h, 1, v);
        assert_eq!(err.is_ok(), true);
        assert_ne!(Hash::hash_zero(), t.root());

    }

    #[test]
    fn test_merkletree_update_get() {
        let max_levels = 128u32;
        let db = SimpleDb::new();
        let mt = ZkTrieImpl::<Hash, SimpleDb>::new_zktrie_impl(db, max_levels);
        let mut t = mt.unwrap();

        //update and get value check
        for i in 1..20 {
            let h = Hash::hash_from_bytes(&[i as u8;1].to_vec()).unwrap();
            let v = vec![[20-i as u8;32]];
            let err = t.try_update(&h, 1, v);
            assert_eq!(err.is_ok(), true);
            let node = t.get_leaf_node(&h).unwrap().unwrap();
            assert_eq!(node.value_preimage.len(), 1);
            assert_eq!(node.value_preimage[0], [20-i as u8;32]);
        }
        let h1 = t.root();

        let db = SimpleDb::new();
        let mt = ZkTrieImpl::<Hash, SimpleDb>::new_zktrie_impl(db, max_levels);
        let mut t = mt.unwrap();
        //update and get value check by reverse order
        for i in 1..20 {
            let h = Hash::hash_from_bytes(&[20-i as u8;1].to_vec()).unwrap();
            let v = vec![[i as u8;32]];
            let err = t.try_update(&h, 1, v);
            assert_eq!(err.is_ok(), true);
            let node = t.get_leaf_node(&h).unwrap().unwrap();
            assert_eq!(node.value_preimage.len(), 1);
            assert_eq!(node.value_preimage[0], [i as u8;32]);
        }
        let h2 = t.root();

        assert_eq!(h2, h1);
        //invalid key
        let h = Hash::hash_from_bytes(&[30u8;1].to_vec()).unwrap();
        let err = t.get_leaf_node(&h).err().unwrap();
        assert_eq!(err, ImplError::ErrKeyNotFound);
    }

    #[test]
    fn test_merkletree_delete() {
        let max_levels = 128u32;
        let db = SimpleDb::new();
        let mt = ZkTrieImpl::<Hash, SimpleDb>::new_zktrie_impl(db, max_levels);
        let mut t = mt.unwrap();

        //update by order, delete reverse order, check root hash change
        let mut hashs = vec![];
        for i in 1..20 {
            let h = Hash::hash_from_bytes(&[i as u8;1].to_vec()).unwrap();
            let v = vec![[20-i as u8;32]];
            t.try_update(&h, 1, v).unwrap();
            hashs.push(t.root().clone());
        }

        for i in 1..20 {
            assert_eq!(t.root().clone(), hashs[19-i]);
            let h = Hash::hash_from_bytes(&[20-i as u8;1].to_vec()).unwrap();
            let err = t.try_delete(&h);
            assert_eq!(err.is_ok(), true);
        }

        //update same leaf and delete by order
        let max_levels = 128u32;
        let db = SimpleDb::new();
        let mt = ZkTrieImpl::<Hash, SimpleDb>::new_zktrie_impl(db, max_levels);
        let mut t = mt.unwrap();
        for i in 1..10 {
            let h = Hash::hash_from_bytes(&[i as u8;1].to_vec()).unwrap();
            let v = vec![[20-i as u8;32]];
            t.try_update(&h, 1, v).unwrap();
        }

        for i in 1..10 {
            let h = Hash::hash_from_bytes(&[i as u8;1].to_vec()).unwrap();
            let v = vec![[20+i as u8;32]];
            t.try_update(&h, 1, v).unwrap();
        }

        for i in 1..10 {
            let h = Hash::hash_from_bytes(&[i as u8;1].to_vec()).unwrap();
            let err = t.try_delete(&h);
            assert_eq!(err.is_ok(), true);
        }
    }
}
