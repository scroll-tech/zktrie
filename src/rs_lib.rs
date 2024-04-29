use super::constants::*;
use std::{cell::RefCell, rc::Rc};
use zktrie_rust::{
    db::ZktrieDatabase,
    types::{Hashable, TrieHashScheme},
    *,
};
#[derive(Clone, Debug, Default, PartialEq)]
pub struct HashField([u8; HASHLEN]);

impl AsRef<[u8]> for HashField {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for HashField {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl hash::Hash for HashField {
    const LEN: usize = HASHLEN;

    // notice: we have skipped the "field range checking" since
    // we have wrapped zktrie in a form that never accept value
    // which would be an invalid field poteinally

    fn simple_hash_scheme(mut a: [u8; 32], mut b: [u8; 32], domain: u64) -> Self {
        a.reverse();
        b.reverse();

        let mut domain_byte32 = [0u8; 32];
        domain_byte32[..8].copy_from_slice(&domain.to_le_bytes());

        let mut ret = super::HASHSCHEME
            .get()
            .expect("init_hash_scheme_simple should have been called")(
            &a, &b, &domain_byte32
        )
        .unwrap_or_default();
        ret.reverse();

        Self(ret)
    }
}

type HashImpl = hash::AsHash<HashField>;

pub struct ZkTrieNode {
    trie_node: types::Node<HashImpl>,
}

impl ZkTrieNode {
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        types::Node::new_node_from_bytes(data)
            // notice the go routine also calculated nodehash while parsing
            // see the code inside `NewTrieNode`
            .and_then(|n| n.calc_node_hash())
            .map(|n| Self { trie_node: n })
            .map_err(|e| e.to_string())
    }

    pub fn node_hash(&self) -> Hash {
        self.trie_node
            .clone()
            .node_hash()
            .expect("has caluclated")
            .as_ref()
            .try_into()
            .expect("same length")
    }

    pub fn value_hash(&self) -> Option<Hash> {
        self.trie_node
            .clone()
            .value_hash()
            .map(|h| h.as_ref().try_into().expect("same length"))
    }

    pub fn is_tip(&self) -> bool {
        self.trie_node.is_terminal()
    }

    pub fn as_account(&self) -> Option<AccountData> {
        if self.is_tip() {
            self.trie_node
                .data()
                .map(|data| {
                    data.chunks(FIELDSIZE)
                        .map(TryInto::<[u8; FIELDSIZE]>::try_into)
                        .map(|v| v.expect("same length"))
                        .collect::<Vec<_>>()
                })
                .map(|datas| datas.try_into().expect("should be same items"))
        } else {
            None
        }
    }

    pub fn as_storage(&self) -> Option<StoreData> {
        if self.is_tip() {
            self.trie_node
                .data()
                .map(|data| data.try_into().expect("should be same length"))
        } else {
            None
        }
    }
}

#[derive(Clone)]
pub struct ZkMemoryDb {
    db: RefCell<db::SimpleDb>,
}

#[derive(Clone)]
struct SharedMemoryDb(Rc<ZkMemoryDb>);

impl db::ZktrieDatabase for SharedMemoryDb {
    fn put(&mut self, k: Vec<u8>, v: Vec<u8>) -> Result<(), raw::ImplError> {
        self.0.db.borrow_mut().put(k, v)
    }
    fn get(&self, k: &[u8]) -> Result<Vec<u8>, raw::ImplError> {
        self.0.db.borrow().get(k)
    }
}

use trie::ZkTrie as ZktrieRs;

#[derive(Clone)]
pub struct ZkTrie {
    trie: ZktrieRs<HashImpl, SharedMemoryDb>,
    binding_db: Rc<ZkMemoryDb>,
}

pub type ErrString = String;

const MAGICSMTBYTES: &[u8] = "THIS IS SOME MAGIC BYTES FOR SMT m1rRXgP2xpDI".as_bytes();

impl ZkMemoryDb {
    pub fn new() -> Rc<Self> {
        Rc::new(Self {
            db: RefCell::new(db::SimpleDb::new()),
        })
    }

    pub fn add_node_bytes(self: &mut Rc<Self>, data: &[u8]) -> Result<(), ErrString> {
        if data == MAGICSMTBYTES {
            return Ok(());
        }
        let n = ZkTrieNode::parse(data)?;
        self.db
            .borrow_mut()
            .put(n.node_hash().to_vec(), n.trie_node.canonical_value())
            .map_err(|e| e.to_string())
    }

    // the zktrie can be created only if the corresponding root node has been added
    pub fn new_trie(self: &Rc<Self>, root: &Hash) -> Option<ZkTrie> {
        HashImpl::from_bytes(root.as_slice())
            .ok()
            .and_then(|h| ZktrieRs::new_zktrie(h, SharedMemoryDb(self.clone())).ok())
            .map(|tr| ZkTrie {
                trie: tr,
                binding_db: self.clone(),
            })
    }
}

impl ZkTrie {
    pub fn root(&self) -> Hash {
        self.trie.hash().as_slice().try_into().expect("same length")
    }

    pub fn get_db(&self) -> Rc<ZkMemoryDb> {
        self.binding_db.clone()
    }

    // all errors are reduced to "not found"
    fn get<const T: usize>(&self, key: &[u8]) -> Option<[u8; T]> {
        let ret = self.trie.try_get(key);
        if ret.len() != T {
            None
        } else {
            Some(ret.as_slice().try_into().expect("same length"))
        }
    }

    // get value from storage trie
    pub fn get_store(&self, key: &[u8]) -> Option<StoreData> {
        self.get::<32>(key)
    }

    // get account data from account trie
    pub fn get_account(&self, key: &[u8]) -> Option<AccountData> {
        self.get::<ACCOUNTSIZE>(key).map(|arr| unsafe {
            std::mem::transmute::<[u8; FIELDSIZE * ACCOUNTFIELDS], AccountData>(arr)
        })
    }

    // build prove array for mpt path
    pub fn prove(&self, key: &[u8]) -> Result<Vec<Vec<u8>>, ErrString> {
        use types::Node;

        let s_key = Node::<HashImpl>::hash_bytes(key).map_err(|e| e.to_string())?;

        let (proof, _) = self.trie.prove(s_key.as_ref()).map_err(|e| e.to_string())?;

        Ok(proof
            .into_iter()
            .map(|n| n.value())
            .chain(std::iter::once(MAGICSMTBYTES.to_vec()))
            .collect())
    }

    fn update(&mut self, key: &[u8], value: &[[u8; FIELDSIZE]]) -> Result<(), ErrString> {
        let v_flag = match value.len() {
            1 => 1,
            4 => 4,
            5 => 8,
            _ => return Err("unexpected buffer type".to_string()),
        };

        self.trie
            .try_update(key, v_flag, value.to_vec())
            .map_err(|e| e.to_string())
    }

    pub fn update_store(&mut self, key: &[u8], value: &StoreData) -> Result<(), ErrString> {
        self.update(key, &[*value])
    }

    pub fn update_account(
        &mut self,
        key: &[u8],
        acc_fields: &AccountData,
    ) -> Result<(), ErrString> {
        self.update(key, acc_fields)
    }

    pub fn delete(&mut self, key: &[u8]) {
        self.trie.try_delete(key).ok();
    }
}
