use super::constants::*;
use std::{collections::HashMap, rc::Rc};
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

    pub fn parse_with_key(data: &[u8], key: &[u8]) -> Result<Self, String> {
        types::Node::new_node_from_bytes(data)
            .and_then(|mut n| {
                let h = HashImpl::from_bytes(key)?;
                n.set_node_hash(h);
                Ok(n)
            })
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
    db: db::SimpleDb,
    key_db: HashMap<Vec<u8>, HashImpl>,
}

#[derive(Clone)]
pub struct SharedMemoryDb(Rc<ZkMemoryDb>);

impl db::ZktrieDatabase for SharedMemoryDb {
    fn put(&mut self, _: Vec<u8>, _: Vec<u8>) -> Result<(), raw::ImplError> {
        Err(raw::ImplError::ErrNotWritable)
    }
    fn get(&self, k: &[u8]) -> Result<&[u8], raw::ImplError> {
        self.0.db.get(k)
    }
}

impl trie::KeyCache<HashImpl> for SharedMemoryDb {
    fn get_key(&self, k: &[u8]) -> Option<&HashImpl> {
        self.0.key_db.get(k)
    }
}

#[derive(Clone)]
pub struct UpdateDb(db::SimpleDb, Rc<ZkMemoryDb>);

impl UpdateDb {
    pub fn updated_db(self) -> db::SimpleDb {
        self.0
    }
}

impl db::ZktrieDatabase for UpdateDb {
    fn put(&mut self, k: Vec<u8>, v: Vec<u8>) -> Result<(), raw::ImplError> {
        self.0.put(k, v)
    }
    fn get(&self, k: &[u8]) -> Result<&[u8], raw::ImplError> {
        let ret = self.0.get(k);
        if ret.is_ok() {
            ret
        } else {
            self.1.db.get(k)
        }
    }
}

impl trie::KeyCache<HashImpl> for UpdateDb {
    fn get_key(&self, k: &[u8]) -> Option<&HashImpl> {
        self.1.key_db.get(k)
    }
}

use trie::ZkTrie as ZktrieRs;

pub struct ZkTrie<DB: ZktrieDatabase + trie::KeyCache<HashImpl>>(ZktrieRs<HashImpl, DB>);

pub type ErrString = String;

const MAGICSMTBYTES: &[u8] = "THIS IS SOME MAGIC BYTES FOR SMT m1rRXgP2xpDI".as_bytes();

impl Default for ZkMemoryDb {
    fn default() -> Self {
        Self::new()
    }
}

impl ZkMemoryDb {
    pub fn new() -> Self {
        Self {
            db: db::SimpleDb::new(),
            key_db: HashMap::new(),
        }
    }

    pub fn with_key_cache<'a>(&mut self, data: impl Iterator<Item = (&'a [u8], &'a [u8])>) {
        for (k, v) in data {
            // TODO: here we silently omit any invalid hash value
            if let Ok(h) = HashImpl::from_bytes(v) {
                self.key_db.insert(Vec::from(k), h);
            }
        }
    }

    pub fn add_node_bytes(&mut self, data: &[u8], key: Option<&[u8]>) -> Result<(), ErrString> {
        if data == MAGICSMTBYTES {
            return Ok(());
        }
        let n = if let Some(key) = key {
            ZkTrieNode::parse_with_key(data, key)
        } else {
            ZkTrieNode::parse(data)
        }?;
        self.db
            .put(n.node_hash().to_vec(), n.trie_node.canonical_value())
            .map_err(|e| e.to_string())
    }

    pub fn add_node_data(&mut self, data: &[u8]) -> Result<(), ErrString> {
        self.add_node_bytes(data, None)
    }

    pub fn update(&mut self, updated_db: db::SimpleDb) {
        self.db.merge(updated_db);
    }

    /// the zktrie can be created only if the corresponding root node has been added
    pub fn new_trie(self: &Rc<Self>, root: &Hash) -> Option<ZkTrie<UpdateDb>> {
        HashImpl::from_bytes(root.as_slice())
            .ok()
            .and_then(|h| ZktrieRs::new_zktrie(h, UpdateDb(Default::default(), self.clone())).ok())
            .map(ZkTrie)
    }

    /// the zktrie can be created only if the corresponding root node has been added
    pub fn new_ref_trie(self: &Rc<Self>, root: &Hash) -> Option<ZkTrie<SharedMemoryDb>> {
        HashImpl::from_bytes(root.as_slice())
            .ok()
            .and_then(|h| ZktrieRs::new_zktrie(h, SharedMemoryDb(self.clone())).ok())
            .map(ZkTrie)
    }
}

impl ZkTrie<UpdateDb> {
    pub fn updated_db(self) -> db::SimpleDb {
        self.0.tree().into_db().updated_db()
    }

    fn update(&mut self, key: &[u8], value: &[[u8; FIELDSIZE]]) -> Result<(), ErrString> {
        let v_flag = match value.len() {
            1 => 1,
            4 => 4,
            5 => 8,
            _ => return Err("unexpected buffer type".to_string()),
        };

        self.0
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
        self.0.try_delete(key).ok();
    }
}

impl<DB: db::ZktrieDatabase + trie::KeyCache<HashImpl>> ZkTrie<DB> {
    pub fn root(&self) -> Hash {
        self.0.hash().as_slice().try_into().expect("same length")
    }

    pub fn commit(&mut self) -> Result<(), ErrString> {
        self.0.commit().map_err(|e| e.to_string())
    }

    pub fn is_trie_dirty(&self) -> bool {
        self.0.is_trie_dirty()
    }

    pub fn prepare_root(&mut self) {
        self.0.prepare_root().expect("prepare root failed");
    }

    // all errors are reduced to "not found"
    fn get<const T: usize>(&self, key: &[u8]) -> Option<[u8; T]> {
        let ret = self.0.try_get(key);
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

        let (proof, _) = self.0.prove(s_key.as_ref()).map_err(|e| e.to_string())?;

        Ok(proof
            .into_iter()
            .map(|n| n.value())
            .chain(std::iter::once(MAGICSMTBYTES.to_vec()))
            .collect())
    }
}
