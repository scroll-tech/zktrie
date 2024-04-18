use super::constants::*;
use std::ffi::{self, c_char, c_int, c_void};
use std::marker::{PhantomData, PhantomPinned};
use std::{fmt, rc::Rc};

#[repr(C)]
struct MemoryDb {
    _data: [u8; 0],
    _marker: PhantomData<(*mut u8, PhantomPinned)>,
}
#[repr(C)]
struct Trie {
    _data: [u8; 0],
    _marker: PhantomData<(*mut u8, PhantomPinned)>,
}
#[repr(C)]
struct TrieNode {
    _data: [u8; 0],
    _marker: PhantomData<(*mut u8, PhantomPinned)>,
}

pub type HashScheme = extern "C" fn(*const u8, *const u8, *const u8, *mut u8) -> *const i8;
type ProveCallback = extern "C" fn(*const u8, c_int, *mut c_void);

#[link(name = "zktrie")]
extern "C" {
    fn InitHashScheme(f: HashScheme);
    fn NewMemoryDb() -> *mut MemoryDb;
    fn InitDbByNode(db: *mut MemoryDb, data: *const u8, sz: c_int) -> *const c_char;
    fn NewZkTrie(root: *const u8, db: *const MemoryDb) -> *mut Trie;
    fn FreeMemoryDb(db: *mut MemoryDb);
    fn FreeZkTrie(trie: *mut Trie);
    fn FreeBuffer(p: *const c_void);
    fn TrieGetSize(trie: *const Trie, key: *const u8, key_sz: c_int, value_sz: c_int) -> *const u8;
    fn TrieRoot(trie: *const Trie) -> *const u8;
    fn TrieUpdate(
        trie: *mut Trie,
        key: *const u8,
        key_sz: c_int,
        val: *const u8,
        val_sz: c_int,
    ) -> *const c_char;
    fn TrieDelete(trie: *mut Trie, key: *const u8, key_sz: c_int);
    fn TrieProve(
        trie: *const Trie,
        key: *const u8,
        key_sz: c_int,
        cb: ProveCallback,
        param: *mut c_void,
    ) -> *const c_char;
    fn NewTrieNode(data: *const u8, data_sz: c_int) -> *const TrieNode;
    fn FreeTrieNode(node: *const TrieNode);
    fn TrieNodeHash(node: *const TrieNode) -> *const u8;
    fn TrieLeafNodeValueHash(node: *const TrieNode) -> *const u8;
    fn TrieNodeIsTip(node: *const TrieNode) -> c_int;
    fn TrieNodeData(node: *const TrieNode, value_sz: c_int) -> *const u8;
}

pub(crate) fn init_hash_scheme(f: HashScheme) {
    unsafe { InitHashScheme(f) }
}

pub struct ErrString(*const c_char);

impl Drop for ErrString {
    fn drop(&mut self) {
        unsafe { FreeBuffer(self.0.cast()) };
    }
}

impl fmt::Debug for ErrString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.to_string().fmt(f)
    }
}

impl From<*const c_char> for ErrString {
    fn from(src: *const c_char) -> Self {
        Self(src)
    }
}

impl ToString for ErrString {
    fn to_string(&self) -> String {
        let ret = unsafe { ffi::CStr::from_ptr(self.0).to_str() };
        ret.map(String::from).unwrap_or_else(|_| {
            String::from("error string include invalid char and can not be displayed")
        })
    }
}

fn must_get_const_bytes<const T: usize>(p: *const u8) -> [u8; T] {
    let bytes = unsafe { std::slice::from_raw_parts(p, T) };
    let bytes = bytes
        .try_into()
        .expect("the buf has been set to specified bytes");
    unsafe { FreeBuffer(p.cast()) }
    bytes
}

fn must_get_hash(p: *const u8) -> Hash {
    must_get_const_bytes::<HASHLEN>(p)
}

pub struct ZkMemoryDb {
    db: *mut MemoryDb,
}

impl Drop for ZkMemoryDb {
    fn drop(&mut self) {
        unsafe { FreeMemoryDb(self.db) };
    }
}

pub struct ZkTrieNode {
    trie_node: *const TrieNode,
}

impl Drop for ZkTrieNode {
    fn drop(&mut self) {
        unsafe { FreeTrieNode(self.trie_node) };
    }
}

impl ZkTrieNode {
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        let trie_node = unsafe { NewTrieNode(data.as_ptr(), c_int::try_from(data.len()).unwrap()) };
        if trie_node.is_null() {
            Err(format!("Can not parse {data:#x?}"))
        } else {
            Ok(Self { trie_node })
        }
    }

    pub fn node_hash(&self) -> Hash {
        must_get_hash(unsafe { TrieNodeHash(self.trie_node) })
    }

    pub fn is_tip(&self) -> bool {
        let is_tip = unsafe { TrieNodeIsTip(self.trie_node) };
        is_tip != 0
    }

    pub fn as_account(&self) -> Option<AccountData> {
        if self.is_tip() {
            let ret = unsafe { TrieNodeData(self.trie_node, ACCOUNTSIZE as i32) };
            if ret.is_null() {
                None
            } else {
                let ret_byte = must_get_const_bytes(ret);
                unsafe {
                    Some(std::mem::transmute::<
                        [u8; FIELDSIZE * ACCOUNTFIELDS],
                        AccountData,
                    >(ret_byte))
                }
            }
        } else {
            None
        }
    }

    pub fn as_storage(&self) -> Option<StoreData> {
        if self.is_tip() {
            let ret = unsafe { TrieNodeData(self.trie_node, 32) };
            if ret.is_null() {
                None
            } else {
                Some(must_get_const_bytes::<32>(ret))
            }
        } else {
            None
        }
    }

    pub fn value_hash(&self) -> Option<Hash> {
        let key_p = unsafe { TrieLeafNodeValueHash(self.trie_node) };
        if key_p.is_null() {
            None
        } else {
            Some(must_get_hash(key_p))
        }
    }
}

pub struct ZkTrie {
    trie: *mut Trie,
    binding_db: Rc<ZkMemoryDb>,
}

impl Drop for ZkTrie {
    fn drop(&mut self) {
        unsafe { FreeZkTrie(self.trie) };
    }
}

impl Clone for ZkTrie {
    fn clone(&self) -> Self {
        self.binding_db
            .new_trie(&self.root())
            .expect("valid under clone")
    }
}

impl ZkMemoryDb {
    pub fn new() -> Rc<Self> {
        Rc::new(Self {
            db: unsafe { NewMemoryDb() },
        })
    }

    pub fn add_node_bytes(self: &mut Rc<Self>, data: &[u8]) -> Result<(), ErrString> {
        let ret_ptr = unsafe { InitDbByNode(self.db, data.as_ptr(), data.len() as c_int) };
        if ret_ptr.is_null() {
            Ok(())
        } else {
            Err(ret_ptr.into())
        }
    }

    // the zktrie can be created only if the corresponding root node has been added
    pub fn new_trie(self: &Rc<Self>, root: &Hash) -> Option<ZkTrie> {
        let ret = unsafe { NewZkTrie(root.as_ptr(), self.db) };

        if ret.is_null() {
            None
        } else {
            Some(ZkTrie {
                trie: ret,
                binding_db: self.clone(),
            })
        }
    }
}

impl ZkTrie {
    extern "C" fn prove_callback(data: *const u8, data_sz: c_int, out_p: *mut c_void) {
        let output = unsafe {
            out_p
                .cast::<Vec<Vec<u8>>>()
                .as_mut()
                .expect("callback parameter can not be zero")
        };
        let buf = unsafe { std::slice::from_raw_parts(data, data_sz as usize) };
        output.push(Vec::from(buf))
    }

    pub fn root(&self) -> Hash {
        must_get_hash(unsafe { TrieRoot(self.trie) })
    }

    pub fn get_db(&self) -> Rc<ZkMemoryDb> {
        self.binding_db.clone()
    }

    // all errors are reduced to "not found"
    fn get<const T: usize>(&self, key: &[u8]) -> Option<[u8; T]> {
        let ret = unsafe { TrieGetSize(self.trie, key.as_ptr(), key.len() as c_int, T as c_int) };

        if ret.is_null() {
            None
        } else {
            Some(must_get_const_bytes::<T>(ret))
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
        let mut output: Vec<Vec<u8>> = Vec::new();
        let ptr: *mut Vec<Vec<u8>> = &mut output;

        let ret_ptr = unsafe {
            TrieProve(
                self.trie,
                key.as_ptr(),
                key.len() as c_int,
                Self::prove_callback,
                ptr.cast(),
            )
        };
        if ret_ptr.is_null() {
            Ok(output)
        } else {
            Err(ret_ptr.into())
        }
    }

    fn update<const T: usize>(&mut self, key: &[u8], value: &[u8; T]) -> Result<(), ErrString> {
        let ret_ptr = unsafe {
            TrieUpdate(
                self.trie,
                key.as_ptr(),
                key.len() as c_int,
                value.as_ptr(),
                T as c_int,
            )
        };
        if ret_ptr.is_null() {
            Ok(())
        } else {
            Err(ret_ptr.into())
        }
    }

    pub fn update_store(&mut self, key: &[u8], value: &StoreData) -> Result<(), ErrString> {
        self.update(key, value)
    }

    pub fn update_account(
        &mut self,
        key: &[u8],
        acc_fields: &AccountData,
    ) -> Result<(), ErrString> {
        let acc_buf: &[u8; FIELDSIZE * ACCOUNTFIELDS] = unsafe {
            let ptr = acc_fields.as_ptr();
            ptr.cast::<[u8; FIELDSIZE * ACCOUNTFIELDS]>()
                .as_ref()
                .expect("casted ptr can not be null")
        };

        self.update(key, acc_buf)
    }

    pub fn delete(&mut self, key: &[u8]) {
        unsafe {
            TrieDelete(self.trie, key.as_ptr(), key.len() as c_int);
        }
    }
}
