use std::ffi::{self, c_char, c_int, c_void};
use std::marker::{PhantomData, PhantomPinned};

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

pub type HashScheme = extern "C" fn(*const u8, *const u8, *mut u8) -> *const u8;
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
    fn TrieGet(trie: *const Trie, key: *const u8, key_sz: c_int) -> *const u8;
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
    );
}

pub fn init_hash_scheme(f: HashScheme) {
    unsafe { InitHashScheme(f) }
}

pub struct ErrString(*const c_char);

impl Drop for ErrString {
    fn drop(&mut self) {
        unsafe { FreeBuffer(self.0.cast()) };
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

pub struct ZkMemoryDb {
    db: *mut MemoryDb,
}

impl Drop for ZkMemoryDb {
    fn drop(&mut self) {
        unsafe { FreeMemoryDb(self.db) };
    }
}

pub struct ZkTrie {
    trie: *mut Trie,
}

impl Drop for ZkTrie {
    fn drop(&mut self) {
        unsafe { FreeZkTrie(self.trie) };
    }
}

impl ZkMemoryDb {
    pub fn new() -> Self {
        Self {
            db: unsafe { NewMemoryDb() },
        }
    }

    pub fn add_node_bytes(&mut self, data: &[u8]) -> Result<(), ErrString> {
        let ret_ptr = unsafe { InitDbByNode(self.db, data.as_ptr(), data.len() as c_int) };
        if ret_ptr.is_null() {
            Ok(())
        } else {
            Err(ret_ptr.into())
        }
    }

    // the zktrie can be created only if the corresponding root node has been added
    pub fn new_trie(&mut self, root: &[u8; 32]) -> Option<ZkTrie> {
        let ret = unsafe { NewZkTrie(root.as_ptr(), self.db.cast_const()) };

        if ret.is_null() {
            None
        } else {
            Some(ZkTrie { trie: ret })
        }
    }
}

impl Default for ZkMemoryDb {
    fn default() -> Self {
        Self::new()
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

    // all errors are reduced to "not found"
    fn get<const T: usize>(&self, key: &[u8]) -> Option<[u8; T]> {
        let ret = unsafe { TrieGet(self.trie, key.as_ptr(), key.len() as c_int) };

        if ret.is_null() {
            None
        } else {
            let buf = unsafe { std::slice::from_raw_parts(ret, T) };
            Some(
                buf.try_into()
                    .expect("the buf has been set to specified bytes"),
            )
        }
    }

    // get value from storage trie
    pub fn get_store(&self, key: &[u8]) -> Option<[u8; 32]> {
        self.get::<32>(key)
    }

    // get account data from account trie
    pub fn get_account(&self, key: &[u8]) -> Option<[[u8; 32]; 4]> {
        self.get::<128>(key)
            .map(|arr| unsafe { std::mem::transmute::<[u8; 128], [[u8; 32]; 4]>(arr) })
    }

    // build prove array for mpt path
    pub fn prove(&self, key: &[u8]) -> Vec<Vec<u8>> {
        let mut output: Vec<Vec<u8>> = Vec::new();
        let ptr: *mut Vec<Vec<u8>> = &mut output;

        unsafe {
            TrieProve(
                self.trie,
                key.as_ptr(),
                key.len() as c_int,
                Self::prove_callback,
                ptr.cast(),
            );
        }

        output
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

    pub fn update_store(&mut self, key: &[u8], value: &[u8; 32]) -> Result<(), ErrString> {
        self.update(key, value)
    }

    pub fn update_account(
        &mut self,
        key: &[u8],
        acc_fields: &[[u8; 32]; 4],
    ) -> Result<(), ErrString> {
        let acc_buf: &[u8; 128] = unsafe {
            let ptr = acc_fields.as_ptr();
            ptr.cast::<[u8; 128]>()
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

#[cfg(test)]
mod tests {

    use super::*;
    use halo2_proofs::arithmetic::BaseExt;
    use halo2_proofs::pairing::bn256::Fr;
    use mpt_circuits::hash::Hashable;

    static HASH_ERROR: &'static str = "error";

    #[link(name = "zktrie")]
    extern "C" {
        fn TestHashScheme();
    }

    extern "C" fn hash_scheme(a: *const u8, b: *const u8, out: *mut u8) -> *const u8 {
        use std::slice;
        let mut a = unsafe { slice::from_raw_parts(a, 32) };
        let mut b = unsafe { slice::from_raw_parts(b, 32) };
        let mut out = unsafe { slice::from_raw_parts_mut(out, 32) };

        let fa = Fr::read(&mut a).unwrap();
        let fb = Fr::read(&mut b).unwrap();

        let h = Fr::hash([fa, fb]);

        h.write(&mut out).unwrap();

        std::ptr::null()
    }

    #[test]
    fn it_works() {
        unsafe {
            InitHashScheme(hash_scheme);
            TestHashScheme();
        }
    }
}
