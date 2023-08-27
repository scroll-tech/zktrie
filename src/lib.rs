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

pub const HASHLEN: usize = 32;
pub const FIELDSIZE: usize = 32;
#[cfg(not(feature = "dual_codehash"))]
pub const ACCOUNTFIELDS: usize = 4;
#[cfg(feature = "dual_codehash")]
pub const ACCOUNTFIELDS: usize = 5;
pub const ACCOUNTSIZE: usize = FIELDSIZE * ACCOUNTFIELDS;
pub type Hash = [u8; HASHLEN];
pub type StoreData = [u8; FIELDSIZE];
pub type AccountData = [[u8; FIELDSIZE]; ACCOUNTFIELDS];

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
}

pub fn init_hash_scheme(f: HashScheme) {
    unsafe { InitHashScheme(f) }
}

struct ErrStringC(*const c_char);

impl Drop for ErrStringC {
    fn drop(&mut self) {
        unsafe { FreeBuffer(self.0.cast()) };
    }
}

pub struct ErrString {
    str_impl: Rc<ErrStringC>,
}

impl fmt::Debug for ErrString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.to_string().fmt(f)
    }
}

impl From<*const c_char> for ErrString {
    fn from(src: *const c_char) -> Self {
        Self {
            str_impl: Rc::new(ErrStringC(src)),
        }
    }
}

impl ToString for ErrString {
    fn to_string(&self) -> String {
        let ret = unsafe { ffi::CStr::from_ptr(self.str_impl.0).to_str() };
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
    pub fn parse(data: &[u8]) -> Rc<Self> {
        Rc::new(Self {
            trie_node: unsafe { NewTrieNode(data.as_ptr(), c_int::try_from(data.len()).unwrap()) },
        })
    }

    pub fn node_hash(self: &Rc<Self>) -> Hash {
        must_get_hash(unsafe { TrieNodeHash(self.trie_node) })
    }

    pub fn value_hash(self: &Rc<Self>) -> Option<Hash> {
        let key_p = unsafe { TrieLeafNodeValueHash(self.trie_node) };
        if key_p.is_null() {
            None
        } else {
            Some(must_get_hash(key_p))
        }
    }
}

struct ZkTrieC(*mut Trie);

impl Drop for ZkTrieC {
    fn drop(&mut self) {
        unsafe { FreeZkTrie(self.0) };
    }
}

pub struct ZkTrie {
    trie: Rc<ZkTrieC>,
    _binding_db: Rc<ZkMemoryDb>,
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
    pub fn new_trie(self: &mut Rc<Self>, root: &Hash) -> Option<ZkTrie> {
        let ret = unsafe { NewZkTrie(root.as_ptr(), self.db) };

        if ret.is_null() {
            None
        } else {
            Some(ZkTrie {
                trie: Rc::new(ZkTrieC(ret)),
                _binding_db: self.clone(),
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
        must_get_hash(unsafe { TrieRoot(self.trie.0) })
    }

    // all errors are reduced to "not found"
    fn get<const T: usize>(&self, key: &[u8]) -> Option<[u8; T]> {
        let ret = unsafe { TrieGetSize(self.trie.0, key.as_ptr(), key.len() as c_int, T as c_int) };

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
                self.trie.0,
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
                self.trie.0,
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
            TrieDelete(self.trie.0, key.as_ptr(), key.len() as c_int);
        }
    }
}

#[cfg(test)]
#[cfg(feature = "dual_codehash")]
mod tests {

    use super::*;
    use halo2_proofs::halo2curves::bn256::Fr;
    use halo2_proofs::halo2curves::group::ff::PrimeField;
    use poseidon_circuit::Hashable;

    static FILED_ERROR_READ: &str = "invalid input field";
    static FILED_ERROR_OUT: &str = "output field fail";

    #[link(name = "zktrie")]
    extern "C" {
        fn TestHashScheme();
    }

    extern "C" fn hash_scheme(
        a: *const u8,
        b: *const u8,
        domain: *const u8,
        out: *mut u8,
    ) -> *const i8 {
        use std::slice;
        let a: [u8; 32] =
            TryFrom::try_from(unsafe { slice::from_raw_parts(a, 32) }).expect("length specified");
        let b: [u8; 32] =
            TryFrom::try_from(unsafe { slice::from_raw_parts(b, 32) }).expect("length specified");
        let domain: [u8; 32] = TryFrom::try_from(unsafe { slice::from_raw_parts(domain, 32) })
            .expect("length specified");
        let out = unsafe { slice::from_raw_parts_mut(out, 32) };

        let fa = Fr::from_bytes(&a);
        let fa = if fa.is_some().into() {
            fa.unwrap()
        } else {
            return FILED_ERROR_READ.as_ptr().cast();
        };
        let fb = Fr::from_bytes(&b);
        let fb = if fb.is_some().into() {
            fb.unwrap()
        } else {
            return FILED_ERROR_READ.as_ptr().cast();
        };
        let fdomain = Fr::from_bytes(&domain);
        let fdomain = if fdomain.is_some().into() {
            fdomain.unwrap()
        } else {
            return FILED_ERROR_READ.as_ptr().cast();
        };

        let h = Fr::hash_with_domain([fa, fb], fdomain);

        let repr_h = h.to_repr();
        if repr_h.len() == 32 {
            out.copy_from_slice(repr_h.as_ref());
            std::ptr::null()
        } else {
            FILED_ERROR_OUT.as_ptr().cast()
        }
    }

    #[test]
    fn hash_works() {
        init_hash_scheme(hash_scheme);
        unsafe {
            TestHashScheme();
        }
    }

    #[allow(dead_code)]
    static EXAMPLE : [&str;41] = [
            "0x09218bcaf094949451aaea2273a4092c7116839ad69df7597df06c7bf741a9477f01020df75837d8a760bfb941f3465f63812b205ac7e1fff5d310a2a3295e60c8",
            "0x0913e957fbc8585b40175129d3547a76b9fc3a1c3b16a6ca4de468879bb08fcbb6104a71f54260a0430906c4a0c3cc5eb459dd132b637c944ea92b769a98dba762",
            "0x092c2eae4f5273c398709da3e317c86a3a817008c98269bf2766405259c488306628c0c92eb1f16fc59b8b99e0a8abee3f88afb477c4d36be3571d537b076e0f83",
            "0x0800100f66e758c81427817699eeed67308bc9a7ee8054f2cbd463b7bf252610af233b07e4b000250359a56ef55485036e6d4dbca7c71bf82812790ac3f4a5238e",
            "0x08088158f4dfd26b06688c646a453c1b52710139a064b0394b47a0693c2bee46a4159d39c4d2776406bca63dfba405861d669f6220a087ad4b204e1cca52c7be5f",
            "0x062b2d9de4b02c2bab78264918866524e44e6efdc24bf0be2d4a8aa6f9b232a7781cb2c64090d483dbe3795eea941f808f7eda30de68190976a36f856f2a824bdd",
            "0x040a30b5d71d70991519167c5314323d2d69b02b7c501070ec7f34f4f24d89b5860508000000000000000000000000000000000000000000000000119b000000000000000100000000000000000000000000000000000000000000000000000000000000001a99ce3a54bcc9f4d7f61c67286f0ffc6a5ddab4a94c1f6fc6741a5ef196145b16fc66d15010e6213d2a009f57ed8e847717ea0b83eeb37cd322e9ad1b018a3e0d85b09a93d5ed99a87d27dcf6d50e4459d16bb694e70f89eefcb745ea1c85e7200c64e6f8d51bb1ae0e4ad62b9a1b996e1b2675d3000000000000000000000000",
            "0x09218bcaf094949451aaea2273a4092c7116839ad69df7597df06c7bf741a9477f01020df75837d8a760bfb941f3465f63812b205ac7e1fff5d310a2a3295e60c8",
            "0x0913e957fbc8585b40175129d3547a76b9fc3a1c3b16a6ca4de468879bb08fcbb6104a71f54260a0430906c4a0c3cc5eb459dd132b637c944ea92b769a98dba762",
            "0x092c2eae4f5273c398709da3e317c86a3a817008c98269bf2766405259c488306628c0c92eb1f16fc59b8b99e0a8abee3f88afb477c4d36be3571d537b076e0f83",
            "0x0800100f66e758c81427817699eeed67308bc9a7ee8054f2cbd463b7bf252610af233b07e4b000250359a56ef55485036e6d4dbca7c71bf82812790ac3f4a5238e",
            "0x08088158f4dfd26b06688c646a453c1b52710139a064b0394b47a0693c2bee46a4159d39c4d2776406bca63dfba405861d669f6220a087ad4b204e1cca52c7be5f",
            "0x062b2d9de4b02c2bab78264918866524e44e6efdc24bf0be2d4a8aa6f9b232a7781cb2c64090d483dbe3795eea941f808f7eda30de68190976a36f856f2a824bdd",
            "0x041822829dca763241624d1f8dd4cf59018fc5f69931d579f8e8a4c3addd6633e605080000000000000000000000000000000000000000000000000000000000000000001101ffffffffffffffffffffffffffffffffffffffffffd5a5fa65e20465da88bf0000000000000000000000000000000000000000000000000000000000000000c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a4702098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864201c5a77d9fa7ef466951b2f01f724bca3a5820b63000000000000000000000000",
            "0x092df5ac113a2c9174aea818559d63df596efdd925bcc14028e901ba605dc030e101ebd1fa8391b5fa5b805444d74896d14cfac9519260e94ab9ef25ee4461f737",
            "0x070000000000000000000000000000000000000000000000000000000000000000104736bbf00e9ab6f74b9e366c28b4f21c4a273cbd1f7e3dff3d68d4dbfe6d76",
            "0x060a9837791a40c9befa2ebdbbe99fdb8d8d7a7bb9fe3a4c14f1581a76809bf2b21323d7866288f9d670672215af41d0d610303b7e5f6ba97b5e54080960974580",
            "0x041aed9d52b6e3489c0ea97983a6dc4fbad57507090547dc83b8830c2ddb88577701010000000000000000000000001c5a77d9fa7ef466951b2f01f724bca3a5820b630012200000000000000000000000000000000000000000000000000000000000000005",
            "0x09218bcaf094949451aaea2273a4092c7116839ad69df7597df06c7bf741a9477f01020df75837d8a760bfb941f3465f63812b205ac7e1fff5d310a2a3295e60c8",
            "0x0913e957fbc8585b40175129d3547a76b9fc3a1c3b16a6ca4de468879bb08fcbb6104a71f54260a0430906c4a0c3cc5eb459dd132b637c944ea92b769a98dba762",
            "0x092c2eae4f5273c398709da3e317c86a3a817008c98269bf2766405259c488306628c0c92eb1f16fc59b8b99e0a8abee3f88afb477c4d36be3571d537b076e0f83",
            "0x0800100f66e758c81427817699eeed67308bc9a7ee8054f2cbd463b7bf252610af233b07e4b000250359a56ef55485036e6d4dbca7c71bf82812790ac3f4a5238e",
            "0x04113060bdeae1240b8b2f272e35848ac6b0c401bdc3a9ec20186da2a6a9d4607e05080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000152d02c7e14af60000000000000000000000000000000000000000000000000000000000000000000000c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a4702098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b6486420c0c4c8baea3f6acb49b6e1fb9e2adeceeacb0ca2000000000000000000000000",
            "0x09218bcaf094949451aaea2273a4092c7116839ad69df7597df06c7bf741a9477f01020df75837d8a760bfb941f3465f63812b205ac7e1fff5d310a2a3295e60c8",
            "0x0908e49a63f6ecd17ace446bd1e684b6cdd29f31faae528a9f058aefa76551068228eeef32a81cf40e295ad9c1de7e53a5180e6f1727521a209e0e2913250941fe",
            "0x082e4e1a6f0a26fe354020a569325d45d9b63e11f769a79620da6c84c053d88733252f02bd2a45416d5076e363e6172f941774eb184ce75ba0803264362958e2ef",
            "0x08020cc627de460d025af928a8a847b8d7475ff44bcaadce1667cfab122c8f3ea6301dc3e787d41a3db0710353073f18eaebab31ac37d69e25983caf72f6c08178",
            "0x04139a6815e4d1fb05c969e6a8036aa5cc06b88751d713326d681bd90448ea64c905080000000000000000000000000000000000000000000000000874000000000000000000000000000000000000000000000000000000000000000000000000000000002c3c54d9c8b2d411ccd6458eaea5c644392b097de2ee416f5c923f3b01c7b8b80fabb5b0f58ec2922e2969f4dadb6d1395b49ecd40feff93e01212ae848355d410e77cae1c507f967948c6cd114e74ed65f662e365c7d6993e97f78ce898252800",
            "0x09218bcaf094949451aaea2273a4092c7116839ad69df7597df06c7bf741a9477f01020df75837d8a760bfb941f3465f63812b205ac7e1fff5d310a2a3295e60c8",
            "0x0908e49a63f6ecd17ace446bd1e684b6cdd29f31faae528a9f058aefa76551068228eeef32a81cf40e295ad9c1de7e53a5180e6f1727521a209e0e2913250941fe",
            "0x082e4e1a6f0a26fe354020a569325d45d9b63e11f769a79620da6c84c053d88733252f02bd2a45416d5076e363e6172f941774eb184ce75ba0803264362958e2ef",
            "0x08020cc627de460d025af928a8a847b8d7475ff44bcaadce1667cfab122c8f3ea6301dc3e787d41a3db0710353073f18eaebab31ac37d69e25983caf72f6c08178",
            "0x0700000000000000000000000000000000000000000000000000000000000000000d652d6e2cc697970d24bfec9c84b720481a080eeb3a039277d5dfa90c634a02",
            "0x060b262fa2cc2bcdf4083a6b4b45956ebcf85003d697780351a24398b7df39985a096c33b369382285822d8f0acf8097ca6f095334750a42f869e513c8ec3779a7",
            "0x04287b801ba8950befe82147f88e71eff6b85eb921845d754c9c2a165a4ec86791050800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a5b65ae2577410000000000000000000000000000000000000000000000000000000000000000c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a4702098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864205300000000000000000000000000000000000005000000000000000000000000",
            "0x092e757f7cfb7c618a89bef428d6f043efb7913959793a525d3e6dc2265aa2e0362c9e569b67ba72d58e6f56454481607aee49523e3da63072e2cb4e0b37453e8a",
            "0x091868286870969b61281e49af8860d1bc74b558a4014da7433cb7e99a88aa56bc2d58daf89ed4b660018c081b11785924bd129ce58535350bd66c23eddf591e2b",
            "0x0900d86fc3cea9f88796671391157d8433f92be74473b01876ef9b6a75632c225d159af6801572801dfd6e17b00de85fcf0dae392c520440b763ecfc3936970af5",
            "0x0911b101680f5f11b4cccdcde4115c3f8e8af523fa76dd52de98c468cc0502dd642fd7d2a38e36d5a616485e21c93edb5798618e0e0e2003b979d05a94b29b2b29",
            "0x070000000000000000000000000000000000000000000000000000000000000000240aaaaee47745183d4820fe7384efe4a3fb93461aecea38b0a7d7bee64784a5",
            "0x05",
    ];

    #[test]
    fn node_parse() {
        init_hash_scheme(hash_scheme);

        let nd = ZkTrieNode::parse(&hex::decode("04139a6815e4d1fb05c969e6a8036aa5cc06b88751d713326d681bd90448ea64c905080000000000000000000000000000000000000000000000000874000000000000000000000000000000000000000000000000000000000000000000000000000000002c3c54d9c8b2d411ccd6458eaea5c644392b097de2ee416f5c923f3b01c7b8b80fabb5b0f58ec2922e2969f4dadb6d1395b49ecd40feff93e01212ae848355d410e77cae1c507f967948c6cd114e74ed65f662e365c7d6993e97f78ce898252800").unwrap());
        assert_eq!(
            hex::encode(nd.node_hash()),
            "301dc3e787d41a3db0710353073f18eaebab31ac37d69e25983caf72f6c08178"
        );
        let nd = ZkTrieNode::parse(&hex::decode("041822829dca763241624d1f8dd4cf59018fc5f69931d579f8e8a4c3addd6633e605080000000000000000000000000000000000000000000000000000000000000000003901ffffffffffffffffffffffffffffffffffffffffffc078f7396622d90018d50000000000000000000000000000000000000000000000000000000000000000c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a4702098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864201c5a77d9fa7ef466951b2f01f724bca3a5820b63000000000000000000000000").unwrap());
        assert_eq!(
            hex::encode(nd.node_hash()),
            "18a38101a2886bca1262d02a7355d693b7937833a0eb729a5612cdb9a9817fc2"
        );
    }

    #[test]
    fn trie_works() {
        init_hash_scheme(hash_scheme);
        let mut db = ZkMemoryDb::new();

        for bts in EXAMPLE {
            let buf = hex::decode(bts.get(2..).unwrap()).unwrap();
            db.add_node_bytes(&buf).unwrap();
        }

        let root = hex::decode("194cfd0c3cce58ac79c5bab34b149927e0cd9280c6d61870bfb621d45533ddbc")
            .unwrap();
        let root: Hash = root.as_slice().try_into().unwrap();

        let mut trie = db.new_trie(&root).unwrap();
        assert_eq!(trie.root(), root);

        let acc_buf = hex::decode("1C5A77d9FA7eF466951B2F01F724BCa3A5820b63").unwrap();

        let acc_data = trie.get_account(&acc_buf).unwrap();

        let mut nonce_code: StoreData =
            hex::decode("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap()
                .as_slice()
                .try_into()
                .unwrap();
        let balance: StoreData =
            hex::decode("01ffffffffffffffffffffffffffffffffffffffffffd5a5fa65e20465da88bf")
                .unwrap()
                .as_slice()
                .try_into()
                .unwrap();
        let code_hash: StoreData =
            hex::decode("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
                .unwrap()
                .as_slice()
                .try_into()
                .unwrap();
        assert_eq!(acc_data[0], nonce_code);
        assert_eq!(acc_data[1], balance);
        assert_eq!(acc_data[3], code_hash);

        nonce_code[31] += 1;

        let newacc: AccountData = [nonce_code, balance, [0; FIELDSIZE], code_hash, acc_data[4]];
        trie.update_account(&acc_buf, &newacc).unwrap();

        let acc_data = trie.get_account(&acc_buf).unwrap();
        assert_eq!(acc_data[0], nonce_code);
        assert_eq!(acc_data[1], balance);
        assert_eq!(acc_data[3], code_hash);

        let mut root =
            hex::decode("9a88bda22f50dc0fda6c355fd93c025df7f7ce6e3d0b979942ebd981c1c6c71c")
                .unwrap();
        root.reverse();
        let root: Hash = root.as_slice().try_into().unwrap();
        assert_eq!(trie.root(), root);

        let newacc: AccountData = [
            newacc[0],
            hex::decode("01ffffffffffffffffffffffffffffffffffffffffffd5a5fa65b10989405cd7")
                .unwrap()
                .as_slice()
                .try_into()
                .unwrap(),
            newacc[2],
            newacc[3],
            newacc[4],
        ];
        trie.update_account(&acc_buf, &newacc).unwrap();
        let mut root =
            hex::decode("7f787ee24805a9e5f69dc3a91ce68ef86d9358ce9c35729bd68660ccf6f9d909")
                .unwrap();
        root.reverse();
        let root: Hash = root.as_slice().try_into().unwrap();
        assert_eq!(trie.root(), root);

        let proof = trie.prove(&acc_buf).unwrap();

        assert_eq!(proof.len(), 8);
        assert_eq!(proof[7], hex::decode("5448495320495320534f4d45204d4147494320425954455320464f5220534d54206d3172525867503278704449").unwrap());
        assert_eq!(proof[3], hex::decode("0810b051b9facdd51b7fd1a1cf8e9a62facef17c80c7be0db1f15f3cda95982e34233b07e4b000250359a56ef55485036e6d4dbca7c71bf82812790ac3f4a5238e").unwrap());

        let node = ZkTrieNode::parse(&proof[6]);
        assert_eq!(
            node.node_hash().as_slice(),
            hex::decode("272f093df377b234e179b70dc1a04a1543072be3c7d3a47f6e59004c84639907")
                .unwrap()
        );
        assert_eq!(
            node.value_hash().unwrap().as_slice(),
            hex::decode("06c7c55f4d38fa2c6f6e0e655038ae7e1b3bb9dfa8954bdec0f9708e6e6b7d72")
                .unwrap()
        );

        trie.delete(&acc_buf);
        assert!(trie.get_account(&acc_buf).is_none());

        trie.update_account(&acc_buf, &newacc).unwrap();
        assert_eq!(trie.root(), root);
    }
}
