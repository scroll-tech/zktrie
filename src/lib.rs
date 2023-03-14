use std::ffi::{self, c_char, c_int, c_void};
use std::fmt;
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
#[repr(C)]
struct TrieNode {
    _data: [u8; 0],
    _marker: PhantomData<(*mut u8, PhantomPinned)>,
}

pub const HASHLEN: usize = 32;
pub const FIELDSIZE: usize = 32;
pub const ACCOUNTFIELDS: usize = 4;
pub type Hash = [u8; HASHLEN];
pub type StoreData = [u8; FIELDSIZE];
pub type AccountData = [[u8; FIELDSIZE]; ACCOUNTFIELDS];

pub type HashScheme = extern "C" fn(*const u8, *const u8, *mut u8) -> *const i8;
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
    );
    fn NewTrieNode(data: *const u8, data_sz: c_int) -> *const TrieNode;
    fn FreeTrieNode(node: *const TrieNode);
    fn TrieNodeKey(node: *const TrieNode) -> *const u8;
    fn TrieLeafNodeValueHash(node: *const TrieNode) -> *const u8;
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
    pub fn parse(data: &[u8]) -> Self {
        Self {
            trie_node: unsafe { NewTrieNode(data.as_ptr(), data.len() as c_int) },
        }
    }

    pub fn key(&self) -> Hash {
        must_get_hash(unsafe { TrieNodeKey(self.trie_node) })
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
    pub fn new_trie(&mut self, root: &Hash) -> Option<ZkTrie> {
        let ret = unsafe { NewZkTrie(root.as_ptr(), self.db) };

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

    pub fn root(&self) -> Hash {
        must_get_hash(unsafe { TrieRoot(self.trie) })
    }

    // all errors are reduced to "not found"
    fn get<const T: usize>(&self, key: &[u8]) -> Option<[u8; T]> {
        let ret = unsafe { TrieGet(self.trie, key.as_ptr(), key.len() as c_int) };

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
        self.get::<128>(key).map(|arr| unsafe {
            std::mem::transmute::<[u8; FIELDSIZE * ACCOUNTFIELDS], AccountData>(arr)
        })
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

#[cfg(test)]
mod tests {

    use super::*;
    use halo2_proofs::halo2curves::bn256::Fr;
    use halo2_proofs::halo2curves::group::ff::PrimeField;
    use mpt_circuits::hash::Hashable;

    static FILED_ERROR_READ: &str = "invalid input field";
    static FILED_ERROR_OUT: &str = "output field fail";

    #[link(name = "zktrie")]
    extern "C" {
        fn TestHashScheme();
    }

    extern "C" fn hash_scheme(a: *const u8, b: *const u8, out: *mut u8) -> *const i8 {
        use std::slice;
        let a: [u8; 32] =
            TryFrom::try_from(unsafe { slice::from_raw_parts(a, 32) }).expect("length specified");
        let b: [u8; 32] =
            TryFrom::try_from(unsafe { slice::from_raw_parts(b, 32) }).expect("length specified");
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

        let h = <Fr as Hashable>::hash([fa, fb]);

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

    static EXAMPLE : [&str;37] = [
            "0x00206372de1e9b006b4104d57ee366871a32eed87731d7e6bcb2b84c605784ba072a84f0cee483739d84d15ba1b0f131900a20b41bc3b52e1b11af816095d49e34",
            "0x0007e14b4527ba2121b4c7b7256a6b0aa6bcedfe0b6f503cea362ea9ddd9f967b92b42961b4531b48a39e50771bff69e37850a57fb7d62604208a6a17f5c045069",
            "0x00147ac10f6d84c10d215f7265ae98d378dbe705fa1028c9ebe73a4d239e48142511e03b7714e0d6a43dbbb5cd94bf3e821b34527bcfefeb1d52ba78aa33c180f0",
            "0x0029b88078f0c28eaf12d13b8819221b89ce387616a5d0df46528d47d6cb14477d0620cc4f1fb663fd384e01a99d16a83aee58be87b9595c0bd8e03d6549c6b161",
            "0x001f99b4886120e7485d1fa370a9c6525ee81ad03838ead64127d545a6f370e13628c056cff6dec01aeec473d3015d96b40ab5c58789dd480bdea71ae463d1f82d",
            "0x0018c516361306d9b85f63f839dd1542d1952e12f869892e2c7c81ad5deb4cfa0412245f8b0685cf3d1006f53063dfc9202cd4e50f892dfa4ba5bdf614e11f86be",
            "0x0102d993e114721d3bc8ab9cf48075580b21178e2897568dcb16277645536d26f804040000000000000000000000000000000000000000000000000000000000000000000b0000000000000000000000000000000000000000000000000093780524bebeacc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470000000000000000000000000000000000000000000000000000000000000000000",
            "0x00206372de1e9b006b4104d57ee366871a32eed87731d7e6bcb2b84c605784ba072a84f0cee483739d84d15ba1b0f131900a20b41bc3b52e1b11af816095d49e34",
            "0x00174e396635f0b8a906f7cc100b51a0245e74d5f427559c9e69441e6da400a8bf22ee038cdac08f51b58437ec300d9dc770a48fd9641b9113421c1fbacff6138a",
            "0x000a4b711b871750b87b706e60a4cce1b5cc8c32528f02905144e6d4d2a2fb14590490ae4c72f6e1775acf6c6901461dbd1a15df1a3f362ee211604e2d496e7dba",
            "0x002c659c5727b02ba04ce36b8ea9e4701ef3ce84a8bd084dc87808a08c5fb3edea2d6d797a01bf7c0dd35870eeb62691e67339aff55f367fbb369b0c141d093fc5",
            "0x0004831789ad2280ed08d71217b56bfb3d7fc57f19bd0adbc3c147a603f90176362e9cefb066657d33d53e88041f10cef2b94c3edc8375c0523cd8505ae24630f1",
            "0x000f3f8422f90a78cc983776ffd08a12ff7fdf1ba054503edcee69289a1310770c10b8c7ed95f15ccb58a05df4daeaa34dafab5503b5e5e0460fc2e31f14d2d6f1",
            "0x0000000000000000000000000000000000000000000000000000000000000000000b27a9a0ae2d31aa47ad45f6f1ecb64d6a76aa72dd79ebdaff5fc01a2d5dbabd",
            "0x02",
            "0x00206372de1e9b006b4104d57ee366871a32eed87731d7e6bcb2b84c605784ba072a84f0cee483739d84d15ba1b0f131900a20b41bc3b52e1b11af816095d49e34",
            "0x0007e14b4527ba2121b4c7b7256a6b0aa6bcedfe0b6f503cea362ea9ddd9f967b92b42961b4531b48a39e50771bff69e37850a57fb7d62604208a6a17f5c045069",
            "0x00147ac10f6d84c10d215f7265ae98d378dbe705fa1028c9ebe73a4d239e48142511e03b7714e0d6a43dbbb5cd94bf3e821b34527bcfefeb1d52ba78aa33c180f0",
            "0x001be854efd466d8f6fb2ad9da76a92003cab8b581330e2e7b4f942feb5504d9cc1f14fba5a5dae4a7d974320ddba70bad142d300cc8166001e3f8993fddef55d8",
            "0x00203c132957bc929e5cf56fe864216e440b5582447fbda3c0c215d8992ed4b0ba1ebf0c7b06867a7f29276b6679a04a2593966bf59244b0b3c860805e67cf16f3",
            "0x011c9e9343aa449fec94fc11c7c3c9555d62f56796ba9bb9f402a3819b8fea1f9c04040000000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000197f7ef0aab588fbcc511af4e7d236206b90e8fbe1adfc7afe76c181cc4e9f01174a74116199342928da9dc02c01cc50efd151cbdd403d9f896820cb60992f200",
            "0x00206372de1e9b006b4104d57ee366871a32eed87731d7e6bcb2b84c605784ba072a84f0cee483739d84d15ba1b0f131900a20b41bc3b52e1b11af816095d49e34",
            "0x00174e396635f0b8a906f7cc100b51a0245e74d5f427559c9e69441e6da400a8bf22ee038cdac08f51b58437ec300d9dc770a48fd9641b9113421c1fbacff6138a",
            "0x00073e0a4f144235e0c633af855786c248253e46d7b7c7f6dbbfafd83f390d3d861aa806ff2c954aa869fe6a848ac72590ad10da1e68e5fbe4783e6ab94ff2b3db",
            "0x0021b159129c78d2e847315ef7cee7b48fa23ddd9062defa98fa8be74d077a471422de217a821ca10394e3c0f7a99762e37d87f50e2a61f48a154a26a4c4c7c5e7",
            "0x000ef81a6c68d20d9d29dd6322d851e57c54c031ac00ee05e60c2f21424d4924f62f6afcc93e210b7f5c85acb1490945135685af25ebaeb411565bec6e4b81b70d",
            "0x0025aab923d9a5a2d93978c98a1f5bb1a2ed1a57702b3e81e9da4e97a44c390bc70d2c7c546fc532f443e728bc9baf3c48c49573e4c724213a5c39c6a5f90e9ffe",
            "0x00240595687c8fa1172547dcc9450ef9f30519743088365ea537ff0a5a0263eef8213be0e1e5e5f6b999f07c9dccddbed71cf352f297d67020094bbc2b4dd94ce0",
            "0x002d8ce2cb06703649dcac18d3c618103fbfc0408d89a0e048b0a78d5d13e8c91b2fe8b70043185278f8f6c75d7057d75ebc62e82052f480dfc207de3b0e89700e",
            "0x0129bdbea092f4f7e6de593fd1a16ddb50b1c2a6297d4ae141a60f8da631e481750404000000000000000000000000000000000000000000000000000000000000000000df0056bc75e2d630ffffffffffffffffffffffffffffffffffff334673d90832bec5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470000000000000000000000000000000000000000000000000000000000000000000",
            "0x00206372de1e9b006b4104d57ee366871a32eed87731d7e6bcb2b84c605784ba072a84f0cee483739d84d15ba1b0f131900a20b41bc3b52e1b11af816095d49e34",
            "0x00174e396635f0b8a906f7cc100b51a0245e74d5f427559c9e69441e6da400a8bf22ee038cdac08f51b58437ec300d9dc770a48fd9641b9113421c1fbacff6138a",
            "0x000a4b711b871750b87b706e60a4cce1b5cc8c32528f02905144e6d4d2a2fb14590490ae4c72f6e1775acf6c6901461dbd1a15df1a3f362ee211604e2d496e7dba",
            "0x002c659c5727b02ba04ce36b8ea9e4701ef3ce84a8bd084dc87808a08c5fb3edea2d6d797a01bf7c0dd35870eeb62691e67339aff55f367fbb369b0c141d093fc5",
            "0x002dfc4306867ac67ea956f8d304c70d77f410a9cde3d52b1c189d389f48bbb90915569f5493240d886f181280e937c7d05358b285afc2c6e9f5310b8dbe149387",
            "0x0025e88c47733a9fd1047a8b2ade1012bff0f52e168141cdd4b7aedfee2011dbd22413161495eab27b3ece1a9942f7943855281b803366d697b325d163de111a8b",
            "0x010ae130046f9d7da44010613c1c787fe02536e75b661e3a39a379b44d700a15e3040400000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000c2455a35210099bbbb95bdd1b6a9bfc4702d98ba0f971009391cd8f970e72930245c87e64f9d2b7838df1c283a5cb371310f76ac0dfa8a796e4bcf0fd602d800",
    ];

    #[test]
    fn node_parse() {
        init_hash_scheme(hash_scheme);
        let nd = ZkTrieNode::parse(&hex::decode("012098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864010100000000000000000000000000000000000000000000000000000000018282256f8b00").unwrap());
        assert_eq!(
            hex::encode(nd.key()),
            "058c7a163389dea56e5efe3b57428428831a3aecfe0ed6a3f885c37bc8563b1c"
        );
        let nd = ZkTrieNode::parse(&hex::decode("0107061006b64441e81799d7fd6751ae26fed5347d31c0bb04d6b11052c9a6f7e1040400000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000029b74e075daad9f17eb39cd893c2dd32f52ecd99084d63964842defd00ebcbe2058c7a163389dea56e5efe3b57428428831a3aecfe0ed6a3f885c37bc8563b1c00").unwrap());
        assert_eq!(
            hex::encode(nd.key()),
            "2ed8f76e353a8fb28bf175f3e1cddc697407fd7c98632ce8642ca249964aabf1"
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

        let root = hex::decode("079a038fbf78f25a2590e5a1d2fa34ce5e5f30e9a332713b43fa0e51b8770ab8")
            .unwrap();
        let root: Hash = root.as_slice().try_into().unwrap();

        let mut trie = db.new_trie(&root).unwrap();
        assert_eq!(trie.root(), root);

        let acc_buf = hex::decode("4cb1aB63aF5D8931Ce09673EbD8ae2ce16fD6571").unwrap();

        let acc_data = trie.get_account(&acc_buf).unwrap();

        let mut nonce: StoreData =
            hex::decode("00000000000000000000000000000000000000000000000000000000000000df")
                .unwrap()
                .as_slice()
                .try_into()
                .unwrap();
        let balance: StoreData =
            hex::decode("0056bc75e2d630ffffffffffffffffffffffffffffffffffff334673d90832be")
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
        assert_eq!(acc_data[0], nonce);
        assert_eq!(acc_data[1], balance);
        assert_eq!(acc_data[2], code_hash);

        nonce[31] += 1;

        let newacc: AccountData = [nonce, balance, code_hash, [0; FIELDSIZE]];
        trie.update_account(&acc_buf, &newacc).unwrap();

        let acc_data = trie.get_account(&acc_buf).unwrap();
        assert_eq!(acc_data[0], nonce);
        assert_eq!(acc_data[1], balance);
        assert_eq!(acc_data[2], code_hash);

        let root = hex::decode("1f914fa71145a8722aa0dcac0fc12b8bd7993f8fdb804e7180d359865407c7ae")
            .unwrap();
        let root: Hash = root.as_slice().try_into().unwrap();
        assert_eq!(trie.root(), root);

        let acc_buf = hex::decode("080B18Cb659f0a532D679E660C9841E1E0991Ae1").unwrap();
        trie.update_account(&acc_buf, &newacc).unwrap();
        let root = hex::decode("18d64b82ab828eb0195a633c327e4e10efaaf65a131357289f7d38eee9c71cf4")
            .unwrap();
        let root: Hash = root.as_slice().try_into().unwrap();
        assert_eq!(trie.root(), root);

        trie.delete(&acc_buf);
        let root = hex::decode("1f914fa71145a8722aa0dcac0fc12b8bd7993f8fdb804e7180d359865407c7ae")
            .unwrap();
        let root: Hash = root.as_slice().try_into().unwrap();
        assert_eq!(trie.root(), root);

        let acc_buf = hex::decode("4cb1aB63aF5D8931Ce09673EbD8ae2ce16fD6571").unwrap();
        let proof = trie.prove(&acc_buf);

        assert_eq!(proof.len(), 10);
        assert_eq!(proof[9], hex::decode("5448495320495320534f4d45204d4147494320425954455320464f5220534d54206d3172525867503278704449").unwrap());
        assert_eq!(proof[3], hex::decode("0018ed59d5017a460600179c674f819292fe410f58d6ac8251a2d4b87fe4d0fb2422de217a821ca10394e3c0f7a99762e37d87f50e2a61f48a154a26a4c4c7c5e7").unwrap());

        let node = ZkTrieNode::parse(&proof[8]);
        assert_eq!(
            node.key().as_slice(),
            hex::decode("03913cd940cf5cf31a07b9b87d04d92eff246f76ab76d6a08806b1516d956973")
                .unwrap()
        );
        assert_eq!(
            node.value_hash().unwrap().as_slice(),
            hex::decode("02b84b0bd92ebd4dc276e06bd4041c94cfd58cdfe2ac82b09f944f90d5c9398d")
                .unwrap()
        );
    }
}
