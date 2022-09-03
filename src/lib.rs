


#[link(name = "zktrie")]
extern {
    fn TestHashScheme();
    fn InitHashScheme(f: extern fn(*const u8, *const u8, *mut u8) -> *const u8);
}


#[cfg(test)]
mod tests {

    use super::*;
    use halo2_proofs::pairing::bn256::Fr;
    use halo2_proofs::arithmetic::BaseExt;
    use mpt_circuits::hash::Hashable;

    static HASH_ERROR: &'static str = "error";


    extern "C" fn hash_scheme(a: *const u8, b: *const u8, out: *mut u8) -> *const u8{
        use std::slice;
        let mut a = unsafe { slice::from_raw_parts(a, 32)};
        let mut b = unsafe { slice::from_raw_parts(b, 32)};
        let mut out = unsafe { slice::from_raw_parts_mut(out, 32)};

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
