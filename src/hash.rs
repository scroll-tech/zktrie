use crate::{types::Hashable, raw::ImplError};



const HASH_BYTE_LEN: usize = 32;
const HASH_DOMAIN_ELEMS_BASE: usize = 256;
const HASH_DOMAIN_BYTE32: usize = 2 * HASH_DOMAIN_ELEMS_BASE;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Hash(pub(crate) [u8; HASH_BYTE_LEN]);

impl Hash {
    //todo replace with poseidon hash
    fn simple_hash_scheme(a: &[u8; 32], b: &[u8; 32], domain: u64) -> Self{
        let mut h = Self::hash_zero();
        h.0[0..12].copy_from_slice(&a[4..16]);
        h.0[12..20].copy_from_slice(&u64::to_le_bytes(domain).to_vec()[..]);
        h.0[20..32].copy_from_slice(&b[16..28]);
        h
    }

    fn simple_hash_byte32(b: &[u8; 32]) -> Self{
        Self::simple_hash_scheme(b, b, HASH_DOMAIN_BYTE32 as u64)
    }
}


impl Hashable for Hash {
    fn check_in_field(hash: &Self) -> bool {
        let limit = [1u8, 0, 0, 240, 147, 245, 225, 67, 145, 112, 185, 121, 72, 232, 51, 40, 93, 88, 129, 129, 182, 69, 80, 184, 41, 160, 49, 225, 114, 78, 100, 48];
        let mut ret = false;
        for i in 0..HASH_BYTE_LEN {
            if hash.0[HASH_BYTE_LEN - i - 1] != limit[HASH_BYTE_LEN - i - 1] {
                ret = hash.0[HASH_BYTE_LEN - i - 1] < limit[HASH_BYTE_LEN - i - 1];
                break;
            }
        }
        ret
    }

    fn test_bit(key: &Self, pos: usize) -> bool {
        return key.0[pos/8]&(1<<(pos%8)) != 0
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0[0..HASH_BYTE_LEN].to_vec()
    }

    fn hash_zero() -> Self {
        Hash([0; HASH_BYTE_LEN])
    }

    fn hash_from_bytes(bytes: &Vec<u8>) -> Result<Self, ImplError> {
        if bytes.len() > HASH_BYTE_LEN {
            Err(ImplError::ErrNodeBytesBadSize)
        } else {
            let mut h = Self::hash_zero();
            h.0[0..HASH_BYTE_LEN].copy_from_slice(&bytes.to_vec()[..]);
            if Self::check_in_field(&h) {
                Ok(h)
            } else {
                Err(ImplError::ErrNodeBytesBadSize)
            }
        }
    }

    fn hash_elems_with_domain(domain: u64, lbytes: &Option<Self>, rbytes: &Option<Self>) -> Result<Self, ImplError> {
        let l = &lbytes.as_ref().unwrap().to_bytes()[..];
        let r = &rbytes.as_ref().unwrap().to_bytes()[..];
        let h = Self::simple_hash_scheme(l.try_into().unwrap(), r.try_into().unwrap(), domain);
        if Self::check_in_field(&h) {
            Ok(h)
        } else {
            Err(ImplError::ErrNodeBytesBadSize)
        }
    }

    fn handling_elems_and_bytes32(flags: u32, bytes: &Vec<[u8; 32]>) -> Result<Self, ImplError> {
        let mut tmp = vec![];
        let mut err = false;
        for i in 0..bytes.len() {
            if flags & (1 << i) != 0 {
                tmp.push(Self::simple_hash_byte32(&bytes[i]));
            } else {
                let h = Self::hash_from_bytes(&bytes[i].to_vec());
                if h.is_ok() {
                    tmp.push(h?);
                } else {
                    err = true;
                    break;
                }
            }
        }
        if !err {
            let domain = bytes.len() * HASH_DOMAIN_ELEMS_BASE + HASH_DOMAIN_BYTE32;
            for _ in 0..bytes.len()-1 {
                let a = tmp.pop();
                let b = tmp.pop();
                let h = Self::hash_elems_with_domain(domain as u64, &a, &b);
                if h.is_ok() {
                    tmp.push(h?);
                } else {
                    err = true;
                    break;
                }
            }
        }

        if !err {
            Ok(tmp.pop().unwrap())
        } else {
            Err(ImplError::ErrNodeBytesBadSize)
        }
    }

}

#[cfg(test)]
mod tests{
    use crate::types::Hashable;
    use super::{HASH_BYTE_LEN, Hash};

    #[test]
    fn test_hash_byte() {
        let mut byte = vec![];
        let mut h = Hash::hash_zero();
        for i in 0..HASH_BYTE_LEN {
            byte.push(i as u8);
            h.0[i] = i as u8;
        }
        assert_eq!(h.to_bytes(), byte);
        assert_eq!(Hash::hash_from_bytes(&byte).unwrap(), h);
    }

    #[test]
    fn test_hash_domain() {
        let domain: u64 = 16;
        let mut bytes = vec![];
        for i in 0..16 {
            bytes.push([i as u8; 32]);
        }
        for i in 0..8 {
            let ret = Hash::hash_elems_with_domain(domain, &Some(Hash::hash_from_bytes(&bytes[2*i].to_vec()).unwrap()),
                                                                                    &Some(Hash::hash_from_bytes(&bytes[2*i+1].to_vec()).unwrap()));
            assert!(ret.is_ok());
        }
        let ret = Hash::handling_elems_and_bytes32(65535, &bytes);
        assert!(ret.is_ok());
    }

    #[test]
    fn test_hash_scheme() {
        //fill poseidon hash result when move to zk
        todo!();
    }
}



