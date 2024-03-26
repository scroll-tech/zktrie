use crate::{raw::ImplError, types::Hashable};
use std::fmt::Debug;

const HASH_BYTE_LEN: usize = 32;
const HASH_DOMAIN_ELEMS_BASE: usize = 256;
const HASH_DOMAIN_BYTE32: usize = 2 * HASH_DOMAIN_ELEMS_BASE;

pub trait Hash: AsRef<[u8]> + AsMut<[u8]> + Default + Clone + Debug + PartialEq {
    fn is_valid(&self) -> bool {
        true
    }
    fn zero() -> Self;
    fn simple_hash_scheme(a: &[u8; 32], b: &[u8; 32], domain: u64) -> Self;
    fn simple_hash_byte32(b: &[u8; 32]) -> Self {
        Self::simple_hash_scheme(b, b, HASH_DOMAIN_BYTE32 as u64)
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct AsHash<T>(T);

impl<T: Hash> AsRef<[u8]> for AsHash<T> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<T: Hash> AsMut<[u8]> for AsHash<T> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl<T: Hash> Hashable for AsHash<T> {
    fn check_in_field(hash: &Self) -> bool {
        hash.0.is_valid()
    }

    fn test_bit(key: &Self, pos: usize) -> bool {
        return key.as_ref().as_ref()[pos / 8] & (1 << (pos % 8)) != 0;
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.as_ref()[0..HASH_BYTE_LEN].to_vec()
    }

    fn hash_zero() -> Self {
        Self(T::zero())
    }

    fn hash_from_bytes(bytes: &Vec<u8>) -> Result<Self, ImplError> {
        if bytes.len() > HASH_BYTE_LEN {
            Err(ImplError::ErrNodeBytesBadSize)
        } else {
            let padding = HASH_BYTE_LEN - bytes.len();
            let mut b = bytes.clone();
            for _ in 0..padding {
                b.push(0u8);
            }
            let mut h = Self::hash_zero();
            h.as_mut()[0..HASH_BYTE_LEN].copy_from_slice(&b.to_vec()[..]);
            if Self::check_in_field(&h) {
                Ok(h)
            } else {
                Err(ImplError::ErrNodeBytesBadSize)
            }
        }
    }

    fn hash_elems_with_domain(
        domain: u64,
        lbytes: &Option<Self>,
        rbytes: &Option<Self>,
    ) -> Result<Self, ImplError> {
        let l = &lbytes.as_ref().unwrap().to_bytes()[..];
        let r = &rbytes.as_ref().unwrap().to_bytes()[..];
        let h = Self(T::simple_hash_scheme(
            l.try_into().unwrap(),
            r.try_into().unwrap(),
            domain,
        ));
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
                tmp.push(Self(T::simple_hash_byte32(&bytes[i])));
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
            for _ in 0..bytes.len() - 1 {
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
mod tests {
    use super::{HASH_BYTE_LEN, HASH_DOMAIN_BYTE32};
    use crate::types::Hashable;

    use ff::PrimeField;
    use halo2_proofs::pairing::bn256::Fr;
    use poseidon::Poseidon;

    lazy_static::lazy_static! {
        pub static ref POSEIDON_HASHER: poseidon::Poseidon<Fr, 9, 8> = Poseidon::<Fr, 9, 8>::new(8, 63);
    }

    #[derive(Clone, Debug, Default, PartialEq)]
    pub struct Hash(pub(crate) [u8; HASH_BYTE_LEN]);

    impl AsRef<[u8]> for Hash {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    impl AsMut<[u8]> for Hash {
        fn as_mut(&mut self) -> &mut [u8] {
            &mut self.0
        }
    }

    impl super::Hash for Hash {
        //todo replace with poseidon hash
        fn simple_hash_scheme(a: &[u8; 32], b: &[u8; 32], domain: u64) -> Self {
            let mut hasher = POSEIDON_HASHER.clone();
            hasher.update(&[
                Fr::from_repr(a.clone()).unwrap(),
                Fr::from_repr(b.clone()).unwrap(),
                Fr::from(domain),
            ]);
            Hash(hasher.squeeze().to_repr())
        }

        fn simple_hash_byte32(b: &[u8; 32]) -> Self {
            Self::simple_hash_scheme(b, b, HASH_DOMAIN_BYTE32 as u64)
        }

        fn is_valid(&self) -> bool {
            if Fr::from_repr(self.0).is_some().into() {
                return true;
            } else {
                return false;
            }
        }
        fn zero() -> Self {
            Self([0; HASH_BYTE_LEN])
        }
    }

    pub type HashImpl = super::AsHash<Hash>;

    #[test]
    fn test_hash_byte() {
        let mut byte = vec![];
        let mut h = HashImpl::hash_zero();
        for i in 0..HASH_BYTE_LEN {
            byte.push(i as u8);
            h.as_mut()[i] = i as u8;
        }
        assert_eq!(h.to_bytes(), byte);
        assert_eq!(HashImpl::hash_from_bytes(&byte).unwrap(), h);
    }

    #[test]
    fn test_hash_domain() {
        let domain: u64 = 16;
        let mut bytes = vec![];
        for i in 0..16 {
            bytes.push([i as u8; 32]);
        }
        for i in 0..8 {
            let ret = HashImpl::hash_elems_with_domain(
                domain,
                &Some(HashImpl::hash_from_bytes(&bytes[2 * i].to_vec()).unwrap()),
                &Some(HashImpl::hash_from_bytes(&bytes[2 * i + 1].to_vec()).unwrap()),
            );
            assert!(ret.is_ok());
        }
        let ret = HashImpl::handling_elems_and_bytes32(65535, &bytes);
        assert!(ret.is_ok());
    }

    #[test]
    fn test_hash_scheme() {
        //fill poseidon hash result when move to zk
        //todo!();
    }
}

#[cfg(test)]
pub use tests::HashImpl;
