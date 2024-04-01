use crate::{raw::ImplError, types::Hashable};
use std::fmt::Debug;

pub trait Hash: AsRef<[u8]> + AsMut<[u8]> + Default + Clone + Debug + PartialEq {
    const LEN: usize;

    fn is_valid(&self) -> bool {
        true
    }
    fn zero() -> Self {
        Default::default()
    }
    fn simple_hash_scheme(a: [u8; 32], b: [u8; 32], domain: u64) -> Self;
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct AsHash<T>(T);

impl<T> AsHash<T> {
    pub fn take(self) -> T {
        self.0
    }
}

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
        return key.as_ref()[T::LEN - pos / 8 - 1] & (1 << (pos % 8)) != 0;
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.as_ref()[0..T::LEN].to_vec()
    }

    fn hash_zero() -> Self {
        Self(T::zero())
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, ImplError> {
        if bytes.len() > T::LEN {
            Err(ImplError::ErrNodeBytesBadSize)
        } else {
            let padding = T::LEN - bytes.len();
            let mut h = Self::hash_zero();
            h.as_mut()[padding..].copy_from_slice(bytes);
            if Self::check_in_field(&h) {
                Ok(h)
            } else {
                Err(ImplError::ErrNodeBytesBadSize)
            }
        }
    }

    fn hash_elems_with_domain(
        domain: u64,
        lbytes: &Self,
        rbytes: &Self,
    ) -> Result<Self, ImplError> {
        let h = Self(T::simple_hash_scheme(
            lbytes.as_ref().try_into().expect("same length"),
            rbytes.as_ref().try_into().expect("same length"),
            domain,
        ));
        if Self::check_in_field(&h) {
            Ok(h)
        } else {
            Err(ImplError::ErrNodeBytesBadSize)
        }
    }
}

#[cfg(test)]
pub use tests::HashImpl;

#[cfg(test)]
mod tests {
    use crate::types::{Hashable, Node, TrieHashScheme};

    use ff::PrimeField;
    use halo2_proofs::pairing::bn256::Fr;
    use poseidon::Poseidon;

    lazy_static::lazy_static! {
        pub static ref POSEIDON_HASHER: poseidon::Poseidon<Fr, 9, 8> = Poseidon::<Fr, 9, 8>::new(8, 63);
    }

    const HASH_BYTE_LEN: usize = 32;

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
        const LEN: usize = HASH_BYTE_LEN;

        //todo replace with poseidon hash
        fn simple_hash_scheme(a: [u8; 32], b: [u8; 32], domain: u64) -> Self {
            let mut hasher = POSEIDON_HASHER.clone();
            hasher.update(&[
                Fr::from_repr(a).unwrap(),
                Fr::from_repr(b).unwrap(),
                Fr::from(domain),
            ]);
            Hash(hasher.squeeze().to_repr())
        }

        fn is_valid(&self) -> bool {
            Fr::from_repr(self.0).is_some().into()
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
        assert_eq!(HashImpl::from_bytes(&byte).unwrap(), h);
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
                &HashImpl::from_bytes(&bytes[2 * i]).unwrap(),
                &HashImpl::from_bytes(&bytes[2 * i + 1]).unwrap(),
            );
            assert!(ret.is_ok());
        }
        let ret = Node::<HashImpl>::handling_elems_and_bytes32(65535, &bytes);
        assert!(ret.is_ok());
    }

    #[test]
    fn test_hash_scheme() {
        //fill poseidon hash result when move to zk
        //todo!();
    }
}
