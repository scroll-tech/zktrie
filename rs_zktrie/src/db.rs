use crate::raw::ImplError;
use std::collections::HashMap;
use std::rc::Rc;

pub trait ZktrieDatabase: Clone {
    fn put(&mut self, k: Vec<u8>, v: Vec<u8>) -> Result<(), ImplError>;
    fn get(&self, k: &[u8]) -> Result<Rc<[u8]>, ImplError>;
}

#[derive(Clone, Default)]
pub struct SimpleDb {
    db: HashMap<Box<[u8]>, Rc<[u8]>>,
}

impl SimpleDb {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ZktrieDatabase for SimpleDb {
    fn put(&mut self, k: Vec<u8>, v: Vec<u8>) -> Result<(), ImplError> {
        self.db.insert(k.into_boxed_slice(), Rc::from(v.into_boxed_slice()));
        Ok(())
    }

    fn get(&self, k: &[u8]) -> Result<Rc<[u8]>, ImplError> {
        self.db.get(k).cloned().ok_or(ImplError::ErrKeyNotFound)
    }
}

#[cfg(test)]
mod test {
    use super::{SimpleDb, ZktrieDatabase};

    #[test]
    fn test_db() {
        let k1 = [1u8; 32].to_vec();
        let k2 = [3u8; 32].to_vec();
        let v1 = [2u8; 256].to_vec();
        let v2 = [4u8; 256].to_vec();
        let mut d = SimpleDb::new();
        d.put(k1.clone(), v1.clone()).unwrap();
        d.put(k2.clone(), v2.clone()).unwrap();
        let v0 = d.get(&k1).unwrap();
        assert_eq!(v0.as_ref(), v1.as_slice());
        let v0 = d.get(&k2).unwrap();
        assert_eq!(v0.as_ref(), v2.as_slice());
    }
}
