use crate::raw::ImplError;
use std::collections::HashMap;
pub trait ZktrieDatabase : Clone {
    fn put(&mut self, k: &Vec<u8>, v: &Vec<u8>) -> Result<(), ImplError> ;
    fn get(&self, k: &Vec<u8>) -> Result<Option<Vec<u8>>, ImplError> ;
}

#[derive (Clone)]
pub struct SimpleDb {
    db: HashMap<String, String>,
}


impl SimpleDb {
    pub fn new() -> Self{
        let m: HashMap<String, String> = HashMap::new();
        SimpleDb {
            db: m,
        }
    }
}

impl ZktrieDatabase for SimpleDb {
    fn put(&mut self, k: &Vec<u8>, v: &Vec<u8>) -> Result<(), ImplError>  {
        let string_k = String::from_utf8(k.clone()).unwrap();
        let string_v = String::from_utf8(v.clone()).unwrap();
        self.db.insert(string_k, string_v);
        Ok(())
    }

    fn get(&self, k: &Vec<u8>) -> Result<Option<Vec<u8>>, ImplError>  {
        let string_k = String::from_utf8(k.clone()).unwrap();
        let ret = self.db.get(&string_k);
        match ret {
            Some(string_v) => {
                Ok(Some(string_v.as_bytes().to_vec()))
            },
            None => {
                Err(ImplError::ErrKeyNotFound)
            }
        }
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
        d.put(&k1, &v1).unwrap();
        d.put(&k2, &v2).unwrap();
        let v0 = d.get(&k1).unwrap().unwrap();
        assert_eq!(v0, v1);
        let v0 = d.get(&k2).unwrap().unwrap();
        assert_eq!(v0, v2);
    }
}

