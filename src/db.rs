use crate::raw::ImplError;

pub trait ZktrieDatabase {
    fn put(&mut self, k: &Vec<u8>, v: &Vec<u8>) -> Result<(), ImplError> ;
    fn get(&self, k: &Vec<u8>) -> Result<Option<Vec<u8>>, ImplError> ;
}
