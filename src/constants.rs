pub const HASHLEN: usize = 32;
pub const FIELDSIZE: usize = 32;
pub const ACCOUNTFIELDS: usize = 5;
pub const ACCOUNTSIZE: usize = FIELDSIZE * ACCOUNTFIELDS;
pub type Hash = [u8; HASHLEN];
pub type StoreData = [u8; FIELDSIZE];
pub type AccountData = [[u8; FIELDSIZE]; ACCOUNTFIELDS];
