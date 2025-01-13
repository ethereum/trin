use ssz_types::{typenum, VariableList};

pub type ByteList32 = VariableList<u8, typenum::U32>;
pub type ByteList1024 = VariableList<u8, typenum::U1024>;
pub type ByteList2048 = VariableList<u8, typenum::U2048>;
pub type ByteList32K = VariableList<u8, typenum::U32768>;
pub type ByteList1G = VariableList<u8, typenum::U1073741824>;
