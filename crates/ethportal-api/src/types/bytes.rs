use ssz_types::{
    typenum::{self, UInt, UTerm, B0, B1},
    VariableList,
};

// 1100 in binary is 10001001100
pub type U1100 = UInt<
    UInt<
        UInt<
            UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B1>, B0>, B0>, B1>,
            B1,
        >,
        B0,
    >,
    B0,
>;

pub type ByteList32 = VariableList<u8, typenum::U32>;
pub type ByteList1024 = VariableList<u8, typenum::U1024>;
pub type ByteList1100 = VariableList<u8, U1100>;
pub type ByteList2048 = VariableList<u8, typenum::U2048>;
pub type ByteList32K = VariableList<u8, typenum::U32768>;
pub type ByteList1G = VariableList<u8, typenum::U1073741824>;
