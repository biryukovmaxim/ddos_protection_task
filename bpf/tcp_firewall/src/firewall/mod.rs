use cty::*;

pub const SYN: u16 = 2; // 2u16

// This is where you should define the types shared by the kernel and user
// space, eg:
//
// #[repr(C)]
// #[derive(Debug)]
// pub struct SomeEvent {
//     pub pid: u64,
//     ...
// }
