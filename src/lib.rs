

#![feature(core_intrinsics)]
#![feature(asm)]

use std::mem::transmute;
use std::ptr::{
    read_unaligned
};
use std::intrinsics::{
    ctpop,
    likely,
    unlikely,
};

const MASK: u64 = 0x8080808080808080u64;

#[inline(always)]
fn pext(mask: u64, src: u64) -> u64 {
    let mut ret: u64;
    unsafe{
        asm!("pext rax, rsi, rdi"
         : "={rax}"(ret)
         : "{rsi}"(src), "{rdi}"(mask)
         : "rax", "rdi", "rsi"
         : "intel");
    }
    ret
}

#[test]
fn test_pext() {
    //ensure I understand wtf I'm doing
    assert_eq!( pext(0xFF,0xFFFF), 0xFF);
    assert_eq!( pext(0x00,0xFFFF), 0x00);
    assert_eq!( pext(0xF80F,0xFFFF), 0x1FF);
}

/// Attempts to read a full length varint
///
/// This method will fail if the varint requires 10bytes,
/// or the provided buffer is smaller then 8 bytes long.
#[inline(always)]
pub fn get_var_int(buffer: &[u8]) -> Option<u64> {
    unsafe {
        if unlikely(buffer.len() < 8) {
            return None;
        }
        let ptr: *const u8 = buffer.as_ptr();       
        let value: u64 = read_unaligned(transmute(ptr));
        let var = ctpop(value.clone() & MASK.clone());
        let mask: u64 = match var {
            0 => 0x7F,
            1 => 0x7F7F,
            2 => 0x7F7F7F,
            3 => 0x7F7F7F7F,
            4 => 0x7F7F7F7F7F,
            5 => 0x7F7F7F7F7F7F,
            6 => 0x7F7F7F7F7F7F7F,
            7 => 0x7F7F7F7F7F7F7F7F,
            _ => return None
        };
        Some(pext(mask, value))
    }
}


/// Attempts to read a 32bit varint
///
/// # None returned
///
/// * `buffer.len() < 8` this prevents fast dereference magic
/// * var int is `>5` bytes long encoded. This means its `>u32::MAX`
///
/// # Weird edge case
///
/// If the value is `>u32::MAX` it'll be AND masked to `u32::MAX`.
/// This _shouldnt_ happen, but the encoding standard allows it too.
#[inline(always)]
pub fn get_var_int32(buffer: &[u8]) -> Option<u32> {
    unsafe {
        if unlikely(buffer.len() < 8) {
            return None;
        }
        let ptr: *const u8 = buffer.as_ptr();       
        let value: u64 = read_unaligned(transmute(ptr));
        let var = ctpop(value.clone() & MASK.clone());
        let mask: u64 = match var {
            0 => 0x7F,
            1 => 0x7F7F,
            2 => 0x7F7F7F,
            3 => 0x7F7F7F7F,
            4 => 0x7F7F7F7F7F,
            5 => 0x7F7F7F7F7F7F,
            _ => return None
        };
        let var = pext(mask,value) & (u32::MAX as u64);
        Some(var as u32)
    }
}



#[test]
pub fn test_get_var_int() {

    macro_rules! do_test {
        ($arr: expr, $val: expr) => {
            if $arr.len() != 8 {
                panic!("Length of {} is not 8 but {:?}", stringify!($arr), $arr.len());
            }
            match get_var_int($arr) {
                Option::None => panic!("Array {} contents {:?} returned None", stringify!($arr), $arr),
                Option::Some(var) => {
                    if var != $val {
                        panic!("Return value from {:?} is {:?} but doesn't equal assertion {:?}", $arr, var, $val);
                    }
                }
            };
        }
    }
   
    let trivial0 = &[0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00];
    do_test!(trivial0, 0u64);

    let trivial1 = &[0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00];
    do_test!(trivial1, 1u64);

    let trivial2 = &[0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00];
    do_test!(trivial2, 2u64);

    let trivial3 = &[0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00];
    do_test!(trivial3, 3u64);

    let trivial127 = &[0x7F,0x00,0x00,0x00,0x00,0x00,0x00,0x00];
    do_test!(trivial127, 127u64);
    
    let trivial = &[0xAC,0x02,0x00,0x00,0x00,0x00,0x00,0x00];
    do_test!(trivial, 300u64);
    
    let trivial = &[0x96,0x01,0x00,0x00,0x00,0x00,0x00,0x00];
    do_test!(trivial, 150u64);
}








