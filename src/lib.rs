

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

#[inline(always)]
fn pdep(mask: u64, src: u64) -> u64 {
    let mut ret: u64;
    unsafe{
        asm!("pdep rax, rsi, rdi"
         : "={rax}"(ret)
         : "{rsi}"(src), "{rdi}"(mask)
         : "rax", "rdi", "rsi"
         : "intel");
    }
    ret
}

#[test]
fn validate_pdep() {
    //ensure I understand how this works
    assert_eq!(pdep(0x7F7Fu64, 0x80u64), 0x0100u64);
}

/// Attempts to read a full length varint
///
/// This method will fail if the varint requires 10bytes,
/// or the provided buffer is smaller then 8 bytes long.
#[inline(always)]
pub fn decode_var_int(buffer: &[u8]) -> Option<u64> {
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

/// Failes to encode values that are longer then 8bytes
pub fn encode_var_int(x: u64) -> Option<Vec<u8>> {
    let (mask,finalize) = match (x.clone()) {
        0...0x7F => (0x7F,0x00),
        0x80...0x3FFF => (0x7F7F,0x8000),
        0x4000...0x1FFFFF => (0x7F7F7F,0x808000),
        0x200000...0xFFFFFFF => (0x7F7F7F7F,0x80808000),
        0x10000000...0x7FFFFFFFF => (0x7F7F7F7F7F,0x8080808000),
        0x800000000...0x3FFFFFFFFFF => (0x7F7F7F7F7F7F,0x808080808000),
        0x40000000000...0x1FFFFFFFFFFFF => (0x7F7F7F7F7F7F7F,0x80808080808000),
        0x2000000000000...0xFFFFFFFFFFFFFF => (0x7F7F7F7F7F7F7F7F,0x8080808080808000),
        _ => return None
    };
    let out = pdep(mask,x) | finalize;
    let ptr: &[u8] = unsafe{transmute( (&out, 8usize))};
    let mut v = ptr.to_vec(); 
    for _ in v.len()..8 {
        v.push(0u8);
    }
    Some(v)
}

#[test]
pub fn test_decode_var_int() {

    macro_rules! do_test {
        ($arr: expr, $val: expr) => {
            if $arr.len() != 8 {
                panic!("Length of {} is not 8 but {:?}", stringify!($arr), $arr.len());
            }
            match decode_var_int($arr) {
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


#[test]
pub fn reflect_value() {

    for i in 0..::std::u32::MAX {
        let var = i as u64;
        let buf = match encode_var_int(var.clone()) {
            Option::None => panic!("Failed to encode {:?}", var.clone()),
            Option::Some(x) => x,
        };
        match decode_var_int(&buf) {
            Option::None => panic!("Decode arr {:?} paniced on value {:?}", &buf, &var),
            Option::Some(out) => {
                if out != var {
                    panic!("Value in was {:?} array was {:?} value out was {:?}", var, &buf, out); 
                }
            }
        };
    }
}





