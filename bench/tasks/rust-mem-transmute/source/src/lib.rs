use std::mem;

pub fn reinterpret_bits_vulnerable(x: u64) -> f64 {
    unsafe { mem::transmute(x) }
}

pub fn reinterpret_std_vulnerable(x: i32) -> u32 {
    unsafe { std::mem::transmute(x) }
}

pub fn convert_safe(x: u64) -> f64 {
    f64::from_bits(x)
}
