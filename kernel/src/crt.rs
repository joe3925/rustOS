use core::ffi::{c_int, c_void};
use core::ptr;

#[no_mangle]
pub static mut _tls_index: u32 = 0;

#[repr(C)]
struct ImageTlsDirectory64 {
    start_address_of_raw_data: *const c_void,
    end_address_of_raw_data: *const c_void,
    address_of_index: *const c_void,
    address_of_callbacks: *const c_void,
    size_of_zero_fill: u32,
    characteristics: u32,
}

unsafe impl Sync for ImageTlsDirectory64 {}

#[repr(transparent)]
struct TlsCallback(*const c_void);

unsafe impl Sync for TlsCallback {}

#[used]
#[no_mangle]
// Rust emits COFF TLS data into .tls$; exact .tls sorts before it and becomes
// the base used by the compiler's SECREL32 TLS offsets.
#[link_section = ".tls"]
static mut _tls_start: usize = 0;

#[used]
#[no_mangle]
#[link_section = ".tls$ZZZ"]
static mut _tls_end: usize = 0;

#[used]
#[no_mangle]
#[link_section = ".CRT$XLA"]
static __xl_a: TlsCallback = TlsCallback(ptr::null());

#[used]
#[no_mangle]
#[link_section = ".CRT$XLZ"]
static __xl_z: TlsCallback = TlsCallback(ptr::null());

#[used]
#[no_mangle]
#[link_section = ".rdata$T"]
static _tls_used: ImageTlsDirectory64 = ImageTlsDirectory64 {
    start_address_of_raw_data: ptr::addr_of!(_tls_start).cast(),
    end_address_of_raw_data: ptr::addr_of!(_tls_end).cast(),
    address_of_index: ptr::addr_of!(_tls_index).cast(),
    address_of_callbacks: unsafe { ptr::addr_of!(__xl_a).add(1).cast() },
    size_of_zero_fill: 0,
    characteristics: 0,
};

#[no_mangle]
pub unsafe extern "C" fn memcpy(
    dest: *mut c_void,
    src: *const c_void,
    count: usize,
) -> *mut c_void {
    let dest_bytes = dest.cast::<u8>();
    let src_bytes = src.cast::<u8>();

    let mut index = 0;
    while index < count {
        unsafe {
            dest_bytes
                .add(index)
                .write_volatile(src_bytes.add(index).read_volatile());
        }
        index += 1;
    }

    dest
}

#[no_mangle]
pub unsafe extern "C" fn memmove(
    dest: *mut c_void,
    src: *const c_void,
    count: usize,
) -> *mut c_void {
    let dest_bytes = dest.cast::<u8>();
    let src_bytes = src.cast::<u8>();
    let dest_addr = dest as usize;
    let src_addr = src as usize;

    if dest_addr <= src_addr || dest_addr >= src_addr.wrapping_add(count) {
        let mut index = 0;
        while index < count {
            unsafe {
                dest_bytes
                    .add(index)
                    .write_volatile(src_bytes.add(index).read_volatile());
            }
            index += 1;
        }
    } else {
        let mut index = count;
        while index != 0 {
            index -= 1;
            unsafe {
                dest_bytes
                    .add(index)
                    .write_volatile(src_bytes.add(index).read_volatile());
            }
        }
    }

    dest
}

#[no_mangle]
pub unsafe extern "C" fn memset(dest: *mut c_void, value: c_int, count: usize) -> *mut c_void {
    let dest_bytes = dest.cast::<u8>();
    let value = value as u8;

    let mut index = 0;
    while index < count {
        unsafe {
            dest_bytes.add(index).write_volatile(value);
        }
        index += 1;
    }

    dest
}

#[no_mangle]
pub unsafe extern "C" fn memcmp(left: *const c_void, right: *const c_void, count: usize) -> c_int {
    let left_bytes = left.cast::<u8>();
    let right_bytes = right.cast::<u8>();

    let mut index = 0;
    while index < count {
        let left_value = unsafe { left_bytes.add(index).read_volatile() };
        let right_value = unsafe { right_bytes.add(index).read_volatile() };

        if left_value != right_value {
            return left_value as c_int - right_value as c_int;
        }

        index += 1;
    }

    0
}

#[no_mangle]
pub unsafe extern "C" fn strlen(string: *const u8) -> usize {
    let mut len = 0;

    while unsafe { string.add(len).read_volatile() } != 0 {
        len += 1;
    }

    len
}

#[no_mangle]
pub extern "C" fn fmodf(left: f32, right: f32) -> f32 {
    const SIGN_MASK: u32 = 0x8000_0000;
    const EXP_MASK: u32 = 0x7f80_0000;
    const FRACTION_MASK: u32 = 0x007f_ffff;
    const HIDDEN_BIT: u32 = 0x0080_0000;

    let left_bits = left.to_bits();
    let right_bits = right.to_bits();
    let sign = left_bits & SIGN_MASK;
    let left_abs = left_bits & !SIGN_MASK;
    let right_abs = right_bits & !SIGN_MASK;

    if right_abs == 0 || left_abs >= EXP_MASK || right_abs > EXP_MASK {
        return f32::NAN;
    }
    if left_abs < right_abs {
        return left;
    }
    if left_abs == right_abs {
        return f32::from_bits(sign);
    }

    let (mut left_exp, mut left_mantissa) = normalize_f32_parts(left_abs);
    let (right_exp, right_mantissa) = normalize_f32_parts(right_abs);

    while left_exp > right_exp {
        let difference = left_mantissa.wrapping_sub(right_mantissa);
        if difference & SIGN_MASK == 0 {
            if difference == 0 {
                return f32::from_bits(sign);
            }
            left_mantissa = difference;
        }

        left_mantissa <<= 1;
        left_exp -= 1;
    }

    let difference = left_mantissa.wrapping_sub(right_mantissa);
    if difference & SIGN_MASK == 0 {
        if difference == 0 {
            return f32::from_bits(sign);
        }
        left_mantissa = difference;
    }

    while left_mantissa & HIDDEN_BIT == 0 {
        left_mantissa <<= 1;
        left_exp -= 1;
    }

    if left_exp > 0 {
        f32::from_bits(sign | ((left_exp as u32) << 23) | (left_mantissa & FRACTION_MASK))
    } else {
        let shift = (1 - left_exp) as u32;
        let mantissa = if shift < u32::BITS {
            left_mantissa >> shift
        } else {
            0
        };
        f32::from_bits(sign | mantissa)
    }
}

fn normalize_f32_parts(abs_bits: u32) -> (i32, u32) {
    const FRACTION_MASK: u32 = 0x007f_ffff;
    const HIDDEN_BIT: u32 = 0x0080_0000;

    let mut exponent = ((abs_bits >> 23) & 0xff) as i32;
    let mut mantissa = abs_bits & FRACTION_MASK;

    if exponent == 0 {
        while mantissa & HIDDEN_BIT == 0 {
            mantissa <<= 1;
            exponent -= 1;
        }
    } else {
        mantissa |= HIDDEN_BIT;
    }

    (exponent, mantissa)
}
