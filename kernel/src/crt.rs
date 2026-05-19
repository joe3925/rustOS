use core::ffi::c_void;
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
pub unsafe extern "C" fn strlen(string: *const u8) -> usize {
    let mut len = 0;

    while unsafe { string.add(len).read_volatile() } != 0 {
        len += 1;
    }

    len
}
#[unsafe(no_mangle)]
pub extern "C" fn fmodf(x: f32, y: f32) -> f32 {
    libm::fmodf(x, y)
}

#[unsafe(no_mangle)]
pub extern "C" fn fmod(x: f64, y: f64) -> f64 {
    libm::fmod(x, y)
}
#[unsafe(no_mangle)]
pub extern "C" fn fma(x: f64, y: f64, z: f64) -> f64 {
    libm::fma(x, y, z)
}

#[unsafe(no_mangle)]
pub extern "C" fn fmaf(x: f32, y: f32, z: f32) -> f32 {
    libm::fmaf(x, y, z)
}
