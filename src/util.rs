
pub(crate) fn int_to_bytes(n: i64) -> &'static [u8] {
    static mut BUFFER: [u8; 12] = [0; 12];
    let mut i = 11;
    let mut num = if n < 0 { -n } else { n };

    unsafe {
        if num == 0 {
            BUFFER[i] = b'0';
            i -= 1;
        } else {
            while num > 0 {
                BUFFER[i] = b'0' + (num % 10) as u8;
                num /= 10;
                i -= 1;
            }
        }

        if n < 0 {
            BUFFER[i] = b'-';
            i -= 1;
        }

        &BUFFER[i+1..]
    }
}
