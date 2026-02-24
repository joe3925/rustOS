const I8042_DATA: u16 = 0x60;
const I8042_STS: u16 = 0x64;
const I8042_CMD: u16 = 0x64;

const STS_OBF: u8 = 1 << 0;
const STS_IBF: u8 = 1 << 1;

unsafe fn inb(p: u16) -> u8 {
    unsafe {
        let v: u8;
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!("in al, dx", in("dx") p, out("al") v, options(nomem, nostack, preserves_flags));
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = p;
            v = 0;
        }
        v
    }
}
unsafe fn outb(p: u16, v: u8) {
    unsafe {
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!("out dx, al", in("dx") p, in("al") v, options(nomem, nostack, preserves_flags));
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = (p, v);
        }
    }
}

unsafe fn wait_ibf_clear(timeout_iters: u32) -> bool {
    unsafe {
        let mut i = 0;
        while i < timeout_iters {
            if (inb(I8042_STS) & STS_IBF) == 0 {
                return true;
            }
            i += 1;
        }
        false
    }
}
unsafe fn wait_obf_set(timeout_iters: u32) -> Option<u8> {
    unsafe {
        let mut i = 0;
        while i < timeout_iters {
            if (inb(I8042_STS) & STS_OBF) != 0 {
                return Some(inb(I8042_DATA));
            }
            i += 1;
        }
        None
    }
}
unsafe fn flush_ob(timeout_iters: u32) {
    unsafe {
        let mut i = 0;
        while i < timeout_iters {
            if (inb(I8042_STS) & STS_OBF) == 0 {
                break;
            }
            let _ = inb(I8042_DATA);
            i += 1;
        }
    }
}

unsafe fn cmd(c: u8) -> bool {
    unsafe {
        if !wait_ibf_clear(100000) {
            return false;
        }
        outb(I8042_CMD, c);
        true
    }
}
unsafe fn write_data(v: u8) -> bool {
    unsafe {
        if !wait_ibf_clear(100000) {
            return false;
        }
        outb(I8042_DATA, v);
        true
    }
}
unsafe fn read_data() -> Option<u8> {
    unsafe { wait_obf_set(100000) }
}

pub unsafe fn probe_i8042() -> (bool, bool) {
    unsafe {
        let _ = cmd(0xAD);
        let _ = cmd(0xA7);
        flush_ob(10000);

        if !cmd(0xAA) {
            return (false, false);
        }
        let ok = matches!(read_data(), Some(0x55));
        if !ok {
            return (false, false);
        }

        if !cmd(0x20) {
            return (false, false);
        }
        let mut cbyte = match read_data() {
            Some(v) => v,
            None => return (false, false),
        };
        cbyte &= !(1 << 6);
        cbyte &= !(1 << 0);
        cbyte &= !(1 << 1);
        if !cmd(0x60) || !write_data(cbyte) {
            return (false, false);
        }

        let have_kbd = cmd(0xAB) && matches!(read_data(), Some(0x00));
        let mut have_mouse = cmd(0xA9) && matches!(read_data(), Some(0x00));

        if !have_mouse {
            let _ = cmd(0xA8);
            let _ = cmd(0xD4);
            let _ = write_data(0xFF);
            let a = read_data();
            if matches!(a, Some(0xFA)) {
                let b = read_data();
                have_mouse =
                    matches!(b, Some(0xAA)) || matches!(b, Some(0x00)) || matches!(b, Some(0xAA));
            }
            let _ = cmd(0xA7);
            flush_ob(10000);
        }

        if have_kbd {
            let _ = cmd(0xAE);
        }
        if have_mouse {
            let _ = cmd(0xA8);
        }

        (have_kbd, have_mouse)
    }
}
