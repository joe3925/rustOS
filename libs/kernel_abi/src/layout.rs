#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootVirtualLayout {
    pub kernel_image_base: u64,
    pub stub_image_base: u64,
    pub stub_dynamic_range_start: u64,
    pub stub_dynamic_range_end: u64,
}

pub mod x86_64 {
    use super::BootVirtualLayout;

    pub const BOOT_VIRTUAL_LAYOUT: BootVirtualLayout = BootVirtualLayout {
        kernel_image_base: 0xFFFF_8000_0000_0000,
        stub_image_base: 0xFFFF_8200_0000_0000,
        stub_dynamic_range_start: 0xFFFF_8300_0000_0000,
        stub_dynamic_range_end: 0xFFFF_9000_0000_0000,
    };

    const _: () =
        assert!(BOOT_VIRTUAL_LAYOUT.kernel_image_base < BOOT_VIRTUAL_LAYOUT.stub_image_base);
    const _: () =
        assert!(BOOT_VIRTUAL_LAYOUT.stub_image_base < BOOT_VIRTUAL_LAYOUT.stub_dynamic_range_start);
    const _: () = assert!(
        BOOT_VIRTUAL_LAYOUT.stub_dynamic_range_start < BOOT_VIRTUAL_LAYOUT.stub_dynamic_range_end
    );
}

pub mod aarch64 {
    use super::BootVirtualLayout;

    pub const BOOT_VIRTUAL_LAYOUT: BootVirtualLayout = BootVirtualLayout {
        kernel_image_base: 0xFFFF_8000_0000_0000,
        stub_image_base: 0xFFFF_8200_0000_0000,
        stub_dynamic_range_start: 0xFFFF_8300_0000_0000,
        stub_dynamic_range_end: 0xFFFF_9000_0000_0000,
    };
}

pub fn boot_virtual_layout(target_arch: &str) -> Option<BootVirtualLayout> {
    match target_arch {
        "x86_64" => Some(x86_64::BOOT_VIRTUAL_LAYOUT),
        "aarch64" => Some(aarch64::BOOT_VIRTUAL_LAYOUT),
        _ => None,
    }
}
