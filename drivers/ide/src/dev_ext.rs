use kernel_api::x86_64::instructions::port::Port;

pub struct DevExt {
    pub present: bool,
    pub data_port: Port<u16>,
    pub error_port: Port<u8>,
    pub sector_count_port: Port<u8>,
    pub lba_lo_port: Port<u8>,
    pub lba_mid_port: Port<u8>,
    pub lba_hi_port: Port<u8>,
    pub drive_head_port: Port<u8>,
    pub command_port: Port<u8>,
    pub control_port: Port<u8>,
    pub alternative_command_port: Port<u8>,
    pub enumerated: bool,
}
