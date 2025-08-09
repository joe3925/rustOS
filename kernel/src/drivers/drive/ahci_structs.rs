#[repr(C)]
pub struct CommandHeader {
    pub(crate) flags: u16,
    pub(crate) prdtl: u16,
    prdbc: u32,
    pub(crate) ctba: u32,
    pub(crate) ctbau: u32,
    reserved: [u32; 4],
}

#[repr(C)]
pub struct CommandTable {
    pub(crate) command_fis: [u8; 64], // Command FIS
    atapi_command: [u8; 16],          // ATAPI Command (if applicable)
    reserved: [u8; 48],
    pub(crate) prdt_entry: [PRDTEntry; 8], // Physical Region Descriptor Table (PRDT) entries
}

#[repr(C)]
pub struct PRDTEntry {
    pub(crate) data_base_address: u32,
    pub(crate) data_base_address_upper: u32,
    reserved: u32,
    pub(crate) byte_count: u32,
}

#[repr(C)]
pub struct AHCICommandList {
    command_headers: [CommandHeader; 32], // AHCI supports up to 32 command slots
}

pub struct AHCIPortRegisters {
    pub(crate) cmd: *mut u32,  // Command Register
    pub(crate) is: *mut u32,   // Interrupt Status Register
    pub(crate) ci: *mut u32,   // Command Issue Register
    pub(crate) clb: *mut u32,  // Command List Base
    pub(crate) clbu: *mut u32, // Command List Base Upper
    pub(crate) fb: *mut u32,   // FIS Base Address
    pub(crate) fbu: *mut u32,  // FIS Base Upper Address
}
#[repr(C, packed)]
pub struct FisRegH2D {
    pub fis_type: u8,            // FIS type – 0x27 for Register H2D FIS
    pub pm_port_cmd_control: u8, // Port multiplier, Command Control (bit 7 should be set for commands)
    pub command: u8,             // Command register (e.g., 0xEC for IDENTIFY DEVICE)
    pub feature_low: u8,         // Feature register, 7:0

    pub lba0: u8,   // LBA low register, 7:0
    pub lba1: u8,   // LBA mid register, 15:8
    pub lba2: u8,   // LBA high register, 23:16
    pub device: u8, // Device register

    pub lba3: u8,         // LBA register, 31:24
    pub lba4: u8,         // LBA register, 39:32
    pub lba5: u8,         // LBA register, 47:40
    pub feature_high: u8, // Feature register, 15:8

    pub count_low: u8,  // Sector count, 7:0
    pub count_high: u8, // Sector count, 15:8
    pub icc: u8,        // Isochronous command completion
    pub control: u8,    // Control register (e.g., 0 for normal commands)

    pub reserved: [u8; 4], // Reserved area
}
impl FisRegH2D {
    // Create a new H2D FIS for a command
    pub fn new(command: u8, lba: u64, sector_count: u16) -> Self {
        FisRegH2D {
            fis_type: 0x27,              // H2D FIS type
            pm_port_cmd_control: 1 << 7, // Set the Command bit (bit 7)
            command,                     // ATA command (e.g., 0xEC for IDENTIFY DEVICE)
            feature_low: 0,
            feature_high: 0,
            lba0: lba as u8,
            lba1: (lba >> 8) as u8,
            lba2: (lba >> 16) as u8,
            device: 0x40 | ((lba >> 24) as u8 & 0x0F), // Set bit 6 for LBA mode
            lba3: (lba >> 32) as u8,
            lba4: (lba >> 40) as u8,
            lba5: 0,
            count_low: sector_count as u8,
            count_high: (sector_count >> 8) as u8,
            icc: 0,
            control: 0,
            reserved: [0; 4],
        }
    }
}

#[repr(C, packed)]
pub struct FisRegD2H {
    pub fis_type: u8, // FIS type – 0x34 for Register D2H FIS
    pub pm_port: u8,  // Port multiplier
    pub status: u8,   // Status register (device status, e.g., BSY, DRDY)
    pub error: u8,    // Error register (contains ATA error information)

    pub lba0: u8,   // LBA low register, 7:0
    pub lba1: u8,   // LBA mid register, 15:8
    pub lba2: u8,   // LBA high register, 23:16
    pub device: u8, // Device register

    pub lba3: u8,     // LBA register, 31:24
    pub lba4: u8,     // LBA register, 39:32
    pub lba5: u8,     // LBA register, 47:40
    pub reserved: u8, // Reserved

    pub count_low: u8,      // Sector count, 7:0
    pub count_high: u8,     // Sector count, 15:8
    pub reserved2: [u8; 6], // Reserved
}
pub enum FisType {
    FisTypeRegH2d = 0x27,   // Register FIS - host to device
    FisTypeRegD2h = 0x34,   // Register FIS - device to host
    FisTypeDmaAct = 0x39,   // DMA activate FIS - device to host
    FisTypeDmaSetup = 0x41, // DMA setup FIS - bidirectional
    FisTypeData = 0x46,     // Data FIS - bidirectional
    FisTypeBist = 0x58,     // BIST activate FIS - bidirectional
    FisTypePioSetup = 0x5F, // PIO setup FIS - device to host
    FisTypeDevBits = 0xA1,  // Set device bits FIS - device to host
}
