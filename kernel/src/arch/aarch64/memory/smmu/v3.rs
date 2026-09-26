use aarch64_vmsa::address::Level;
use aarch64_vmsa::attrs::{
    AllocationHints, CachePolicy, Cacheability, DataRights, DeviceMemoryType, DirtyBitManagement,
    DirtyControl, ExecuteRights, LiveVmsaConfig, MemoryAttributes, MemoryTransience,
    SemanticLeafAttrs, SemanticTableAttrs, SemanticVmsa64Stage2LeafControls, Shareability,
    SoftwareMetadata, Stage1PermissionSettings, Stage2MemoryAttributes, Stage2MemoryMode,
    Stage2PermissionSettings, Stage2Permissions,
};
use aarch64_vmsa::config::regime::smmu_v3::NonSecureIpaStage2;
use aarch64_vmsa::mapper::{Mapper, Offline};
use aarch64_vmsa::table::{RootTable, RootTableGeometry, TableFrameProvider, TableShape};
use aarch64_vmsa::translation::{WalkInputAddr, WalkOutputAddr};
use acpi::AcpiTable;
use acpi::sdt::{SdtHeader, Signature};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::sync::atomic::{Ordering, fence};
use device_tree::{DeviceTree, Node};
use kernel_types::arch::PhysAddr;
use kernel_types::dma::{
    DMA_IOMMU_VENDOR_ARM_SMMU, DeviceMmuPlatformDeviceIdentity, DmaPciDeviceIdentity,
};
use kernel_types::irq::{HardwareInterruptId, IrqBorrowedHandle, IrqFrame, IrqHandle};
use kernel_types::memory::{KernelMapping, PhysicalMappingCache};
use spin::Mutex;

use crate::machine::MachineInfo;
use crate::memory::device_mmu::{
    DeviceMmuAttachment, DeviceMmuBackend, DeviceMmuBackendInfo, DeviceMmuCapabilities,
    DeviceMmuDeviceIdentity, DeviceMmuDiscoveryError, DeviceMmuDiscoveryResult, DeviceMmuDomain,
    DeviceMmuDomainInfo, DeviceMmuError, DeviceMmuMapPermissions, DeviceMmuResult, DeviceMmuSystem,
};
use crate::memory::paging::mmio::map_physical_pages;

use super::tables::{Format, Granule, MIN_TABLE_ARENA_SIZE, TableArena, TableMemory};

const PAGE_SIZE: u64 = 4096;
const PAGE_SIZES: &[u64] = &[PAGE_SIZE];
const BLOCK_SIZES: &[u64] = &[2 * 1024 * 1024, 1024 * 1024 * 1024];
const REGISTER_SIZE: u64 = 0x20000;
const CMDQ_MAX_LOG2SIZE: u32 = 8;
const EVTQ_MAX_LOG2SIZE: u32 = 8;
const PRIQ_MAX_LOG2SIZE: u32 = 8;
const POLL_LIMIT: usize = 1_000_000;

const IORT_HEADER_SIZE: usize = 48;
const IORT_NODE_COUNT_OFFSET: usize = 36;
const IORT_NODE_OFFSET_OFFSET: usize = 40;
const IORT_NODE_HEADER_SIZE: usize = 16;
const IORT_NODE_TYPE_OFFSET: usize = 0;
const IORT_NODE_LENGTH_OFFSET: usize = 1;
const IORT_NODE_MAPPING_COUNT_OFFSET: usize = 8;
const IORT_NODE_MAPPING_OFFSET_OFFSET: usize = 12;
const IORT_NODE_SMMU_V3: u8 = 4;
const IORT_SMMU_V3_NODE_SIZE: usize = 68;
const IORT_SMMU_V3_BASE_OFFSET: usize = 16;
const IORT_SMMU_V3_FLAGS_OFFSET: usize = 24;
const IORT_SMMU_V3_FLAGS_COHACC_OVERRIDE: u32 = 1 << 0;
const IORT_SMMU_V3_EVENT_GSIV_OFFSET: usize = 40;
const IORT_SMMU_V3_PRI_GSIV_OFFSET: usize = 44;
const IORT_SMMU_V3_GERROR_GSIV_OFFSET: usize = 48;
const IORT_SMMU_V3_SYNC_GSIV_OFFSET: usize = 52;
const IORT_ID_MAPPING_SIZE: usize = 20;
const IORT_ID_MAPPING_INPUT_BASE_OFFSET: usize = 0;
const IORT_ID_MAPPING_ID_COUNT_OFFSET: usize = 4;
const IORT_ID_MAPPING_OUTPUT_BASE_OFFSET: usize = 8;
const IORT_ID_MAPPING_OUTPUT_REFERENCE_OFFSET: usize = 12;
const IORT_ID_MAPPING_FLAGS_OFFSET: usize = 16;
const IORT_ID_MAPPING_FLAGS_SINGLE: u32 = 1;
const MAX_ID_MAPPINGS: usize = 256;
const SMMU_INTERRUPT_COUNT: usize = 4;
const FDT_INTERRUPT_TYPE_SPI: u32 = 0;
const GIC_SPI_BASE: u32 = 32;
const PCI_CONFIG_SPACE_SIZE: u64 = 4096;
const PCI_EXTENDED_CAPABILITIES_OFFSET: u64 = 0x100;
const PCI_EXTENDED_CAPABILITIES_END: u64 = 0x1000;
const PCI_EXTENDED_CAPABILITY_ID_MASK: u32 = 0xffff;
const PCI_EXTENDED_CAPABILITY_NEXT_SHIFT: u32 = 20;
const PCI_EXTENDED_CAPABILITY_NEXT_MASK: u32 = 0xfff << PCI_EXTENDED_CAPABILITY_NEXT_SHIFT;
const PCI_EXTENDED_CAPABILITY_ATS: u32 = 0x000f;
const PCI_ATS_CAPABILITY_CONTROL_OFFSET: u64 = 4;
const PCI_ATS_CONTROL_ENABLE: u32 = 1 << 31;
const MAX_ATTACHED_STREAMS: usize = 1024;

const IDR0: usize = 0x0000;
const IDR0_S2P: u32 = 1 << 0;
const IDR0_COHACC: u32 = 1 << 4;
const IDR0_ATS: u32 = 1 << 10;
const IDR0_TTF_SHIFT: u32 = 2;
const IDR0_TTF_MASK: u32 = 0b11 << IDR0_TTF_SHIFT;
const IDR0_TTF_AARCH64: u32 = 0b10 << IDR0_TTF_SHIFT;
const IDR0_ST_LVL_SHIFT: u32 = 27;
const IDR0_ST_LVL_MASK: u32 = 0b11 << IDR0_ST_LVL_SHIFT;
const IDR0_ST_LVL_2LVL: u32 = 0b01 << IDR0_ST_LVL_SHIFT;
const IDR0_PRI: u32 = 1 << 16;
const IDR1: usize = 0x0004;
const IDR1_SIDSIZE_MASK: u32 = 0x3f;
const IDR1_CMDQS_SHIFT: u32 = 21;
const IDR1_CMDQS_MASK: u32 = 0x1f << IDR1_CMDQS_SHIFT;
const IDR1_EVTQS_SHIFT: u32 = 16;
const IDR1_EVTQS_MASK: u32 = 0x1f << IDR1_EVTQS_SHIFT;
const IDR1_PRIQS_SHIFT: u32 = 11;
const IDR1_PRIQS_MASK: u32 = 0x1f << IDR1_PRIQS_SHIFT;
const IDR5: usize = 0x0014;
const IDR5_OAS_MASK: u32 = 0b111;
const IDR5_GRAN4K: u32 = 1 << 4;

const CR0: usize = 0x0020;
const CR0_SMMUEN: u32 = 1 << 0;
const CR0_PRIQEN: u32 = 1 << 1;
const CR0_EVTQEN: u32 = 1 << 2;
const CR0_CMDQEN: u32 = 1 << 3;
const CR0ACK: usize = 0x0024;
const CR0_ENABLE_MASK: u32 = 0x1f;
const CR1: usize = 0x0028;
const CR1_QUEUE_IC_WB: u32 = 1;
const CR1_QUEUE_OC_WB: u32 = 1 << 2;
const CR1_QUEUE_SH_ISH: u32 = 0b11 << 4;
const CR1_TABLE_IC_WB: u32 = 1 << 6;
const CR1_TABLE_OC_WB: u32 = 1 << 8;
const CR1_TABLE_SH_ISH: u32 = 0b11 << 10;
const IRQ_CTRL: usize = 0x0050;
const IRQ_CTRLACK: usize = 0x0054;
const IRQ_CTRL_GERROR_IRQEN: u32 = 1 << 0;
const IRQ_CTRL_PRIQ_IRQEN: u32 = 1 << 1;
const IRQ_CTRL_EVTQ_IRQEN: u32 = 1 << 2;

const STRTAB_BASE: usize = 0x0080;
const STRTAB_BASE_RA: u64 = 1 << 62;
const STRTAB_BASE_CFG: usize = 0x0088;
const STRTAB_BASE_CFG_FMT_LINEAR: u32 = 0;
const STRTAB_BASE_CFG_FMT_2LVL: u32 = 1 << 16;
const STRTAB_BASE_CFG_SPLIT_SHIFT: u32 = 6;
const STRTAB_BASE_CFG_LOG2SIZE_MASK: u32 = 0x3f;
const STRTAB_SPLIT: u8 = 8;
const STRTAB_L1_DESC_BYTES: u64 = 8;
const STRTAB_L1_DESC_SPAN: u64 = STRTAB_SPLIT as u64;
const STRTAB_L1_DESC_L2PTR_MASK: u64 = 0x000f_ffff_ffff_ffc0;
const STE_DWORDS: u64 = 8;
const STE_BYTES: u64 = STE_DWORDS * 8;
const STE_0: u64 = 0;
const STE_0_V: u64 = 1 << 0;
const STE_0_CFG_SHIFT: u32 = 1;
const STE_0_CFG_S2_TRANS: u64 = 0b110 << STE_0_CFG_SHIFT;
const STE_1: u64 = 8;
const STE_1_SHCFG_SHIFT: u32 = 44;
const STE_1_SHCFG_INCOMING: u64 = 0b01 << STE_1_SHCFG_SHIFT;
const STE_1_EATS_SHIFT: u32 = 28;
const STE_1_EATS_TRANSLATE: u64 = 0b01 << STE_1_EATS_SHIFT;
const STE_2: u64 = 16;
const STE_2_VMID_MASK: u64 = 0xffff;
const STE_2_VTCR_SHIFT: u32 = 32;
const STE_2_S2AA64: u64 = 1 << 51;
const STE_2_S2PTW: u64 = 1 << 54;
const STE_3: u64 = 24;
const STE_3_S2TTB_MASK: u64 = 0x000f_ffff_ffff_fff0;

const CMDQ_BASE: usize = 0x0090;
const CMDQ_BASE_RWA: u64 = 1 << 62;
const CMDQ_PROD: usize = 0x0098;
const CMDQ_CONS: usize = 0x009c;
const CMDQ_DWORDS: u64 = 2;
const CMDQ_BYTES: u64 = CMDQ_DWORDS * 8;
const CMDQ_0_OP_CFGI_STE: u64 = 0x03;
const CMDQ_0_OP_CFGI_ALL: u64 = 0x04;
const CMDQ_0_OP_PRI_RESP: u64 = 0x21;
const CMDQ_0_OP_TLBI_S12_VMALL: u64 = 0x28;
const CMDQ_0_OP_TLBI_S2_IPA: u64 = 0x2a;
const CMDQ_0_OP_ATC_INV: u64 = 0x40;
const CMDQ_0_OP_CMD_SYNC: u64 = 0x46;
const CMDQ_0_SID_SHIFT: u32 = 32;
const CMDQ_0_VMID_SHIFT: u32 = 32;
const CMDQ_1_CFGI_LEAF: u64 = 1;
const CMDQ_1_TLBI_LEAF: u64 = 1;
const CMDQ_1_TLBI_IPA_MASK: u64 = 0x000f_ffff_ffff_f000;
const CMDQ_1_PRI_RESP_GROUP_ID_MASK: u64 = 0x1ff;
const CMDQ_1_PRI_RESP_SHIFT: u32 = 12;
const CMDQ_1_PRI_RESP_DENY: u64 = 0 << CMDQ_1_PRI_RESP_SHIFT;
const CMDQ_1_ATC_INV_SIZE_SHIFT: u32 = 0;
const CMDQ_1_ATC_INV_SIZE_ALL: u64 = 52 << CMDQ_1_ATC_INV_SIZE_SHIFT;

const EVTQ_BASE: usize = 0x00a0;
const EVTQ_BASE_RWA: u64 = 1 << 62;
const EVTQ_PROD: usize = 0x00a8;
const EVTQ_CONS: usize = 0x00ac;
const EVTQ_DWORDS: u64 = 4;
const EVTQ_BYTES: u64 = EVTQ_DWORDS * 8;
const EVTQ_0_ID_MASK: u64 = 0xff;
const EVTQ_0_SID_SHIFT: u32 = 32;
const EVTQ_0_SID_MASK: u64 = 0xffff_ffff << EVTQ_0_SID_SHIFT;

const PRIQ_BASE: usize = 0x00c0;
const PRIQ_BASE_RWA: u64 = 1 << 62;
const PRIQ_PROD: usize = 0x00c8;
const PRIQ_CONS: usize = 0x00cc;
const PRIQ_DWORDS: u64 = 2;
const PRIQ_BYTES: u64 = PRIQ_DWORDS * 8;
const PRIQ_0_SID_MASK: u64 = 0xffff_ffff;
const PRIQ_1_GROUP_ID_MASK: u64 = 0x1ff;
const PRIQ_1_LAST: u64 = 1 << 9;
const QUEUE_PRODUCER_OVERFLOW: u32 = 1 << 31;

const GERROR: usize = 0x0060;
const GERRORN: usize = 0x0064;

const VTCR_SL0_SHIFT: u32 = 6;
const VTCR_SL0_LEVEL_0: u64 = 0b10 << VTCR_SL0_SHIFT;
const VTCR_IRGN0_WBWA: u64 = 0b01 << 8;
const VTCR_ORGN0_WBWA: u64 = 0b01 << 10;
const VTCR_SH0_ISH: u64 = 0b11 << 12;
const VTCR_PS_SHIFT: u32 = 16;

type DomainMapper = Mapper<Format, NonSecureIpaStage2, Granule, TableMemory, TableMemory, Offline>;

struct DomainState {
    vmid: u16,
    root: u64,
    input_bits: u8,
    mapper: Mutex<DomainMapper>,
}

struct State {
    next_domain: u64,
    next_vmid: u16,
    domains: BTreeMap<u64, Arc<DomainState>>,
    attached: Box<[Option<AttachedStream>]>,
}

#[derive(Clone, Copy)]
struct AttachedStream {
    sid: u32,
    domain_id: u64,
    ats_control: u64,
}

#[derive(Clone, Copy)]
struct IdMapping {
    input_base: u32,
    input_mask: u32,
    id_count: u32,
    output_base: u32,
    single: bool,
}

struct FirmwareDescription {
    base: u64,
    coherent: bool,
    firmware_node: u32,
    interrupts: [u32; SMMU_INTERRUPT_COUNT],
    mappings: Box<[Option<IdMapping>]>,
}

#[derive(Clone, Copy)]
enum StreamTableFormat {
    Linear,
    TwoLevel,
}

pub(super) struct SmmuV3 {
    register_mapping: KernelMapping,
    registers: usize,
    sid_bits: u8,
    output_bits: u8,
    coherent: bool,
    ats: bool,
    mappings: Box<[Option<IdMapping>]>,
    stream_table: TableMemory,
    stream_table_phys: u64,
    stream_table_format: StreamTableFormat,
    stream_table_lock: Mutex<()>,
    command_queue: TableMemory,
    command_queue_phys: u64,
    command_queue_log2size: u32,
    command_queue_entries: u32,
    event_queue_phys: u64,
    event_queue_log2size: u32,
    event_consumer: Mutex<u32>,
    pri_queue_phys: Option<u64>,
    pri_queue_log2size: u32,
    pri_consumer: Mutex<u32>,
    interrupt_handles: Mutex<[Option<IrqHandle>; SMMU_INTERRUPT_COUNT]>,
    command_producer: Mutex<u32>,
    ats_mappings: Mutex<BTreeMap<u64, KernelMapping>>,
    state: Mutex<State>,
}

unsafe impl Send for SmmuV3 {}
unsafe impl Sync for SmmuV3 {}

pub(crate) fn discover(machine: &MachineInfo) -> DeviceMmuDiscoveryResult<Option<DeviceMmuSystem>> {
    if let Some(tables) = machine.firmware().acpi_tables() {
        if let Some(iort) = tables.find_table::<IortTable>() {
            let bytes = unsafe {
                core::slice::from_raw_parts(
                    iort.virtual_start.as_ptr().cast::<u8>(),
                    iort.region_length,
                )
            };
            if bytes.len() < IORT_HEADER_SIZE {
                return Err(DeviceMmuDiscoveryError::MalformedFirmware);
            }
            let count = u32::from_le_bytes(
                bytes[IORT_NODE_COUNT_OFFSET..IORT_NODE_COUNT_OFFSET + 4]
                    .try_into()
                    .unwrap(),
            ) as usize;
            let mut offset = u32::from_le_bytes(
                bytes[IORT_NODE_OFFSET_OFFSET..IORT_NODE_OFFSET_OFFSET + 4]
                    .try_into()
                    .unwrap(),
            ) as usize;
            for _ in 0..count {
                if offset + IORT_NODE_HEADER_SIZE > bytes.len() {
                    return Err(DeviceMmuDiscoveryError::MalformedFirmware);
                }
                let length = u16::from_le_bytes(
                    bytes[offset + IORT_NODE_LENGTH_OFFSET..offset + IORT_NODE_LENGTH_OFFSET + 2]
                        .try_into()
                        .unwrap(),
                ) as usize;
                if length < IORT_NODE_HEADER_SIZE || offset + length > bytes.len() {
                    return Err(DeviceMmuDiscoveryError::MalformedFirmware);
                }
                if bytes[offset + IORT_NODE_TYPE_OFFSET] == IORT_NODE_SMMU_V3 {
                    if length < IORT_SMMU_V3_NODE_SIZE {
                        return Err(DeviceMmuDiscoveryError::MalformedFirmware);
                    }
                    let base = u64::from_le_bytes(
                        bytes[offset + IORT_SMMU_V3_BASE_OFFSET
                            ..offset + IORT_SMMU_V3_BASE_OFFSET + 8]
                            .try_into()
                            .unwrap(),
                    );
                    let mut mappings = alloc::vec![None; MAX_ID_MAPPINGS].into_boxed_slice();
                    let mut mapping_index = 0;
                    let mut source_offset = u32::from_le_bytes(
                        bytes[IORT_NODE_OFFSET_OFFSET..IORT_NODE_OFFSET_OFFSET + 4]
                            .try_into()
                            .unwrap(),
                    ) as usize;
                    for _ in 0..count {
                        if source_offset + IORT_NODE_HEADER_SIZE > bytes.len() {
                            return Err(DeviceMmuDiscoveryError::MalformedFirmware);
                        }
                        let source_length = u16::from_le_bytes(
                            bytes[source_offset + IORT_NODE_LENGTH_OFFSET
                                ..source_offset + IORT_NODE_LENGTH_OFFSET + 2]
                                .try_into()
                                .unwrap(),
                        ) as usize;
                        if source_length < IORT_NODE_HEADER_SIZE
                            || source_offset + source_length > bytes.len()
                        {
                            return Err(DeviceMmuDiscoveryError::MalformedFirmware);
                        }
                        let mapping_count = u32::from_le_bytes(
                            bytes[source_offset + IORT_NODE_MAPPING_COUNT_OFFSET
                                ..source_offset + IORT_NODE_MAPPING_COUNT_OFFSET + 4]
                                .try_into()
                                .unwrap(),
                        ) as usize;
                        let mapping_offset = u32::from_le_bytes(
                            bytes[source_offset + IORT_NODE_MAPPING_OFFSET_OFFSET
                                ..source_offset + IORT_NODE_MAPPING_OFFSET_OFFSET + 4]
                                .try_into()
                                .unwrap(),
                        ) as usize;
                        for index in 0..mapping_count {
                            let entry = source_offset
                                .checked_add(mapping_offset)
                                .and_then(|value| value.checked_add(index * IORT_ID_MAPPING_SIZE))
                                .ok_or(DeviceMmuDiscoveryError::MalformedFirmware)?;
                            if entry + IORT_ID_MAPPING_SIZE > source_offset + source_length {
                                return Err(DeviceMmuDiscoveryError::MalformedFirmware);
                            }
                            let output_reference = u32::from_le_bytes(
                                bytes[entry + IORT_ID_MAPPING_OUTPUT_REFERENCE_OFFSET
                                    ..entry + IORT_ID_MAPPING_OUTPUT_REFERENCE_OFFSET + 4]
                                    .try_into()
                                    .unwrap(),
                            ) as usize;
                            if output_reference == offset && mapping_index < MAX_ID_MAPPINGS {
                                let flags = u32::from_le_bytes(
                                    bytes[entry + IORT_ID_MAPPING_FLAGS_OFFSET
                                        ..entry + IORT_ID_MAPPING_FLAGS_OFFSET + 4]
                                        .try_into()
                                        .unwrap(),
                                );
                                mappings[mapping_index] = Some(IdMapping {
                                    input_base: u32::from_le_bytes(
                                        bytes[entry + IORT_ID_MAPPING_INPUT_BASE_OFFSET
                                            ..entry + IORT_ID_MAPPING_INPUT_BASE_OFFSET + 4]
                                            .try_into()
                                            .unwrap(),
                                    ),
                                    input_mask: u32::MAX,
                                    id_count: u32::from_le_bytes(
                                        bytes[entry + IORT_ID_MAPPING_ID_COUNT_OFFSET
                                            ..entry + IORT_ID_MAPPING_ID_COUNT_OFFSET + 4]
                                            .try_into()
                                            .unwrap(),
                                    ),
                                    output_base: u32::from_le_bytes(
                                        bytes[entry + IORT_ID_MAPPING_OUTPUT_BASE_OFFSET
                                            ..entry + IORT_ID_MAPPING_OUTPUT_BASE_OFFSET + 4]
                                            .try_into()
                                            .unwrap(),
                                    ),
                                    single: flags & IORT_ID_MAPPING_FLAGS_SINGLE != 0,
                                });
                                mapping_index += 1;
                            }
                        }
                        source_offset += source_length;
                    }
                    let read_gsiv = |field: usize| {
                        u32::from_le_bytes(
                            bytes[offset + field..offset + field + 4]
                                .try_into()
                                .unwrap(),
                        )
                    };
                    let description = FirmwareDescription {
                        base,
                        coherent: u32::from_le_bytes(
                            bytes[offset + IORT_SMMU_V3_FLAGS_OFFSET
                                ..offset + IORT_SMMU_V3_FLAGS_OFFSET + 4]
                                .try_into()
                                .unwrap(),
                        ) & IORT_SMMU_V3_FLAGS_COHACC_OVERRIDE
                            != 0,
                        firmware_node: 0,
                        interrupts: [
                            read_gsiv(IORT_SMMU_V3_EVENT_GSIV_OFFSET),
                            read_gsiv(IORT_SMMU_V3_PRI_GSIV_OFFSET),
                            read_gsiv(IORT_SMMU_V3_GERROR_GSIV_OFFSET),
                            read_gsiv(IORT_SMMU_V3_SYNC_GSIV_OFFSET),
                        ],
                        mappings,
                    };
                    let interrupts = description.interrupts;
                    let backend = Arc::new(SmmuV3::new(description)?);
                    backend.bind_interrupts(&interrupts);
                    return Ok(Some(DeviceMmuSystem::new(backend)));
                }
                offset += length;
            }
        }
    }
    let Some(header_ptr) = machine.firmware().fdt_header() else {
        return Ok(None);
    };
    let header = unsafe { &*header_ptr };
    let length = header.total_size() as usize;
    if header.magic() != kernel_types::fdt::FdtHeader::MAGIC
        || length < core::mem::size_of::<kernel_types::fdt::FdtHeader>()
    {
        return Err(DeviceMmuDiscoveryError::MalformedFirmware);
    }
    let blob = unsafe { core::slice::from_raw_parts(header_ptr.cast::<u8>(), length) };
    let tree = DeviceTree::load(blob).map_err(|_| DeviceMmuDiscoveryError::MalformedFirmware)?;
    let Some(mut description) = find_smmuv3(&tree.root, 2, 2) else {
        return Ok(None);
    };
    collect_fdt_mappings(
        &tree.root,
        description.firmware_node,
        &mut description.mappings,
    );
    let interrupts = description.interrupts;
    let backend = Arc::new(SmmuV3::new(description)?);
    backend.bind_interrupts(&interrupts);
    Ok(Some(DeviceMmuSystem::new(backend)))
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct IortTable {
    header: SdtHeader,
    node_count: u32,
    node_offset: u32,
    reserved: u32,
}

unsafe impl AcpiTable for IortTable {
    const SIGNATURE: Signature = Signature::IORT;

    fn header(&self) -> &SdtHeader {
        &self.header
    }
}

fn find_smmuv3(
    node: &Node,
    parent_address_cells: u32,
    parent_size_cells: u32,
) -> Option<FirmwareDescription> {
    let address_cells = node
        .prop_raw("#address-cells")
        .and_then(|value| value.get(0..4))
        .and_then(|value| value.try_into().ok().map(u32::from_be_bytes))
        .unwrap_or(parent_address_cells);
    let size_cells = node
        .prop_raw("#size-cells")
        .and_then(|value| value.get(0..4))
        .and_then(|value| value.try_into().ok().map(u32::from_be_bytes))
        .unwrap_or(parent_size_cells);
    if node.prop_raw("compatible").is_some_and(|value| {
        value
            .split(|byte| *byte == 0)
            .any(|part| part == b"arm,smmu-v3")
    }) {
        let reg = node.prop_raw("reg")?;
        if parent_address_cells == 0 || parent_address_cells > 2 {
            return None;
        }
        let mut result = 0u64;
        for index in 0..parent_address_cells as usize {
            result = result << 32
                | u32::from_be_bytes(reg.get(index * 4..index * 4 + 4)?.try_into().ok()?) as u64;
        }
        return Some(FirmwareDescription {
            base: result,
            coherent: node.prop_raw("dma-coherent").is_some(),
            firmware_node: node
                .prop_raw("phandle")
                .or_else(|| node.prop_raw("linux,phandle"))
                .and_then(|value| value.get(0..4))
                .and_then(|value| value.try_into().ok().map(u32::from_be_bytes))
                .unwrap_or(0),
            interrupts: fdt_smmu_interrupts(node),
            mappings: alloc::vec![None; MAX_ID_MAPPINGS].into_boxed_slice(),
        });
    }
    node.children
        .iter()
        .find_map(|child| find_smmuv3(child, address_cells, size_cells))
}

fn fdt_smmu_interrupts(node: &Node) -> [u32; SMMU_INTERRUPT_COUNT] {
    let mut result = [0; SMMU_INTERRUPT_COUNT];
    let Some(interrupts) = node.prop_raw("interrupts") else {
        return result;
    };
    for (index, entry) in interrupts
        .chunks_exact(12)
        .take(SMMU_INTERRUPT_COUNT)
        .enumerate()
    {
        let interrupt_type = u32::from_be_bytes(entry[0..4].try_into().unwrap());
        let interrupt_number = u32::from_be_bytes(entry[4..8].try_into().unwrap());
        if interrupt_type == FDT_INTERRUPT_TYPE_SPI {
            result[index] = interrupt_number + GIC_SPI_BASE;
        }
    }
    result
}

fn collect_fdt_mappings(node: &Node, smmu_phandle: u32, mappings: &mut [Option<IdMapping>]) {
    if let Some(map) = node.prop_raw("iommu-map") {
        let mask = node
            .prop_raw("iommu-map-mask")
            .and_then(|value| value.get(0..4))
            .and_then(|value| value.try_into().ok().map(u32::from_be_bytes))
            .unwrap_or(u32::MAX);
        for entry in map.chunks_exact(16) {
            let phandle = u32::from_be_bytes(entry[4..8].try_into().unwrap());
            if phandle != smmu_phandle {
                continue;
            }
            let Some(slot) = mappings.iter_mut().find(|slot| slot.is_none()) else {
                break;
            };
            let length = u32::from_be_bytes(entry[12..16].try_into().unwrap());
            if length == 0 {
                continue;
            }
            *slot = Some(IdMapping {
                input_base: u32::from_be_bytes(entry[0..4].try_into().unwrap()),
                input_mask: mask,
                id_count: length - 1,
                output_base: u32::from_be_bytes(entry[8..12].try_into().unwrap()),
                single: false,
            });
        }
    }
    for child in &node.children {
        collect_fdt_mappings(child, smmu_phandle, mappings);
    }
}

impl SmmuV3 {
    fn new(description: FirmwareDescription) -> DeviceMmuResult<Self> {
        let register_mapping = map_physical_pages(
            PhysAddr::new(description.base),
            REGISTER_SIZE,
            PhysicalMappingCache::Uncached,
        )
        .map_err(|_| DeviceMmuError::HardwareError)?;
        let registers = register_mapping.address().as_u64() as usize;
        let idr0 = unsafe { core::ptr::read_volatile((registers + IDR0) as *const u32) };
        let idr1 = unsafe { core::ptr::read_volatile((registers + IDR1) as *const u32) };
        let idr5 = unsafe { core::ptr::read_volatile((registers + IDR5) as *const u32) };
        if idr0 & IDR0_S2P == 0
            || idr0 & IDR0_TTF_MASK != IDR0_TTF_AARCH64
            || idr5 & IDR5_GRAN4K == 0
        {
            return Err(DeviceMmuError::Unsupported);
        }
        let sid_bits = (idr1 & IDR1_SIDSIZE_MASK) as u8;
        if sid_bits == 0 {
            return Err(DeviceMmuError::Unsupported);
        }
        let output_bits = match idr5 & IDR5_OAS_MASK {
            0 => 32,
            1 => 36,
            2 => 40,
            3 => 42,
            4 => 44,
            5 => 48,
            6 => 52,
            _ => return Err(DeviceMmuError::Unsupported),
        };
        let command_queue_log2size =
            ((idr1 & IDR1_CMDQS_MASK) >> IDR1_CMDQS_SHIFT).min(CMDQ_MAX_LOG2SIZE);
        let command_queue_entries = 1u32 << command_queue_log2size;
        let event_queue_log2size =
            ((idr1 & IDR1_EVTQS_MASK) >> IDR1_EVTQS_SHIFT).min(EVTQ_MAX_LOG2SIZE);
        let event_queue_entries = 1u64 << event_queue_log2size;
        let pri_queue_log2size =
            ((idr1 & IDR1_PRIQS_MASK) >> IDR1_PRIQS_SHIFT).min(PRIQ_MAX_LOG2SIZE);
        let stream_table_format =
            if idr0 & IDR0_ST_LVL_MASK == IDR0_ST_LVL_2LVL && sid_bits > STRTAB_SPLIT {
                StreamTableFormat::TwoLevel
            } else {
                StreamTableFormat::Linear
            };
        if matches!(stream_table_format, StreamTableFormat::Linear) && sid_bits > 20 {
            return Err(DeviceMmuError::Unsupported);
        }
        let stream_bytes = match stream_table_format {
            StreamTableFormat::Linear => (1u64 << sid_bits) * STE_BYTES,
            StreamTableFormat::TwoLevel => {
                (1u64 << (sid_bits - STRTAB_SPLIT)) * STRTAB_L1_DESC_BYTES
            }
        };
        let arena_size = MIN_TABLE_ARENA_SIZE
            .checked_add(stream_bytes)
            .ok_or(DeviceMmuError::NoBackingFrame)?;
        let arena = Arc::new(TableArena::new(arena_size)?);
        let tables = TableMemory(arena);
        let stream_table_phys = tables.0.allocate(stream_bytes, 64)?;
        let command_queue_phys = tables
            .0
            .allocate(command_queue_entries as u64 * CMDQ_BYTES, PAGE_SIZE)?;
        let event_queue_phys = tables
            .0
            .allocate(event_queue_entries * EVTQ_BYTES, PAGE_SIZE)?;
        let pri_queue_phys = if idr0 & IDR0_PRI != 0 {
            Some(
                tables
                    .0
                    .allocate((1u64 << pri_queue_log2size) * PRIQ_BYTES, PAGE_SIZE)?,
            )
        } else {
            None
        };
        let smmu = Self {
            register_mapping,
            registers,
            sid_bits,
            output_bits,
            coherent: description.coherent || idr0 & IDR0_COHACC != 0,
            ats: idr0 & IDR0_ATS != 0,
            mappings: description.mappings,
            stream_table: tables.clone(),
            stream_table_phys,
            stream_table_format,
            stream_table_lock: Mutex::new(()),
            command_queue: tables,
            command_queue_phys,
            command_queue_log2size,
            command_queue_entries,
            event_queue_phys,
            event_queue_log2size,
            event_consumer: Mutex::new(0),
            pri_queue_phys,
            pri_queue_log2size,
            pri_consumer: Mutex::new(0),
            interrupt_handles: Mutex::new([None; SMMU_INTERRUPT_COUNT]),
            command_producer: Mutex::new(0),
            ats_mappings: Mutex::new(BTreeMap::new()),
            state: Mutex::new(State {
                next_domain: 1,
                next_vmid: 1,
                domains: BTreeMap::new(),
                attached: alloc::vec![None; MAX_ATTACHED_STREAMS].into_boxed_slice(),
            }),
        };
        smmu.initialize_hardware()?;
        Ok(smmu)
    }

    fn initialize_hardware(&self) -> DeviceMmuResult<()> {
        self.write32(IRQ_CTRL, 0);
        self.wait32(IRQ_CTRLACK, u32::MAX, 0)?;
        self.write32(CR0, 0);
        self.wait32(CR0ACK, CR0_ENABLE_MASK, 0)?;
        self.write64(STRTAB_BASE, self.stream_table_phys | STRTAB_BASE_RA);
        let stream_config = match self.stream_table_format {
            StreamTableFormat::Linear => STRTAB_BASE_CFG_FMT_LINEAR,
            StreamTableFormat::TwoLevel => {
                STRTAB_BASE_CFG_FMT_2LVL | (STRTAB_SPLIT as u32) << STRTAB_BASE_CFG_SPLIT_SHIFT
            }
        };
        self.write32(
            STRTAB_BASE_CFG,
            stream_config | self.sid_bits as u32 & STRTAB_BASE_CFG_LOG2SIZE_MASK,
        );
        self.write64(
            CMDQ_BASE,
            self.command_queue_phys | CMDQ_BASE_RWA | self.command_queue_log2size as u64,
        );
        self.write32(CMDQ_PROD, 0);
        self.write32(CMDQ_CONS, 0);
        self.write64(
            EVTQ_BASE,
            self.event_queue_phys | EVTQ_BASE_RWA | self.event_queue_log2size as u64,
        );
        self.write32(EVTQ_PROD, 0);
        self.write32(EVTQ_CONS, 0);
        if let Some(pri_queue_phys) = self.pri_queue_phys {
            self.write64(
                PRIQ_BASE,
                pri_queue_phys | PRIQ_BASE_RWA | self.pri_queue_log2size as u64,
            );
            self.write32(PRIQ_PROD, 0);
            self.write32(PRIQ_CONS, 0);
        }
        self.write32(
            CR1,
            CR1_TABLE_IC_WB
                | CR1_TABLE_OC_WB
                | CR1_TABLE_SH_ISH
                | CR1_QUEUE_IC_WB
                | CR1_QUEUE_OC_WB
                | CR1_QUEUE_SH_ISH,
        );
        let enable = CR0_CMDQEN
            | CR0_EVTQEN
            | if self.pri_queue_phys.is_some() {
                CR0_PRIQEN
            } else {
                0
            }
            | CR0_SMMUEN;
        self.write32(CR0, enable);
        self.wait32(CR0ACK, enable, enable)
    }

    fn bind_interrupts(&self, interrupts: &[u32; SMMU_INTERRUPT_COUNT]) {
        let mut handles = self.interrupt_handles.lock();
        for (index, interrupt) in interrupts.iter().copied().enumerate() {
            if interrupt == 0 || interrupts[..index].contains(&interrupt) {
                continue;
            }
            let handle = crate::idt::interrupt_impl::bind_wired_interrupt(
                HardwareInterruptId(interrupt),
                smmu_v3_interrupt,
                self as *const Self as usize,
            );
            if !handle.is_null() {
                if let Some(slot) = handles.iter_mut().find(|slot| slot.is_none()) {
                    *slot = Some(handle);
                }
            }
        }
        let mut enable = 0;
        if interrupts[0] != 0 {
            enable |= IRQ_CTRL_EVTQ_IRQEN;
        }
        if interrupts[1] != 0 && self.pri_queue_phys.is_some() {
            enable |= IRQ_CTRL_PRIQ_IRQEN;
        }
        if interrupts[2] != 0 {
            enable |= IRQ_CTRL_GERROR_IRQEN;
        }
        self.write32(IRQ_CTRL, enable);
        let _ = self.wait32(IRQ_CTRLACK, u32::MAX, enable);
    }

    fn read32(&self, offset: usize) -> u32 {
        unsafe { core::ptr::read_volatile((self.registers + offset) as *const u32) }
    }

    fn write32(&self, offset: usize, value: u32) {
        unsafe { core::ptr::write_volatile((self.registers + offset) as *mut u32, value) }
    }

    fn write64(&self, offset: usize, value: u64) {
        unsafe { core::ptr::write_volatile((self.registers + offset) as *mut u64, value) }
    }
    fn publish(&self, address: u64, bytes: u64) {
        fence(Ordering::Release);
        if !self.coherent {
            crate::arch::aarch64::cpu::clean_to_poc(address, bytes as usize);
        }
    }

    fn wait32(&self, offset: usize, mask: u32, value: u32) -> DeviceMmuResult<()> {
        for _ in 0..POLL_LIMIT {
            if self.read32(offset) & mask == value {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(DeviceMmuError::HardwareError)
    }

    fn issue_command(&self, word0: u64, word1: u64) -> DeviceMmuResult<()> {
        let mut producer = self.command_producer.lock();
        let producer_wrap_mask = self.command_queue_entries * 2 - 1;
        let mut consumer = self.read32(CMDQ_CONS) & producer_wrap_mask;
        let next = producer.wrapping_add(1) & producer_wrap_mask;
        let mut polls = 0;
        while next == (consumer ^ self.command_queue_entries) {
            if polls == POLL_LIMIT {
                return Err(DeviceMmuError::HardwareError);
            }
            polls += 1;
            core::hint::spin_loop();
            consumer = self.read32(CMDQ_CONS) & producer_wrap_mask;
        }
        let index = *producer & (self.command_queue_entries - 1);
        let address = self
            .command_queue
            .0
            .virtual_address(self.command_queue_phys)
            + index as u64 * CMDQ_BYTES;
        unsafe {
            core::ptr::write_volatile(address as *mut u64, word0);
            core::ptr::write_volatile((address + 8) as *mut u64, word1);
        }
        self.publish(address, CMDQ_BYTES);
        *producer = next;
        self.write32(CMDQ_PROD, *producer);
        polls = 0;
        while self.read32(CMDQ_CONS) & producer_wrap_mask != *producer {
            if polls == POLL_LIMIT {
                return Err(DeviceMmuError::HardwareError);
            }
            polls += 1;
            core::hint::spin_loop();
        }
        Ok(())
    }

    fn issue_command_and_sync(&self, word0: u64, word1: u64) -> DeviceMmuResult<()> {
        self.issue_command(word0, word1)?;
        self.issue_command(CMDQ_0_OP_CMD_SYNC, 0)
    }

    fn invalidate_stream(&self, sid: u32) -> DeviceMmuResult<()> {
        self.issue_command_and_sync(
            CMDQ_0_OP_CFGI_STE | ((sid as u64) << CMDQ_0_SID_SHIFT),
            CMDQ_1_CFGI_LEAF,
        )
    }

    fn invalidate_stream_table(&self) -> DeviceMmuResult<()> {
        self.issue_command_and_sync(CMDQ_0_OP_CFGI_ALL, 0)
    }

    fn service_queues(&self) -> DeviceMmuResult<()> {
        let error = self.read32(GERROR);
        let acknowledged = self.read32(GERRORN);
        if error != acknowledged {
            self.write32(GERRORN, error);
            return Err(DeviceMmuError::HardwareError);
        }
        let event_entries = 1u32 << self.event_queue_log2size;
        let event_pointer_mask = event_entries * 2 - 1;
        let mut event_consumer = self.event_consumer.lock();
        let event_producer = self.read32(EVTQ_PROD);
        while *event_consumer & event_pointer_mask != event_producer & event_pointer_mask {
            let index = *event_consumer & (event_entries - 1);
            let address = self.stream_table.0.virtual_address(self.event_queue_phys)
                + index as u64 * EVTQ_BYTES;
            if !self.coherent {
                crate::arch::aarch64::cpu::clean_to_poc(address, EVTQ_BYTES as usize);
            }
            fence(Ordering::Acquire);
            let word0 = unsafe { core::ptr::read_volatile(address as *const u64) };
            let word1 = unsafe { core::ptr::read_volatile((address + 8) as *const u64) };
            let word2 = unsafe { core::ptr::read_volatile((address + 16) as *const u64) };
            let word3 = unsafe { core::ptr::read_volatile((address + 24) as *const u64) };
            let event_id = word0 & EVTQ_0_ID_MASK;
            let sid = (word0 & EVTQ_0_SID_MASK) >> EVTQ_0_SID_SHIFT;
            crate::println!(
                "SMMUv3 event {event_id:#x} stream {sid:#x} words [{word0:#018x}, {word1:#018x}, {word2:#018x}, {word3:#018x}]"
            );
            *event_consumer = event_consumer.wrapping_add(1) & event_pointer_mask;
        }
        self.write32(
            EVTQ_CONS,
            *event_consumer | event_producer & QUEUE_PRODUCER_OVERFLOW,
        );
        let Some(pri_queue_phys) = self.pri_queue_phys else {
            return Ok(());
        };
        let pri_entries = 1u32 << self.pri_queue_log2size;
        let pri_pointer_mask = pri_entries * 2 - 1;
        let mut pri_consumer = self.pri_consumer.lock();
        let pri_producer = self.read32(PRIQ_PROD);
        while *pri_consumer & pri_pointer_mask != pri_producer & pri_pointer_mask {
            let index = *pri_consumer & (pri_entries - 1);
            let address =
                self.stream_table.0.virtual_address(pri_queue_phys) + index as u64 * PRIQ_BYTES;
            if !self.coherent {
                crate::arch::aarch64::cpu::clean_to_poc(address, PRIQ_BYTES as usize);
            }
            fence(Ordering::Acquire);
            let word0 = unsafe { core::ptr::read_volatile(address as *const u64) };
            let word1 = unsafe { core::ptr::read_volatile((address + 8) as *const u64) };
            if word1 & PRIQ_1_LAST != 0 {
                self.issue_command(
                    CMDQ_0_OP_PRI_RESP | ((word0 & PRIQ_0_SID_MASK) << CMDQ_0_SID_SHIFT),
                    word1 & PRIQ_1_GROUP_ID_MASK | CMDQ_1_PRI_RESP_DENY,
                )?;
            }
            *pri_consumer = pri_consumer.wrapping_add(1) & pri_pointer_mask;
        }
        self.write32(
            PRIQ_CONS,
            *pri_consumer | pri_producer & QUEUE_PRODUCER_OVERFLOW,
        );
        Ok(())
    }

    fn stream_entry(&self, sid: u32, allocate: bool) -> DeviceMmuResult<Option<u64>> {
        let _lock = self.stream_table_lock.lock();
        match self.stream_table_format {
            StreamTableFormat::Linear => Ok(Some(
                self.stream_table.0.virtual_address(self.stream_table_phys)
                    + sid as u64 * STE_BYTES,
            )),
            StreamTableFormat::TwoLevel => {
                let l1_index = sid as u64 >> STRTAB_SPLIT;
                let l2_index = sid as u64 & ((1u64 << STRTAB_SPLIT) - 1);
                let l1 = self.stream_table.0.virtual_address(self.stream_table_phys)
                    + l1_index * STRTAB_L1_DESC_BYTES;
                let mut descriptor = unsafe { core::ptr::read_volatile(l1 as *const u64) };
                if descriptor & STRTAB_L1_DESC_L2PTR_MASK == 0 {
                    if !allocate {
                        return Ok(None);
                    }
                    let l2_bytes = (1u64 << STRTAB_SPLIT) * STE_BYTES;
                    let l2 = self.stream_table.0.allocate(l2_bytes, l2_bytes)?;
                    descriptor = l2 & STRTAB_L1_DESC_L2PTR_MASK | STRTAB_L1_DESC_SPAN;
                    unsafe { core::ptr::write_volatile(l1 as *mut u64, descriptor) };
                    self.publish(l1, STRTAB_L1_DESC_BYTES);
                    self.invalidate_stream_table()?;
                }
                let l2 = descriptor & STRTAB_L1_DESC_L2PTR_MASK;
                Ok(Some(
                    self.stream_table.0.virtual_address(l2) + l2_index * STE_BYTES,
                ))
            }
        }
    }

    fn reclaim_stream_block(&self, sid: u32) -> DeviceMmuResult<()> {
        if !matches!(self.stream_table_format, StreamTableFormat::TwoLevel) {
            return Ok(());
        }
        let _lock = self.stream_table_lock.lock();
        let l1_index = sid as u64 >> STRTAB_SPLIT;
        let l1 = self.stream_table.0.virtual_address(self.stream_table_phys)
            + l1_index * STRTAB_L1_DESC_BYTES;
        let descriptor = unsafe { core::ptr::read_volatile(l1 as *const u64) };
        let l2 = descriptor & STRTAB_L1_DESC_L2PTR_MASK;
        if l2 == 0 {
            return Ok(());
        }
        let l2_virtual = self.stream_table.0.virtual_address(l2);
        for index in 0..1u64 << STRTAB_SPLIT {
            let word0 = unsafe {
                core::ptr::read_volatile((l2_virtual + index * STE_BYTES + STE_0) as *const u64)
            };
            if word0 & STE_0_V != 0 {
                return Ok(());
            }
        }
        unsafe { core::ptr::write_volatile(l1 as *mut u64, 0) };
        self.publish(l1, STRTAB_L1_DESC_BYTES);
        self.invalidate_stream_table()?;
        let l2_bytes = (1u64 << STRTAB_SPLIT) * STE_BYTES;
        self.stream_table
            .0
            .reclaim_allocation(l2, l2_bytes, l2_bytes);
        Ok(())
    }

    fn raw_domain(&self, domain: &DeviceMmuDomain) -> DeviceMmuResult<Arc<DomainState>> {
        self.state
            .lock()
            .domains
            .get(&domain.domain_id())
            .cloned()
            .ok_or(DeviceMmuError::InvalidDomain)
    }

    fn stream_id(&self, identity: DeviceMmuDeviceIdentity) -> DeviceMmuResult<u32> {
        let input = match identity {
            DeviceMmuDeviceIdentity::Pci(DmaPciDeviceIdentity { requester_id, .. }) => {
                requester_id as u32
            }
            DeviceMmuDeviceIdentity::Platform(DeviceMmuPlatformDeviceIdentity {
                iommu_id_base,
                iommu_id_count: 1,
                ..
            }) => iommu_id_base,
            _ => return Err(DeviceMmuError::InvalidDevice),
        };
        for mapping in self.mappings.iter().flatten() {
            let input = input & mapping.input_mask;
            if mapping.single && input == mapping.input_base {
                return Ok(mapping.output_base);
            }
            if !mapping.single
                && input >= mapping.input_base
                && input - mapping.input_base <= mapping.id_count
            {
                return mapping
                    .output_base
                    .checked_add(input - mapping.input_base)
                    .ok_or(DeviceMmuError::InvalidDevice);
            }
        }
        Ok(input)
    }

    fn enable_ats(&self, identity: DeviceMmuDeviceIdentity) -> DeviceMmuResult<u64> {
        if !self.ats {
            return Ok(0);
        }
        let DeviceMmuDeviceIdentity::Pci(DmaPciDeviceIdentity {
            config_space_phys, ..
        }) = identity
        else {
            return Ok(0);
        };
        let config_mapping = map_physical_pages(
            PhysAddr::new(config_space_phys),
            PCI_CONFIG_SPACE_SIZE,
            PhysicalMappingCache::Uncached,
        )
        .map_err(|_| DeviceMmuError::HardwareError)?;
        let config = config_mapping.address().as_u64();
        let mut offset = PCI_EXTENDED_CAPABILITIES_OFFSET;
        while offset < PCI_EXTENDED_CAPABILITIES_END {
            let header = unsafe { core::ptr::read_volatile((config + offset) as *const u32) };
            if header == 0 || header == u32::MAX {
                break;
            }
            if header & PCI_EXTENDED_CAPABILITY_ID_MASK == PCI_EXTENDED_CAPABILITY_ATS {
                let control = config + offset + PCI_ATS_CAPABILITY_CONTROL_OFFSET;
                let value = unsafe { core::ptr::read_volatile(control as *const u32) };
                unsafe {
                    core::ptr::write_volatile(control as *mut u32, value | PCI_ATS_CONTROL_ENABLE)
                };
                self.ats_mappings.lock().insert(control, config_mapping);
                return Ok(control);
            }
            let next =
                (header & PCI_EXTENDED_CAPABILITY_NEXT_MASK) >> PCI_EXTENDED_CAPABILITY_NEXT_SHIFT;
            if next < PCI_EXTENDED_CAPABILITIES_OFFSET as u32 || next as u64 <= offset {
                break;
            }
            offset = next as u64;
        }
        Ok(0)
    }

    fn invalidate_domain_atc(&self, domain_id: u64) -> DeviceMmuResult<()> {
        let state = self.state.lock();
        for attached in state
            .attached
            .iter()
            .flatten()
            .filter(|attached| attached.domain_id == domain_id && attached.ats_control != 0)
        {
            self.issue_command(
                CMDQ_0_OP_ATC_INV | (attached.sid as u64) << CMDQ_0_SID_SHIFT,
                CMDQ_1_ATC_INV_SIZE_ALL,
            )?;
        }
        Ok(())
    }

    fn map_range_with_attributes(
        &self,
        domain: &DeviceMmuDomain,
        iova: u64,
        phys: u64,
        len: u64,
        permissions: DeviceMmuMapPermissions,
        memory: MemoryAttributes,
        leaf_shareability: Shareability,
    ) -> DeviceMmuResult<()> {
        let raw = self.raw_domain(domain)?;
        let attrs = SemanticLeafAttrs::<Format, NonSecureIpaStage2> {
            memory: Stage2MemoryAttributes::Combined(memory),
            permissions: Stage2Permissions::direct(
                match permissions {
                    DeviceMmuMapPermissions::Read => DataRights::Read,
                    DeviceMmuMapPermissions::Write => DataRights::Write,
                    DeviceMmuMapPermissions::ReadWrite => DataRights::ReadWrite,
                },
                ExecuteRights::Neither,
            ),
            output_address_space: (),
            controls: SemanticVmsa64Stage2LeafControls {
                shareability: leaf_shareability,
                access_flag: true,
                dirty: DirtyControl::Direct(DirtyBitManagement::SoftwareManaged),
                contiguous: false,
                software: SoftwareMetadata::new(0),
            },
        };
        let table_attrs = SemanticTableAttrs::<Format, NonSecureIpaStage2>::default();
        let config = LiveVmsaConfig {
            mair: 0,
            mair2: None,
            smmu_v3_aie: false,
            stage1_permissions: Stage1PermissionSettings::direct(),
            stage2_permissions: Stage2PermissionSettings::direct(),
            stage2_memory_mode: Stage2MemoryMode::FwbDisabled,
            d128_stage1_alias: aarch64_vmsa::attrs::D128Stage1AliasKind::NonGlobal,
            shareability: Shareability::InnerShareable,
            output_pas: (),
        };
        let mut mapper = raw.mapper.lock();
        let pages = len / PAGE_SIZE;
        for page in 0..pages {
            if mapper
                .map_semantic_leaf(
                    &config,
                    WalkInputAddr::new(iova + page * PAGE_SIZE),
                    WalkOutputAddr::new(phys + page * PAGE_SIZE),
                    Level::L3,
                    attrs,
                    table_attrs,
                )
                .is_err()
            {
                for rollback_page in 0..page {
                    let _ = unsafe {
                        mapper.unmap(WalkInputAddr::new(iova + rollback_page * PAGE_SIZE))
                    };
                }
                drop(mapper);
                let _ = self.invalidate_range(domain, iova, page * PAGE_SIZE);
                return Err(DeviceMmuError::HardwareError);
            }
        }
        drop(mapper);
        if !self.coherent {
            self.stream_table.0.clean_allocated();
        }
        self.invalidate_range(domain, iova, len)
    }

    fn disable_ats(&self, control: u64) {
        if control != 0 {
            let value = unsafe { core::ptr::read_volatile(control as *const u32) };
            unsafe {
                core::ptr::write_volatile(control as *mut u32, value & !PCI_ATS_CONTROL_ENABLE)
            };
            self.ats_mappings.lock().remove(&control);
        }
    }
}

extern "C" fn smmu_v3_interrupt(
    _interrupt_id: u32,
    _cpu: u32,
    _frame: &mut IrqFrame,
    _handle: IrqBorrowedHandle,
    context: usize,
) -> bool {
    let smmu = unsafe { &*(context as *const SmmuV3) };
    smmu.service_queues().is_ok()
}

impl DeviceMmuBackend for SmmuV3 {
    fn info(&self) -> DeviceMmuBackendInfo {
        let input_bits = self.output_bits.min(48);
        DeviceMmuBackendInfo {
            public_vendor_code: DMA_IOMMU_VENDOR_ARM_SMMU,
            name: "Arm SMMUv3.0",
            capabilities: DeviceMmuCapabilities {
                supported_page_sizes: PAGE_SIZES,
                supported_superpage_sizes: BLOCK_SIZES,
                input_address_bits: input_bits,
                output_address_bits: self.output_bits,
                page_table_alignment: PAGE_SIZE,
                invalidation_granularity: PAGE_SIZE,
                segment_boundary: 0,
                device_page_sizes_match_cpu_page_sizes: true,
                supports_range_invalidation: true,
                supports_domain_invalidation: true,
                reserved: 0,
            },
        }
    }

    fn create_domain(
        &self,
        _identity: DeviceMmuDeviceIdentity,
    ) -> DeviceMmuResult<DeviceMmuDomainInfo> {
        let mut memory = self.stream_table.clone();
        let input_bits = self.output_bits.min(48);
        let shape = TableShape::<Format, Granule>::root_for_addr_bits(Level::L0, input_bits)
            .map_err(|_| DeviceMmuError::InvalidDomain)?;
        let root = memory.allocate_zeroed_table(
            shape
                .alloc_layout()
                .map_err(|_| DeviceMmuError::InvalidDomain)?,
        )?;
        let geometry =
            RootTableGeometry::<Format, Granule>::new(root, input_bits, self.output_bits)
                .map_err(|_| DeviceMmuError::InvalidDomain)?;
        let mapper = Mapper::new_offline(
            RootTable::<Format, NonSecureIpaStage2, Granule>::from_geometry(geometry),
            memory.clone(),
            memory,
        )
        .map_err(|_| DeviceMmuError::InvalidDomain)?;
        let mut state = self.state.lock();
        let id = state.next_domain;
        state.next_domain = state.next_domain.wrapping_add(1).max(1);
        let vmid = state.next_vmid;
        state.next_vmid = state.next_vmid.wrapping_add(1).max(1);
        state.domains.insert(
            id,
            Arc::new(DomainState {
                vmid,
                root: root.raw(),
                input_bits,
                mapper: Mutex::new(mapper),
            }),
        );
        Ok(DeviceMmuDomainInfo {
            domain_id: id,
            translation_unit_index: 0,
            iova_start: PAGE_SIZE,
            iova_end: (1u64 << input_bits) - PAGE_SIZE,
            capabilities: self.info().capabilities,
        })
    }

    fn destroy_domain(&self, domain: &DeviceMmuDomain) {
        loop {
            let attached = {
                let mut state = self.state.lock();
                state
                    .attached
                    .iter_mut()
                    .find(|slot| {
                        slot.is_some_and(|attached| attached.domain_id == domain.domain_id())
                    })
                    .and_then(Option::take)
            };
            let Some(attached) = attached else {
                break;
            };
            if attached.ats_control != 0 {
                let _ = self.issue_command_and_sync(
                    CMDQ_0_OP_ATC_INV | (attached.sid as u64) << CMDQ_0_SID_SHIFT,
                    CMDQ_1_ATC_INV_SIZE_ALL,
                );
                self.disable_ats(attached.ats_control);
            }
            if let Ok(Some(ste)) = self.stream_entry(attached.sid, false) {
                unsafe { core::ptr::write_volatile((ste + STE_0) as *mut u64, 0) };
                self.publish(ste, STE_BYTES);
                let _ = self.invalidate_stream(attached.sid);
                let _ = self.reclaim_stream_block(attached.sid);
            }
        }
        let raw = self.state.lock().domains.remove(&domain.domain_id());
        if let Some(raw) = raw {
            let _ = self.issue_command_and_sync(
                CMDQ_0_OP_TLBI_S12_VMALL | (raw.vmid as u64) << CMDQ_0_VMID_SHIFT,
                0,
            );
            drop(raw.mapper.lock());
            self.stream_table.0.reclaim_translation_tree(raw.root);
        }
    }

    fn attach_device(
        &self,
        domain: &DeviceMmuDomain,
        identity: DeviceMmuDeviceIdentity,
    ) -> DeviceMmuResult<DeviceMmuAttachment> {
        self.service_queues()?;
        let sid = self.stream_id(identity)?;
        if sid as u64 >= 1u64 << self.sid_bits {
            return Err(DeviceMmuError::InvalidDevice);
        }
        let raw = self.raw_domain(domain)?;
        let ste = self
            .stream_entry(sid, true)?
            .ok_or(DeviceMmuError::InvalidDevice)?;
        let ats_control = self.enable_ats(identity)?;
        {
            let mut state = self.state.lock();
            if state
                .attached
                .iter()
                .flatten()
                .any(|attached| attached.sid == sid)
            {
                self.disable_ats(ats_control);
                return Err(DeviceMmuError::InvalidDevice);
            }
            let Some(slot) = state.attached.iter_mut().find(|slot| slot.is_none()) else {
                self.disable_ats(ats_control);
                return Err(DeviceMmuError::NoBackingFrame);
            };
            *slot = Some(AttachedStream {
                sid,
                domain_id: domain.domain_id(),
                ats_control,
            });
        }
        let vtcr = (64 - raw.input_bits as u64)
            | VTCR_SL0_LEVEL_0
            | VTCR_IRGN0_WBWA
            | VTCR_ORGN0_WBWA
            | VTCR_SH0_ISH
            | ((match self.output_bits {
                32 => 0,
                36 => 1,
                40 => 2,
                42 => 3,
                44 => 4,
                48 => 5,
                _ => 6,
            }) << VTCR_PS_SHIFT);
        unsafe {
            core::ptr::write_volatile(
                (ste + STE_1) as *mut u64,
                STE_1_SHCFG_INCOMING
                    | if ats_control != 0 {
                        STE_1_EATS_TRANSLATE
                    } else {
                        0
                    },
            );
            core::ptr::write_volatile(
                (ste + STE_2) as *mut u64,
                raw.vmid as u64 & STE_2_VMID_MASK
                    | (vtcr << STE_2_VTCR_SHIFT)
                    | STE_2_S2AA64
                    | STE_2_S2PTW,
            );
            core::ptr::write_volatile((ste + STE_3) as *mut u64, raw.root & STE_3_S2TTB_MASK);
            core::ptr::write_volatile((ste + STE_0) as *mut u64, STE_0_V | STE_0_CFG_S2_TRANS);
        }
        self.publish(ste, STE_BYTES);
        if let Err(error) = self.invalidate_stream(sid) {
            unsafe { core::ptr::write_volatile((ste + STE_0) as *mut u64, 0) };
            self.publish(ste, STE_BYTES);
            self.disable_ats(ats_control);
            let mut state = self.state.lock();
            if let Some(slot) = state
                .attached
                .iter_mut()
                .find(|slot| slot.is_some_and(|attached| attached.sid == sid))
            {
                *slot = None;
            }
            return Err(error);
        }
        Ok(DeviceMmuAttachment {
            attachment_id: sid as u64,
            domain_id: domain.domain_id(),
            translation_unit_index: 0,
            reserved: 0,
        })
    }

    fn detach_device(&self, _domain: &DeviceMmuDomain, attachment: DeviceMmuAttachment) {
        let sid = attachment.attachment_id as u32;
        let ats_control = {
            let mut state = self.state.lock();
            let Some(slot) = state
                .attached
                .iter_mut()
                .find(|slot| slot.is_some_and(|attached| attached.sid == sid))
            else {
                return;
            };
            slot.take().unwrap().ats_control
        };
        if ats_control != 0 {
            let _ = self.issue_command_and_sync(
                CMDQ_0_OP_ATC_INV | (sid as u64) << CMDQ_0_SID_SHIFT,
                CMDQ_1_ATC_INV_SIZE_ALL,
            );
            self.disable_ats(ats_control);
        }
        let Ok(Some(ste)) = self.stream_entry(attachment.attachment_id as u32, false) else {
            return;
        };
        unsafe { core::ptr::write_volatile((ste + STE_0) as *mut u64, 0) };
        self.publish(ste, STE_BYTES);
        let _ = self.invalidate_stream(attachment.attachment_id as u32);
        let _ = self.reclaim_stream_block(attachment.attachment_id as u32);
    }

    fn map_range(
        &self,
        domain: &DeviceMmuDomain,
        iova: u64,
        phys: u64,
        len: u64,
        permissions: DeviceMmuMapPermissions,
    ) -> DeviceMmuResult<()> {
        let cache = Cacheability::Cacheable {
            policy: CachePolicy::WriteBack,
            transience: MemoryTransience::NonTransient,
            allocation: AllocationHints::ReadWriteAllocate,
        };

        self.map_range_with_attributes(
            domain,
            iova,
            phys,
            len,
            permissions,
            MemoryAttributes::Normal {
                inner: cache,
                outer: cache,
            },
            Shareability::InnerShareable,
        )
    }

    fn map_mmio_range(
        &self,
        domain: &DeviceMmuDomain,
        iova: u64,
        phys: u64,
        len: u64,
        permissions: DeviceMmuMapPermissions,
    ) -> DeviceMmuResult<()> {
        self.map_range_with_attributes(
            domain,
            iova,
            phys,
            len,
            permissions,
            MemoryAttributes::Device(DeviceMemoryType::NonGatheringNonReorderingNoEarlyAck),
            Shareability::OuterShareable,
        )
    }

    fn unmap_range(
        &self,
        domain: &DeviceMmuDomain,
        iova: u64,
        page_count: u32,
    ) -> DeviceMmuResult<()> {
        let raw = self.raw_domain(domain)?;
        let mut mapper = raw.mapper.lock();
        for page in 0..page_count as u64 {
            unsafe { mapper.unmap(WalkInputAddr::new(iova + page * PAGE_SIZE)) }
                .map_err(|_| DeviceMmuError::NotMapped)?;
        }
        drop(mapper);
        if !self.coherent {
            self.stream_table.0.clean_allocated();
        }
        self.invalidate_range(domain, iova, page_count as u64 * PAGE_SIZE)
    }

    fn invalidate_range(
        &self,
        domain: &DeviceMmuDomain,
        iova: u64,
        len: u64,
    ) -> DeviceMmuResult<()> {
        let raw = self.raw_domain(domain)?;
        self.service_queues()?;
        let pages = len / PAGE_SIZE;
        for page in 0..pages {
            let address = iova + page * PAGE_SIZE;
            self.issue_command(
                CMDQ_0_OP_TLBI_S2_IPA | ((raw.vmid as u64) << CMDQ_0_VMID_SHIFT),
                address & CMDQ_1_TLBI_IPA_MASK | CMDQ_1_TLBI_LEAF,
            )?;
        }
        self.invalidate_domain_atc(domain.domain_id())?;
        self.issue_command(CMDQ_0_OP_CMD_SYNC, 0)
    }

    fn invalidate_domain(&self, domain: &DeviceMmuDomain) -> DeviceMmuResult<()> {
        let raw = self.raw_domain(domain)?;
        self.service_queues()?;
        self.issue_command(
            CMDQ_0_OP_TLBI_S12_VMALL | ((raw.vmid as u64) << CMDQ_0_VMID_SHIFT),
            0,
        )?;
        self.invalidate_domain_atc(domain.domain_id())?;
        self.issue_command(CMDQ_0_OP_CMD_SYNC, 0)
    }
}
