extern crate rand_xoshiro;

use crate::benchmarking::BenchWindow;
use crate::boot_packages;
use crate::console::Screen;
use crate::drivers::driver_install::install_prepacked_drivers;
use crate::drivers::interrupt_index::{
    apic_calibrate_ticks_per_ns_via_wait, apic_program_period_ns, calibrate_tsc, current_cpu_id,
    get_current_logical_id, init_percpu_gs, wait_using_pit_50ms, ApicImpl, IpiDest, IpiKind,
    LocalApic,
};
use crate::drivers::interrupt_index::{APIC, PICS};
use crate::drivers::pnp::manager::PNP_MANAGER;
use crate::drivers::timer_driver::NUM_CORES;
use crate::executable::program::{Program, PROGRAM_MANAGER};
use crate::exports::EXPORTS;
use crate::file_system::file_provider::{install_file_provider, ProviderKind};
use crate::gdt::PER_CPU_GDT;
use crate::idt::load_idt;
use crate::lazy_static;
use crate::memory::dma::init_dma_manager;
use crate::memory::heap::{init_heap, HEAP_SIZE};
use crate::memory::iommu::init_iommu;
use crate::memory::paging::frame_alloc::BootInfoFrameAllocator;
use crate::memory::paging::stack::StackSize;
use crate::memory::paging::tables::{init_kernel_cr3, kernel_cr3};
use crate::memory::paging::virt_tracker::KERNEL_RANGE_TRACKER;
use crate::scheduling::global_async::GlobalAsyncExecutor;
use crate::scheduling::runtime::runtime::yield_now;
use crate::scheduling::runtime::runtime::{init_executor_platform, spawn_detached};
use crate::scheduling::scheduler::{dump_scheduler, task_name_panic, SCHEDULER};
use crate::scheduling::task::Task;
use crate::structs::stopwatch::Stopwatch;
use crate::syscalls::syscall::syscall_init;
use crate::{cpu, println, BOOT_INFO};
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::{vec, vec::Vec};
use bootloader_api::BootInfo;
use core::arch::asm;
use core::marker::PhantomData;
use core::mem::size_of;
use core::panic::PanicInfo;
use core::sync::atomic::AtomicU8;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use kernel_types::benchmark::BenchWindowConfig;
use kernel_types::fs::Path;
use kernel_types::memory::Module;
use kernel_types::request::{BorrowedHandle, RequestDataView, RequestHandle, RequestType};
use rand_core::{RngCore, SeedableRng};
use rand_xoshiro::Xoshiro256PlusPlus;
use spin::rwlock::RwLock;
use spin::{Mutex, Once};
use x86_64::registers::control::Cr3;
use x86_64::structures::idt::InterruptDescriptorTable;
use x86_64::VirtAddr;
pub(crate) static KERNEL_INITIALIZED: AtomicBool = AtomicBool::new(false);
pub static CORE_LOCK: AtomicUsize = AtomicUsize::new(0);
pub static INIT_LOCK: Mutex<usize> = Mutex::new(0);
pub static CPU_ID: AtomicUsize = AtomicUsize::new(0);
pub static TOTAL_TIME: Once<Stopwatch> = Once::new();
pub const APIC_START_PERIOD: u64 = 250_000;
pub static BOOTSET: &[BootPkg] = boot_packages![
    "acpi", "pci", "ide", "disk", "partmgr", "volmgr", "mountmgr", "fat32", "i8042", "virtio"
];
pub static PANIC_ACTIVE: AtomicBool = AtomicBool::new(false);
static PANIC_OWNER: Mutex<Option<u32>> = Mutex::new(None);
lazy_static! {
    pub static ref DRIVE_WINDOW: BenchWindow = BenchWindow::new(BenchWindowConfig {
        name: "drive",
        folder: "C:\\system\\logs",
        log_samples: false,
        log_spans: true,
        log_mem_on_persist: true,
        end_on_drop: false,
        timeout_ms: None,
        auto_persist_secs: None,
        sample_reserve: 256,
        span_reserve: 256,
        disable_per_core: true
    });
}
const TLS_SELF_TEST_PENDING: u8 = 0;
const TLS_SELF_TEST_PASS: u8 = 1;
const TLS_SELF_TEST_FAIL: u8 = 2;

static TLS_SELF_TEST_BUSY: AtomicBool = AtomicBool::new(false);
static TLS_SELF_TEST_RESULT: AtomicU8 = AtomicU8::new(TLS_SELF_TEST_PENDING);

const TLS_TEMPLATE_U64: u64 = 0x1122_3344_5566_7788;
const TLS_MAIN_U64: u64 = 0xA1A2_A3A4_A5A6_A7A8;
const TLS_WORKER_U64: u64 = 0xB1B2_B3B4_B5B6_B7B8;
const TLS_TEMPLATE_BYTES: [u8; 16] = *b"KERNEL_TLS_CHECK";
const TLS_MAIN_BYTES: [u8; 16] = *b"KERNEL_TLS_MAIN!";
const TLS_WORKER_BYTES: [u8; 16] = *b"KERNEL_TLS_WORK!";
const TLS_MAIN_ZERO_BYTES: [u8; 16] = [0x4Du8; 16];
const TLS_WORKER_ZERO_BYTES: [u8; 16] = [0x57u8; 16];

#[thread_local]
static mut TLS_TEST_INIT_U64: u64 = TLS_TEMPLATE_U64;
#[thread_local]
static mut TLS_TEST_INIT_BYTES: [u8; 16] = TLS_TEMPLATE_BYTES;
#[thread_local]
static mut TLS_TEST_ZERO_U64: u64 = 0;
#[thread_local]
static mut TLS_TEST_ZERO_BYTES: [u8; 16] = [0; 16];
pub unsafe fn init() {
    init_kernel_cr3();
    let memory_map = &boot_info().memory_regions;
    BootInfoFrameAllocator::init_start(memory_map);
    {
        let _init_lock = INIT_LOCK.lock();
        init_heap();
        Screen::clear_framebuffer();
        load_idt();

        init_kernel_cr3();

        PER_CPU_GDT.lock().init_gdt();
        PICS.lock().initialize();
        x86_64::instructions::interrupts::enable();
        syscall_init();
        init_dma_manager();
        init_iommu();

        // TSC calibration
        let tsc_start = cpu::get_cycles();
        wait_using_pit_50ms();
        let tsc_end = cpu::get_cycles();
        calibrate_tsc(tsc_start, tsc_end, 50);
        TOTAL_TIME.call_once(Stopwatch::start);
        let apic_time = Stopwatch::start();
        match ApicImpl::init_apic_full() {
            Ok(_) => {
                x86_64::instructions::interrupts::disable();
                APIC.lock().as_ref().unwrap().start_aps();
                println!(
                    "APIC init and AP start successful in {} s!",
                    apic_time.elapsed_sec()
                );
            }
            Err(err) => {
                println!("APIC transition failed {}!", err.to_str());
            }
        }
    }
    while CORE_LOCK.load(Ordering::SeqCst) != 0 {}

    init_percpu_gs(CPU_ID.fetch_add(1, Ordering::Acquire) as u32);

    apic_calibrate_ticks_per_ns_via_wait(10);
    apic_program_period_ns(APIC_START_PERIOD);
    SCHEDULER.init_core(current_cpu_id());
    SCHEDULER.add_task(Task::new_kernel_mode(
        kernel_main,
        0,
        StackSize::Tiny,
        "kernel".into(),
        0,
    ));

    x86_64::instructions::interrupts::enable();
    println!("Init Done");
    KERNEL_INITIALIZED.store(true, Ordering::SeqCst);
    loop {
        asm!("hlt");
    }
}

// Temporary request-view self-test scaffolding. Delete this block after PnP bring-up validation.
#[repr(C)]
#[derive(kernel_types::RequestPayload)]
struct RequestViewTarget {
    value: u64,
    tag: u32,
}

#[repr(C)]
#[derive(kernel_types::RequestPayload)]
struct RequestViewAltTarget {
    value: u64,
}

#[repr(C)]
#[derive(kernel_types::RequestPayload)]
struct RequestIntoTarget {
    prefix: u32,
    value: u64,
    tag: u32,
}

#[repr(C)]
#[derive(kernel_types::RequestPayload)]
struct RequestViewMissingTarget {
    value: u64,
}

#[repr(C)]
#[derive(kernel_types::RequestPayload)]
#[request_view(RequestViewSource<RequestViewSourceState> => RequestViewTarget)]
#[request_view(RequestViewSource<RequestViewSourceState> => RequestViewAltTarget)]
#[request_view_mut(RequestViewSource<RequestViewSourceState> => RequestViewTarget)]
#[request_into(RequestViewSource<RequestViewSourceState> => RequestIntoTarget)]
struct RequestViewSource<State> {
    prefix: u32,
    target: RequestViewTarget,
    alt: RequestViewAltTarget,
    _state: PhantomData<fn() -> State>,
}

struct RequestViewSourceState;
struct RequestViewHeapState;

impl AsRef<RequestViewTarget> for RequestViewSource<RequestViewSourceState> {
    fn as_ref(&self) -> &RequestViewTarget {
        &self.target
    }
}

impl AsMut<RequestViewTarget> for RequestViewSource<RequestViewSourceState> {
    fn as_mut(&mut self) -> &mut RequestViewTarget {
        &mut self.target
    }
}

impl AsRef<RequestViewAltTarget> for RequestViewSource<RequestViewSourceState> {
    fn as_ref(&self) -> &RequestViewAltTarget {
        &self.alt
    }
}

impl From<RequestViewSource<RequestViewSourceState>> for RequestIntoTarget {
    fn from(source: RequestViewSource<RequestViewSourceState>) -> Self {
        Self {
            prefix: source.prefix,
            value: source.target.value,
            tag: source.target.tag,
        }
    }
}

#[repr(C)]
#[derive(kernel_types::RequestPayload)]
#[request_view(RequestViewHeapSource<RequestViewHeapState> => RequestViewTarget)]
#[request_view_mut(RequestViewHeapSource<RequestViewHeapState> => RequestViewTarget)]
#[request_into(RequestViewHeapSource<RequestViewHeapState> => RequestIntoTarget)]
struct RequestViewHeapSource<State> {
    padding: [u64; 9],
    target: RequestViewTarget,
    _state: PhantomData<fn() -> State>,
}

impl AsRef<RequestViewTarget> for RequestViewHeapSource<RequestViewHeapState> {
    fn as_ref(&self) -> &RequestViewTarget {
        &self.target
    }
}

impl AsMut<RequestViewTarget> for RequestViewHeapSource<RequestViewHeapState> {
    fn as_mut(&mut self) -> &mut RequestViewTarget {
        &mut self.target
    }
}

impl From<RequestViewHeapSource<RequestViewHeapState>> for RequestIntoTarget {
    fn from(source: RequestViewHeapSource<RequestViewHeapState>) -> Self {
        Self {
            prefix: source.padding[0] as u32,
            value: source.target.value,
            tag: source.target.tag,
        }
    }
}

trait RequestViewDirection: Send {}
trait RequestViewReadableDirection: RequestViewDirection {}
trait RequestViewWritableDirection: RequestViewReadableDirection {}
trait RequestViewAccessMode: Send {}

struct RequestViewReadOnly;
struct RequestViewWriteOnly;
struct RequestViewDirect;

impl RequestViewDirection for RequestViewReadOnly {}
impl RequestViewReadableDirection for RequestViewReadOnly {}
impl RequestViewDirection for RequestViewWriteOnly {}
impl RequestViewReadableDirection for RequestViewWriteOnly {}
impl RequestViewWritableDirection for RequestViewWriteOnly {}
impl RequestViewAccessMode for RequestViewDirect {}

#[repr(C)]
#[derive(kernel_types::RequestPayload)]
struct GenericRequestViewTarget<'a, Direction: RequestViewDirection, Access: RequestViewAccessMode>
{
    value: u64,
    _marker: PhantomData<(&'a (), fn() -> Direction, fn() -> Access)>,
}

#[repr(C)]
#[derive(kernel_types::RequestPayload)]
#[request_view(
    GenericRequestViewSource<'a, RequestViewSourceState, Direction, Access> => GenericRequestViewTarget<'a, Direction, Access>
    where Direction: RequestViewReadableDirection, Access: RequestViewAccessMode
)]
#[request_view_mut(
    GenericRequestViewSource<'a, RequestViewSourceState, Direction, Access> => GenericRequestViewTarget<'a, Direction, Access>
    where Direction: RequestViewWritableDirection, Access: RequestViewAccessMode
)]
struct GenericRequestViewSource<
    'a,
    State,
    Direction: RequestViewDirection,
    Access: RequestViewAccessMode,
> {
    target: GenericRequestViewTarget<'a, Direction, Access>,
    _state: PhantomData<fn() -> State>,
}

impl<'a, Direction, Access> AsRef<GenericRequestViewTarget<'a, Direction, Access>>
    for GenericRequestViewSource<'a, RequestViewSourceState, Direction, Access>
where
    Direction: RequestViewReadableDirection,
    Access: RequestViewAccessMode,
{
    fn as_ref(&self) -> &GenericRequestViewTarget<'a, Direction, Access> {
        &self.target
    }
}

impl<'a, Direction, Access> AsMut<GenericRequestViewTarget<'a, Direction, Access>>
    for GenericRequestViewSource<'a, RequestViewSourceState, Direction, Access>
where
    Direction: RequestViewWritableDirection,
    Access: RequestViewAccessMode,
{
    fn as_mut(&mut self) -> &mut GenericRequestViewTarget<'a, Direction, Access> {
        &mut self.target
    }
}

struct RequestViewConcreteState;
struct RequestViewOtherState;

#[repr(C)]
#[derive(kernel_types::RequestPayload)]
struct ConcreteRequestViewTarget<'a, Direction: RequestViewDirection> {
    value: u64,
    _marker: PhantomData<(&'a (), fn() -> Direction)>,
}

#[repr(C)]
#[derive(kernel_types::RequestPayload)]
#[request_view(
    ConcreteRequestViewSource<'a, RequestViewConcreteState, Direction> => ConcreteRequestViewTarget<'a, Direction>
    where Direction: RequestViewReadableDirection
)]
#[request_view_mut(
    ConcreteRequestViewSource<'a, RequestViewConcreteState, Direction> => ConcreteRequestViewTarget<'a, Direction>
    where Direction: RequestViewWritableDirection
)]
struct ConcreteRequestViewSource<'a, State, Direction: RequestViewDirection> {
    target: ConcreteRequestViewTarget<'a, Direction>,
    _state: PhantomData<fn() -> State>,
}

impl<'a, Direction> AsRef<ConcreteRequestViewTarget<'a, Direction>>
    for ConcreteRequestViewSource<'a, RequestViewConcreteState, Direction>
where
    Direction: RequestViewReadableDirection,
{
    fn as_ref(&self) -> &ConcreteRequestViewTarget<'a, Direction> {
        &self.target
    }
}

impl<'a, Direction> AsMut<ConcreteRequestViewTarget<'a, Direction>>
    for ConcreteRequestViewSource<'a, RequestViewConcreteState, Direction>
where
    Direction: RequestViewWritableDirection,
{
    fn as_mut(&mut self) -> &mut ConcreteRequestViewTarget<'a, Direction> {
        &mut self.target
    }
}

fn test_request_payload_views() {
    test_request_payload_exact_shared_mut_and_take();
    test_request_payload_heap_view();
    test_request_payload_owned_into();
    test_request_payload_borrowed_views();
    test_request_payload_generic_where_views();
    test_request_payload_concrete_generic_views();
    println!("RequestPayload view self-test passed");
}

fn test_request_payload_exact_shared_mut_and_take() {
    type Source = RequestViewSource<RequestViewSourceState>;
    let mut handle = RequestHandle::new_t(
        RequestType::DeviceControl(0xF00D),
        Source {
            prefix: 7,
            target: RequestViewTarget { value: 11, tag: 1 },
            alt: RequestViewAltTarget { value: 22 },
            _state: PhantomData,
        },
    );

    match handle.data() {
        RequestDataView::FromDevice(mut data) => {
            assert_eq!(data.view::<Source>().unwrap().prefix, 7);
            assert_eq!(data.view::<RequestViewTarget>().unwrap().value, 11);
            assert_eq!(data.view::<RequestViewAltTarget>().unwrap().value, 22);
            assert!(data.view::<RequestViewMissingTarget>().is_none());
            assert!(data.view_mut::<RequestViewAltTarget>().is_none());

            data.view_mut::<RequestViewTarget>().unwrap().value = 33;
            assert_eq!(data.view::<Source>().unwrap().target.value, 33);
        }
        RequestDataView::ToDevice(_) => panic!("owned request payload should be writable"),
    }

    match handle.data() {
        RequestDataView::FromDevice(mut data) => {
            assert!(data.take_exact::<RequestViewTarget>().is_err());
            let source = data.take_exact::<Source>().unwrap();
            assert_eq!(source.target.value, 33);
            assert_eq!(source.alt.value, 22);
        }
        RequestDataView::ToDevice(_) => panic!("owned request payload should be writable"),
    }
}

fn test_request_payload_heap_view() {
    type HeapSource = RequestViewHeapSource<RequestViewHeapState>;
    let mut handle = RequestHandle::new_t(
        RequestType::DeviceControl(0xF00D),
        HeapSource {
            padding: [0xAB; 9],
            target: RequestViewTarget { value: 44, tag: 2 },
            _state: PhantomData,
        },
    );

    match handle.data() {
        RequestDataView::FromDevice(mut data) => {
            assert_eq!(data.view::<RequestViewTarget>().unwrap().value, 44);
            data.view_mut::<RequestViewTarget>().unwrap().value = 55;
            assert_eq!(data.view::<HeapSource>().unwrap().target.value, 55);
        }
        RequestDataView::ToDevice(_) => panic!("owned request payload should be writable"),
    }
}

fn test_request_payload_owned_into() {
    type Source = RequestViewSource<RequestViewSourceState>;
    let mut inline_handle = RequestHandle::new_t(
        RequestType::DeviceControl(0xF00D),
        Source {
            prefix: 12,
            target: RequestViewTarget { value: 123, tag: 5 },
            alt: RequestViewAltTarget { value: 0 },
            _state: PhantomData,
        },
    );

    match inline_handle.data() {
        RequestDataView::FromDevice(mut data) => {
            let target = data.require::<RequestIntoTarget>().unwrap();
            assert_eq!(target.prefix, 12);
            assert_eq!(target.value, 123);
            assert_eq!(target.tag, 5);
        }
        RequestDataView::ToDevice(_) => panic!("owned request payload should be writable"),
    }

    type HeapSource = RequestViewHeapSource<RequestViewHeapState>;
    let mut heap_handle = RequestHandle::new_t(
        RequestType::DeviceControl(0xF00D),
        HeapSource {
            padding: [0xAB; 9],
            target: RequestViewTarget { value: 456, tag: 6 },
            _state: PhantomData,
        },
    );

    match heap_handle.data() {
        RequestDataView::FromDevice(mut data) => {
            let target = data.require::<RequestIntoTarget>().unwrap();
            assert_eq!(target.prefix, 0xAB);
            assert_eq!(target.value, 456);
            assert_eq!(target.tag, 6);
        }
        RequestDataView::ToDevice(_) => panic!("owned request payload should be writable"),
    }
}

fn test_request_payload_borrowed_views() {
    type Source = RequestViewSource<RequestViewSourceState>;
    let read_only_source = Source {
        prefix: 9,
        target: RequestViewTarget { value: 66, tag: 3 },
        alt: RequestViewAltTarget { value: 77 },
        _state: PhantomData,
    };
    let mut read_only_handle = RequestHandle::new_t(
        RequestType::DeviceControl(0xF00D),
        RequestViewMissingTarget { value: 0 },
    );
    {
        let mut borrowed = BorrowedHandle::read_only(&mut read_only_handle, &read_only_source);
        match borrowed.handle().data() {
            RequestDataView::ToDevice(data) => {
                assert_eq!(data.view::<Source>().unwrap().prefix, 9);
                assert_eq!(data.view::<RequestViewTarget>().unwrap().value, 66);
            }
            RequestDataView::FromDevice(_) => {
                panic!("read-only borrowed payload should not be writable")
            }
        }
    }

    let mut writable_source = Source {
        prefix: 10,
        target: RequestViewTarget { value: 88, tag: 4 },
        alt: RequestViewAltTarget { value: 99 },
        _state: PhantomData,
    };
    let mut writable_handle = RequestHandle::new_t(
        RequestType::DeviceControl(0xF00D),
        RequestViewMissingTarget { value: 0 },
    );
    {
        let mut borrowed = BorrowedHandle::writable(&mut writable_handle, &mut writable_source);
        match borrowed.handle().data() {
            RequestDataView::FromDevice(mut data) => {
                assert_eq!(data.view::<RequestViewTarget>().unwrap().value, 88);
                data.view_mut::<RequestViewTarget>().unwrap().value = 100;
                assert!(data.require::<RequestIntoTarget>().is_err());
            }
            RequestDataView::ToDevice(_) => panic!("writable borrowed payload should be writable"),
        }
    }
    assert_eq!(writable_source.target.value, 100);
}

fn test_request_payload_generic_where_views() {
    type WritableSource = GenericRequestViewSource<
        'static,
        RequestViewSourceState,
        RequestViewWriteOnly,
        RequestViewDirect,
    >;
    type WritableTarget =
        GenericRequestViewTarget<'static, RequestViewWriteOnly, RequestViewDirect>;
    let mut writable = RequestHandle::new_t(
        RequestType::DeviceControl(0xF00D),
        WritableSource {
            target: WritableTarget {
                value: 111,
                _marker: PhantomData,
            },
            _state: PhantomData,
        },
    );

    match writable.data() {
        RequestDataView::FromDevice(mut data) => {
            assert_eq!(data.view::<WritableTarget>().unwrap().value, 111);
            data.view_mut::<WritableTarget>().unwrap().value = 222;
            assert_eq!(data.view::<WritableSource>().unwrap().target.value, 222);
        }
        RequestDataView::ToDevice(_) => panic!("owned request payload should be writable"),
    }

    type ReadOnlySource = GenericRequestViewSource<
        'static,
        RequestViewSourceState,
        RequestViewReadOnly,
        RequestViewDirect,
    >;
    type ReadOnlyTarget = GenericRequestViewTarget<'static, RequestViewReadOnly, RequestViewDirect>;
    let mut read_only = RequestHandle::new_t(
        RequestType::DeviceControl(0xF00D),
        ReadOnlySource {
            target: ReadOnlyTarget {
                value: 333,
                _marker: PhantomData,
            },
            _state: PhantomData,
        },
    );

    match read_only.data() {
        RequestDataView::FromDevice(mut data) => {
            assert_eq!(data.view::<ReadOnlyTarget>().unwrap().value, 333);
            assert!(data.view_mut::<ReadOnlyTarget>().is_none());
        }
        RequestDataView::ToDevice(_) => panic!("owned request payload should be writable"),
    }
}

fn test_request_payload_concrete_generic_views() {
    type ConcreteWritableSource =
        ConcreteRequestViewSource<'static, RequestViewConcreteState, RequestViewWriteOnly>;
    type ConcreteWritableTarget = ConcreteRequestViewTarget<'static, RequestViewWriteOnly>;
    let mut concrete = RequestHandle::new_t(
        RequestType::DeviceControl(0xF00D),
        ConcreteWritableSource {
            target: ConcreteWritableTarget {
                value: 444,
                _marker: PhantomData,
            },
            _state: PhantomData,
        },
    );

    match concrete.data() {
        RequestDataView::FromDevice(mut data) => {
            assert_eq!(data.view::<ConcreteWritableTarget>().unwrap().value, 444);
            data.view_mut::<ConcreteWritableTarget>().unwrap().value = 555;
            assert_eq!(
                data.view::<ConcreteWritableSource>().unwrap().target.value,
                555
            );
        }
        RequestDataView::ToDevice(_) => panic!("owned request payload should be writable"),
    }

    type OtherStateSource =
        ConcreteRequestViewSource<'static, RequestViewOtherState, RequestViewWriteOnly>;
    let mut other_state = RequestHandle::new_t(
        RequestType::DeviceControl(0xF00D),
        OtherStateSource {
            target: ConcreteWritableTarget {
                value: 666,
                _marker: PhantomData,
            },
            _state: PhantomData,
        },
    );

    match other_state.data() {
        RequestDataView::FromDevice(mut data) => {
            assert!(data.view::<ConcreteWritableTarget>().is_none());
            assert!(data.view_mut::<ConcreteWritableTarget>().is_none());
            assert_eq!(data.view::<OtherStateSource>().unwrap().target.value, 666);
        }
        RequestDataView::ToDevice(_) => panic!("owned request payload should be writable"),
    }
}

pub extern "win64" fn kernel_main(ctx: usize) {
    init_executor_platform();
    GlobalAsyncExecutor::global().init(NUM_CORES.load(Ordering::Acquire));
    install_file_provider(ProviderKind::Bootstrap);
    test_kernel_tls_runtime();
    test_request_payload_views();
    let mut program = Program::new(
        "KRNL".to_string(),
        Path::from_string(""),
        VirtAddr::new(0xFFFF_8500_0000_0000),
        kernel_cr3(),
        KERNEL_RANGE_TRACKER.clone(),
    );

    program.main_thread = Some(SCHEDULER.get_current_task(current_cpu_id()).unwrap());

    program.modules = RwLock::new(vec![Arc::new(RwLock::new(Module {
        title: "KRNL.DLL".into(),
        image_path: Path::from_string(""),
        parent_pid: 0,
        image_base: VirtAddr::new(0xFFFF_8500_0000_0000),
        symbols: EXPORTS.to_vec(),
    }))]);
    let _pid = PROGRAM_MANAGER.add_program(program);

    spawn_detached(async move {
        let _ = install_prepacked_drivers().await;
        // BOOT_WINDOW.start();
        let _ = PNP_MANAGER.init_from_registry().await;
        // bench_async_vs_sync_call_latency_async().await;

        // benchmark_async_async().await;
    });
    println!("");
}
#[no_mangle]
#[inline(never)]
pub extern "win64" fn trigger_guard_page_overflow() -> ! {
    let task = SCHEDULER
        .get_current_task(current_cpu_id())
        .expect("no current task");
    let guard = task.guard_page.load(core::sync::atomic::Ordering::Acquire);
    let target = (guard + 0x800) & !0xFu64;
    unsafe {
        asm!(
            "mov rsp, {0}",
            "mov qword ptr [rsp], 0",
            in(reg) target,
            options(noreturn)
        );
    }
}
#[inline(never)]
fn halt_loop() -> ! {
    unsafe {
        loop {
            asm!("hlt;", options(nomem, nostack, preserves_flags));
        }
    }
}
#[no_mangle]
pub extern "win64" fn panic_common(mod_name: &'static str, info: &PanicInfo) -> ! {
    if PANIC_ACTIVE.swap(true, Ordering::SeqCst) {
        halt_loop()
    }

    x86_64::instructions::interrupts::disable();
    unsafe { Cr3::write(kernel_cr3(), Cr3::read().1) }
    crate::KERNEL_INITIALIZED.store(false, Ordering::SeqCst);

    let me = get_current_logical_id() as u32;
    let is_owner = match PANIC_OWNER.try_lock() {
        Some(mut g) => {
            if g.is_none() {
                *g = Some(me);
                true
            } else {
                g.as_ref() == Some(&me)
            }
        }
        None => false,
    };
    if is_owner {
        println!("=== KERNEL PANIC [{}] ===", mod_name);
        println!("{}", info);

        // let dump = dump_scheduler();
        // println!("--- Running tasks at panic ---");
        // for (cpu_id, slot) in dump.current_tasks.iter().enumerate().take(dump.num_cores) {
        //     if let Some(task) = slot {
        //         let name = unsafe { task_name_panic(task) };
        //         println!(
        //             "  CPU {}: \"{}\" (id={})",
        //             cpu_id,
        //             name,
        //             task.id.load(Ordering::Relaxed)
        //         );
        //     } else {
        //         println!("  CPU {}: <idle>", cpu_id);
        //     }
        // }
        // println!("--- Tasks in run queue and ipi queue ---");
        // for (cpu_id, queue) in dump.run_queues.iter().enumerate().take(dump.num_cores) {
        //     let some_count = queue.tasks.iter().filter(|task| task.is_some()).count();
        //     println!(
        //         "  CPU {}: run_queue={} (captured={}, total_before_drain={})",
        //         cpu_id, some_count, queue.captured, queue.total_before_drain
        //     );
        // }

        // for (cpu_id, queue) in dump.ipi_queues.iter().enumerate().take(dump.num_cores) {
        //     let some_count = queue.tasks.iter().filter(|task| task.is_some()).count();
        //     println!(
        //         "  CPU {}: ipi_queue={} (captured={}, total_before_drain={})",
        //         cpu_id, some_count, queue.captured, queue.total_before_drain
        //     );
        // }
        // for (cpu_id, task) in dump.current_tasks.iter().enumerate().take(dump.num_cores) {
        //     match task {
        //         Some(task) => {
        //             let stack_size = task.stack_size.load(core::sync::atomic::Ordering::Acquire);
        //             let guard_page = task.guard_page.load(core::sync::atomic::Ordering::Acquire);

        //             println!(
        //                 "  CPU {}: current_task stack_size={} guard_page={:#x}",
        //                 cpu_id, stack_size, guard_page
        //             );
        //         }
        //         None => {
        //             println!("  CPU {}: current_task=None", cpu_id);
        //         }
        //     }
        // }
        unsafe {
            if let Some(a) = APIC.lock().as_ref() {
                a.lapic.send_ipi(IpiDest::AllExcludingSelf, IpiKind::Nmi)
            }
        }

        halt_loop()
    } else {
        halt_loop()
    }
}

#[no_mangle]
#[allow(unconditional_recursion)]
pub extern "C" fn trigger_stack_overflow() {
    trigger_stack_overflow();
}

#[no_mangle]
#[inline(never)]
pub extern "win64" fn trigger_triple_fault() -> ! {
    static EMPTY_IDT: InterruptDescriptorTable = InterruptDescriptorTable::new();

    x86_64::instructions::interrupts::disable();
    unsafe {
        EMPTY_IDT.load();
        asm!("ud2", options(noreturn));
    }
}

pub fn trigger_breakpoint() {
    unsafe {
        asm!("int 3");
    }
}

pub fn test_full_heap() {
    let element_count = (HEAP_SIZE as usize / 4) / size_of::<u64>();

    let mut vec: Vec<u64> = Vec::with_capacity(1);
    for i in 0..element_count {
        vec.push(i as u64);
    }
    for i in 0..element_count {
        if i != vec[i] as usize {
            println!("Heap data verification failed at index {}", i);
        }
    }

    println!(
        "Heap test passed: allocated and verified {} elements in the heap",
        element_count
    );
}

pub extern "win64" fn random_number() -> u64 {
    let mut rng = Random::new(cpu::get_cycles());
    rng.next_u64()
}

pub fn boot_info() -> &'static mut BootInfo {
    unsafe { BOOT_INFO.as_mut().expect("BOOT_INFO not initialized") }
}

pub fn generate_guid() -> [u8; 16] {
    let start: [u8; 8] = random_number().to_le_bytes();
    let end: [u8; 8] = random_number().to_le_bytes();

    let mut guid = [0u8; 16];
    guid[..8].copy_from_slice(&start);
    guid[8..].copy_from_slice(&end);

    // Set UUID version (v4)
    guid[6] = (guid[6] & 0x0F) | 0x40;
    // Set UUID variant (RFC 4122)
    guid[8] = (guid[8] & 0x3F) | 0x80;

    guid
}

pub struct Random {
    rng: Xoshiro256PlusPlus,
}

impl Random {
    pub fn new(seed: u64) -> Self {
        let rng = Xoshiro256PlusPlus::seed_from_u64(seed);
        Self { rng }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }

    pub fn next_u32(&mut self) -> u32 {
        (self.rng.next_u64() & 0xFFFF_FFFF) as u32
    }
}

pub fn name_to_utf16_fixed(name: &str) -> [u16; 36] {
    let mut buffer = [0x0000; 36];
    for (i, c) in name.encode_utf16().take(36).enumerate() {
        buffer[i] = c;
    }
    buffer
}

#[derive(Clone, Copy)]
pub struct BootPkg {
    pub name: &'static str,
    pub toml: &'static [u8],
    pub image: &'static [u8],
}

#[macro_export]
macro_rules! boot_packages {
    ($($name:literal),+ $(,)?) => {{
        &[
            $(
                {
                    #[cfg(debug_assertions)]
                    const IMAGE: &[u8] = include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/../drivers/target/x86_64-rustos-driver/debug/",
                        $name,
                        ".dll"
                    ));
                    #[cfg(not(debug_assertions))]
                    const IMAGE: &[u8] = include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/../drivers/target/x86_64-rustos-driver/release/",
                        $name,
                        ".dll"
                    ));

                    $crate::util::BootPkg {
                        name: $name,
                        toml: include_bytes!(concat!(
                            env!("CARGO_MANIFEST_DIR"),
                            "/../drivers/",
                            $name,
                            "/src/",
                            $name,
                            ".toml"
                        )),
                        image: IMAGE,
                    }
                },
            )+
        ] as &[ $crate::util::BootPkg ]
    }};
}
unsafe fn tls_test_snapshot() -> (u64, [u8; 16], u64, [u8; 16]) {
    (
        TLS_TEST_INIT_U64,
        TLS_TEST_INIT_BYTES,
        TLS_TEST_ZERO_U64,
        TLS_TEST_ZERO_BYTES,
    )
}

unsafe fn tls_test_write(init_u64: u64, init_bytes: [u8; 16], zero_u64: u64, zero_bytes: [u8; 16]) {
    TLS_TEST_INIT_U64 = init_u64;
    TLS_TEST_INIT_BYTES = init_bytes;
    TLS_TEST_ZERO_U64 = zero_u64;
    TLS_TEST_ZERO_BYTES = zero_bytes;
}

extern "win64" fn kernel_tls_self_test_worker(_ctx: usize) {
    let expected = unsafe { tls_test_snapshot() };
    if expected != (TLS_TEMPLATE_U64, TLS_TEMPLATE_BYTES, 0, [0; 16]) {
        TLS_SELF_TEST_RESULT.store(TLS_SELF_TEST_FAIL, Ordering::Release);
        return;
    }

    unsafe {
        tls_test_write(
            TLS_WORKER_U64,
            TLS_WORKER_BYTES,
            TLS_WORKER_U64,
            TLS_WORKER_ZERO_BYTES,
        );
    }

    let worker_snapshot = unsafe { tls_test_snapshot() };
    let ok = worker_snapshot
        == (
            TLS_WORKER_U64,
            TLS_WORKER_BYTES,
            TLS_WORKER_U64,
            TLS_WORKER_ZERO_BYTES,
        );

    TLS_SELF_TEST_RESULT.store(
        if ok {
            TLS_SELF_TEST_PASS
        } else {
            TLS_SELF_TEST_FAIL
        },
        Ordering::Release,
    );
}

pub fn test_kernel_tls_runtime() {
    let current = SCHEDULER
        .get_current_task(current_cpu_id())
        .expect("kernel TLS self-test requires a scheduled task");
    assert!(
        current.is_kernel_mode.load(Ordering::Acquire),
        "kernel TLS self-test requires a scheduled kernel task"
    );

    let initial = unsafe { tls_test_snapshot() };
    if initial != (TLS_TEMPLATE_U64, TLS_TEMPLATE_BYTES, 0, [0; 16]) {
        panic!(
            "kernel TLS self-test saw wrong initial state: {:?}",
            initial
        );
    }

    unsafe {
        tls_test_write(
            TLS_MAIN_U64,
            TLS_MAIN_BYTES,
            TLS_MAIN_U64,
            TLS_MAIN_ZERO_BYTES,
        );
    }

    SCHEDULER.add_task(Task::new_kernel_mode(
        kernel_tls_self_test_worker,
        0,
        StackSize::Tiny,
        "kernel-tls-self-test".into(),
        0,
    ));

    let mut completed = false;
    for _ in 0..4096 {
        if TLS_SELF_TEST_RESULT.load(Ordering::Acquire) != TLS_SELF_TEST_PENDING {
            completed = true;
            break;
        }
        yield_now();
    }

    let current_snapshot = unsafe { tls_test_snapshot() };
    unsafe {
        tls_test_write(TLS_TEMPLATE_U64, TLS_TEMPLATE_BYTES, 0, [0; 16]);
    }
    let worker_result = TLS_SELF_TEST_RESULT.load(Ordering::Acquire);
    TLS_SELF_TEST_BUSY.store(false, Ordering::Release);

    assert!(completed, "kernel TLS self-test worker did not complete");
    assert!(
        worker_result == TLS_SELF_TEST_PASS,
        "kernel TLS self-test worker failed with state {}",
        worker_result
    );
    assert!(
        current_snapshot
            == (
                TLS_MAIN_U64,
                TLS_MAIN_BYTES,
                TLS_MAIN_U64,
                TLS_MAIN_ZERO_BYTES,
            ),
        "kernel TLS self-test current thread state was clobbered: {:?}",
        current_snapshot
    );

    println!("Kernel TLS self-test passed");
}
