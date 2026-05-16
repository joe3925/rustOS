use alloc::{string::String, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU8, AtomicU32, Ordering};

use spin::RwLock;
use x86_64::VirtAddr;

use crate::device::{
    DevExtError, DeviceInit, DeviceObject, DeviceStack, DriverPackage, DriverRuntime, DriverState,
    StackLayer,
};
use crate::fs::Path;
use crate::io::IoVtable;
use crate::memory::Module;
use crate::pnp::BootType;

#[derive(Debug, Default, PartialEq, Eq)]
struct TestExt {
    value: u32,
}

fn runtime(name: &str) -> Arc<DriverRuntime> {
    Arc::new(DriverRuntime {
        pkg: Arc::new(DriverPackage {
            name: name.into(),
            image_path: Path::from_string("C:/drivers/test.dll"),
            toml_path: String::from("C:/drivers/test.toml"),
            start: BootType::Demand,
            hwids: Vec::new(),
        }),
        module: Arc::new(RwLock::new(Module {
            title: name.into(),
            image_path: Path::from_string("C:/drivers/test.dll"),
            parent_pid: 0,
            image_base: VirtAddr::new(0),
            symbols: Vec::new(),
            pe_info: None,
        })),
        state: AtomicU8::new(DriverState::Loaded as u8),
        refcnt: AtomicU32::new(1),
    })
}

#[test]
fn driver_runtime_state_round_trips_through_atomic_storage() {
    let runtime = runtime("drv");

    assert_eq!(runtime.get_state(), DriverState::Loaded);
    runtime.set_state(DriverState::Started);
    assert_eq!(runtime.get_state(), DriverState::Started);
    runtime.state.store(200, Ordering::Release);
    assert_eq!(runtime.get_state(), DriverState::Failed);
}

#[test]
fn device_init_moves_typed_extension_into_device_object() {
    let mut init = DeviceInit::new(IoVtable::new(), None);
    init.set_dev_ext_from(TestExt { value: 42 });

    let dev = DeviceObject::new(init);
    assert_eq!(dev.try_devext::<TestExt>().unwrap().value, 42);

    match dev.try_devext::<u64>() {
        Err(DevExtError::TypeMismatch { expected }) => {
            assert_eq!(expected, core::any::type_name::<u64>())
        }
        Ok(_) => panic!("unexpectedly read devext with the wrong type"),
        Err(other) => panic!("unexpected devext error: {other:?}"),
    }
}

#[test]
fn device_init_can_install_default_extension() {
    let mut init = DeviceInit::new(IoVtable::new(), None);
    init.set_dev_ext_default::<TestExt>();

    let dev = DeviceObject::new(init);
    assert_eq!(*dev.try_devext::<TestExt>().unwrap(), TestExt::default());
}

#[test]
fn device_object_links_lower_and_upper_devices_once() {
    let upper = DeviceObject::new(DeviceInit::new(IoVtable::new(), None));
    let lower = DeviceObject::new(DeviceInit::new(IoVtable::new(), None));

    DeviceObject::set_lower_upper(&upper, lower.clone());

    assert!(Arc::ptr_eq(upper.lower_device.get().unwrap(), &lower));
    assert!(Arc::ptr_eq(
        &lower.upper_device.get().unwrap().upgrade().unwrap(),
        &upper
    ));
}

#[test]
fn device_stack_prefers_upper_then_function_then_lower() {
    let runtime = runtime("stack");
    let mk_layer = |name: &str| StackLayer {
        driver: crate::device::DriverObject::allocate(runtime.clone(), name.into()),
        devobj: Some(DeviceObject::new(DeviceInit::new(IoVtable::new(), None))),
    };

    let mut stack = DeviceStack::new();
    assert!(stack.get_top_device_object().is_none());

    let lower = mk_layer("lower");
    let function = mk_layer("function");
    let upper = mk_layer("upper");

    stack.lower.push(lower.clone());
    assert!(Arc::ptr_eq(
        &stack.get_top_device_object().unwrap(),
        lower.devobj.as_ref().unwrap()
    ));

    stack.function = Some(function.clone());
    assert!(Arc::ptr_eq(
        &stack.get_top_device_object().unwrap(),
        function.devobj.as_ref().unwrap()
    ));

    stack.upper.push(upper.clone());
    assert!(Arc::ptr_eq(
        &stack.get_top_device_object().unwrap(),
        upper.devobj.as_ref().unwrap()
    ));
}
