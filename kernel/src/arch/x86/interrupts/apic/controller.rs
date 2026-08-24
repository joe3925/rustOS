use alloc::vec::Vec;
use kernel_types::irq::IrqSafeMutex;
use x86_64::PhysAddr;

use crate::machine::MachineInterruptInfo;

use super::local::LAPIC_BASE_VA;
use crate::arch::x86::cpu::{get_cpu_info, platform_cpu_id};

use super::io::Ioapic;
use super::local::{Lapic, LocalApic};

use self::ApicErrors::{AlreadyInit, BadInterruptModel, NoACPI, NoCPUID, NotAvailable};

#[derive(Debug, Clone, Copy)]
pub(crate) enum ApicErrors {
    NotAvailable,
    NoCPUID,
    BadInterruptModel,
    NoACPI,
    AlreadyInit,
}
impl ApicErrors {
    pub(crate) fn to_str(&self) -> &'static str {
        match self {
            NotAvailable => "Apic is not supported by this CPU",
            NoCPUID => "CPU ID is not supported by this CPU",
            BadInterruptModel => "CPU has incorrect Interrupt model",
            NoACPI => "ACPI is not supported by this CPU",
            AlreadyInit => "The APIC has already been init",
        }
    }
}

pub(crate) static APIC: IrqSafeMutex<Option<ApicImpl>> = IrqSafeMutex::new(None);

pub(crate) struct ApicImpl {
    pub(crate) apic_info: MachineInterruptInfo,
    pub(crate) lapic: Lapic,
    pub(crate) ioapics: Vec<Ioapic>,
}

impl ApicImpl {
    pub(crate) fn new() -> Result<Self, ApicErrors> {
        let info = get_cpu_info();
        let features = info.get_feature_info().ok_or(NoCPUID)?;

        if !features.has_apic() {
            return Err(NotAvailable);
        }

        let model = crate::machine::machine_info()
            .interrupt_info()
            .ok_or(NoACPI)?
            .clone();
        let lapic = Lapic::new(PhysAddr::new(model.local_interrupt_controller_address))
            .map_err(|_| BadInterruptModel)?;
        let mut ioapics = Vec::with_capacity(model.interrupt_controllers.len());
        for info in &model.interrupt_controllers {
            ioapics.push(
                Ioapic::new(
                    PhysAddr::new(info.address),
                    info.global_system_interrupt_base,
                )
                .map_err(|_| BadInterruptModel)?,
            );
        }
        if ioapics.is_empty() {
            return Err(BadInterruptModel);
        }

        Ok(Self {
            apic_info: model,
            lapic,
            ioapics,
        })
    }

    pub(crate) fn bind_wired_interrupt(&self, source: u32, vector: u8, destination: u8) -> bool {
        let Some(ioapic) = self.ioapics.iter().find(|ioapic| ioapic.owns(source)) else {
            return false;
        };
        ioapic.unmask_irq_any_cpu(source, vector, destination);
        true
    }

    pub(crate) fn unbind_wired_interrupt(&self, source: u32) {
        if let Some(ioapic) = self.ioapics.iter().find(|ioapic| ioapic.owns(source)) {
            ioapic.mask_irq(source);
        }
    }
    pub(crate) fn init_apic_full() -> Result<(), ApicErrors> {
        use core::sync::atomic::Ordering;
        use x86_64::instructions::interrupts;

        interrupts::disable();

        if APIC.lock().is_some() {
            interrupts::enable();
            return Err(ApicErrors::AlreadyInit);
        }

        let apic = ApicImpl::new()?;

        unsafe {
            let logical_id = platform_cpu_id();
            apic.lapic.init(logical_id);
            apic.lapic.init_timer();
            LAPIC_BASE_VA.store(apic.lapic.base_addr.as_u64(), Ordering::Release);
            APIC.lock().replace(apic);
        }

        interrupts::enable();
        Ok(())
    }
}
