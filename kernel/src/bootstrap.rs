use crate::{
    drivers::{driver_install::install_prepacked_drivers, pnp::pnp_manager::PNP_MANAGER},
    println,
    registry::{reg, Data},
};

pub fn bootstrap_on_c_and_init_pnp() {
    match install_prepacked_drivers() {
        Ok(()) => println!("Bootstrap: prepacked drivers installed to C:\\SYSTEM"),
        Err(e) => println!("Bootstrap: install_prepacked_drivers failed: {:?}", e),
    }

    if let Err(e) = PNP_MANAGER.init_from_registry() {
        println!("Bootstrap: PNP init_from_registry failed: {:?}", e);
    }
}
pub fn maybe_finish_first_boot() {
    let is_first = matches!(
        reg::get_value("SYSTEM/SETUP", "FirstBoot"),
        Some(Data::Bool(true))
    );
    if !is_first {
        return;
    }

    println!("FirstBoot: running post-enum driver install...");
    if let Err(e) = install_prepacked_drivers() {
        println!("FirstBoot: install_prepacked_drivers failed: {:?}", e);
        return;
    }

    if let Err(e) = PNP_MANAGER.init_from_registry() {
        println!("FirstBoot: PNP incremental init failed: {:?}", e);
        return;
    }

    // Mark done
    if let Err(e) = reg::set_value("SYSTEM/SETUP", "FirstBoot", Data::Bool(false)) {
        println!("FirstBoot: failed to clear flag: {:?}", e);
    }
}
