use crate::platform::{DebugPlatform, DebugTransportPlatform};

use super::platform::Aarch64Platform;

impl DebugTransportPlatform for Aarch64Platform {
    fn init_debug_metadata_transport() {
        todo!()
    }
}

impl DebugPlatform for Aarch64Platform {
    fn breakpoint() {
        todo!()
    }

    fn fatal_reset() -> ! {
        todo!()
    }
}
