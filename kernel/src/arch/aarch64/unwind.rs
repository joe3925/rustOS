use kernel_types::memory::Module;

use crate::platform::UnwindPlatform;
use crate::profiling::backtrace::{StackBounds, UnwindStart, UnwindStep};

use super::platform::Aarch64Platform;
use super::scheduling::TaskContext;

pub struct UnwindContext;

impl UnwindPlatform for Aarch64Platform {
    type UnwindContext = UnwindContext;

    fn begin_current_unwind() -> UnwindStart<Self::UnwindContext> { todo!() }
    fn begin_unwind(_state: &TaskContext) -> UnwindStart<Self::UnwindContext> { todo!() }
    fn unwind_next(_context: &mut Self::UnwindContext, _module: Option<&Module>, _stack_bounds: StackBounds) -> UnwindStep { todo!() }
}
