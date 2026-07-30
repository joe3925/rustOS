use core::sync::atomic::Ordering;

use kernel_types::arch::VirtAddr;

use crate::executable::program::PROGRAM_MANAGER;
use crate::platform::{ActivePlatform, UnwindPlatform};
use crate::scheduling::scheduler::SCHEDULER;
use crate::scheduling::state::State;
use crate::scheduling::task::TaskRef;

pub const MAX_BACKTRACE_DEPTH: usize = 64;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BacktraceFrame {
    ip: VirtAddr,
}

impl BacktraceFrame {
    pub const fn instruction_pointer(self) -> VirtAddr {
        self.ip
    }
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct BacktraceStatus: u16 {
        const TRUNCATED = 1 << 0;
        const NO_UNWIND_INFO = 1 << 1;
        const BAD_STACK_READ = 1 << 2;
        const BAD_UNWIND_INFO = 1 << 3;
        const UNSUPPORTED_OPERATION = 1 << 4;
        const LEAF_FALLBACK = 1 << 5;
        const PE_UNWIND = 1 << 6;
        const UNKNOWN_FRAME = 1 << 7;
        const STACK_BOUNDS_MISSING = 1 << 8;
        const MODULE_LOOKUP_UNAVAILABLE = 1 << 9;
    }
}

#[derive(Clone, Copy, Debug)]
pub struct StackBounds {
    pub low: VirtAddr,
    pub high: VirtAddr,
}

pub struct UnwindStart<C> {
    pub context: C,
    pub pc: VirtAddr,
}

pub struct UnwindStep {
    pub pc: Option<VirtAddr>,
    pub status: BacktraceStatus,
}

#[derive(Clone, Copy)]
pub struct Backtrace {
    frames: [BacktraceFrame; MAX_BACKTRACE_DEPTH],
    depth: u8,
    status: BacktraceStatus,
    stack_bounds: Option<StackBounds>,
}

impl core::fmt::Debug for Backtrace {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Backtrace")
            .field("frames", &self.frames())
            .field("depth", &self.depth)
            .field("status", &self.status)
            .field("stack_bounds", &self.stack_bounds)
            .finish()
    }
}

impl Backtrace {
    pub fn capture() -> Self {
        let task = SCHEDULER.get_current_task(crate::platform::current_cpu_id());
        let start = <ActivePlatform as UnwindPlatform>::begin_current_unwind();
        Self::from_start(start, task.as_deref(), MAX_BACKTRACE_DEPTH)
    }

    pub fn from_state(state: &State, task: Option<&TaskRef>) -> Self {
        Self::from_state_limited(state, task, MAX_BACKTRACE_DEPTH)
    }

    pub fn from_state_limited(state: &State, task: Option<&TaskRef>, max_depth: usize) -> Self {
        let start = <ActivePlatform as UnwindPlatform>::begin_unwind(state);
        Self::from_start(start, task, max_depth)
    }

    fn from_start(
        start: UnwindStart<<ActivePlatform as UnwindPlatform>::UnwindContext>,
        task: Option<&TaskRef>,
        max_depth: usize,
    ) -> Self {
        let stack_bounds = task.and_then(stack_bounds_for_task);
        let mut trace = Self {
            frames: [BacktraceFrame::default(); MAX_BACKTRACE_DEPTH],
            depth: 0,
            status: BacktraceStatus::empty(),
            stack_bounds,
        };

        let max_depth = max_depth.clamp(1, MAX_BACKTRACE_DEPTH);
        let mut context = start.context;
        trace.push(start.pc);

        let Some(bounds) = stack_bounds else {
            trace.status |= BacktraceStatus::STACK_BOUNDS_MISSING;
            return trace;
        };

        while trace.frames().len() < max_depth {
            let current_pc = trace.frames[trace.depth as usize - 1].ip;
            let pid = task
                .and_then(|task| task.inner.try_read().map(|inner| inner.parent_pid))
                .unwrap_or(0);
            let program = PROGRAM_MANAGER.get(pid);
            let module = program
                .as_ref()
                .and_then(|program| program.try_read())
                .and_then(|program| program.module_containing(current_pc));

            let step = match module.as_ref().and_then(|module| module.try_read()) {
                Some(module) => <ActivePlatform as UnwindPlatform>::unwind_next(
                    &mut context,
                    Some(&module),
                    bounds,
                ),
                None => {
                    if module.is_none() {
                        trace.status |= BacktraceStatus::UNKNOWN_FRAME;
                    } else {
                        trace.status |= BacktraceStatus::MODULE_LOOKUP_UNAVAILABLE;
                    }
                    <ActivePlatform as UnwindPlatform>::unwind_next(&mut context, None, bounds)
                }
            };

            trace.status |= step.status;
            let Some(pc) = step.pc else {
                break;
            };
            trace.push(pc);

            if step.status.intersects(
                BacktraceStatus::BAD_STACK_READ
                    | BacktraceStatus::BAD_UNWIND_INFO
                    | BacktraceStatus::UNSUPPORTED_OPERATION,
            ) {
                break;
            }
        }

        if trace.frames().len() == max_depth {
            trace.status |= BacktraceStatus::TRUNCATED;
        }

        trace
    }

    pub fn frames(&self) -> &[BacktraceFrame] {
        &self.frames[..self.depth as usize]
    }

    pub fn iter(&self) -> core::slice::Iter<'_, BacktraceFrame> {
        self.frames().iter()
    }

    pub const fn status(&self) -> BacktraceStatus {
        self.status
    }

    pub const fn stack_bounds(&self) -> Option<StackBounds> {
        self.stack_bounds
    }

    fn push(&mut self, ip: VirtAddr) {
        if self.depth as usize == MAX_BACKTRACE_DEPTH {
            self.status |= BacktraceStatus::TRUNCATED;
            return;
        }

        self.frames[self.depth as usize] = BacktraceFrame { ip };
        self.depth += 1;
    }
}

impl<'a> IntoIterator for &'a Backtrace {
    type Item = &'a BacktraceFrame;
    type IntoIter = core::slice::Iter<'a, BacktraceFrame>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

fn stack_bounds_for_task(task: &TaskRef) -> Option<StackBounds> {
    let high = task.stack_start.load(Ordering::Acquire);
    let size = task.stack_size.load(Ordering::Acquire);
    let low = high.checked_sub(size)?;

    (high != 0 && size != 0).then_some(StackBounds {
        low: VirtAddr::new(low),
        high: VirtAddr::new(high),
    })
}
