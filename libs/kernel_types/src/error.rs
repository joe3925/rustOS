use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::{self, Display, Write};

use crate::dma::IoBufferError;

pub const MAX_ERROR_BACKTRACE_DEPTH: usize = 64;

#[cfg(not(test))]
unsafe extern "C" {
    // TODO: Replace this kernel linker seam with a cleaner shared diagnostic-resolution boundary.
    fn kernel_resolve_error_context_module(instruction_pointer: usize) -> Option<String>;
}

#[repr(C)]
#[derive(Clone)]
pub struct KernelError {
    kind: ErrorKind,
    diagnostics: Option<Arc<ErrorDiagnostics>>,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    Driver(DriverErrorKind),
    File(FileErrorKind),
    Registry(RegistryErrorKind),
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DriverErrorKind {
    NotImplemented,
    InvalidParameter,
    InsufficientResources,
    NoSuchDevice,
    NoSuchFile,
    DeviceNotReady,
    Unsuccessful,
    DeviceError,
    Timeout,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileErrorKind {
    AlreadyExists,
    PathNotFound,
    UnknownFailure,
    NoBuffer,
    BufferError(IoBufferError),
    FilesystemError,
    NotFat,
    DriveNotFound,
    IncompatibleFlags,
    CorruptFilesystem,
    InternalError,
    BadPath,
    AccessDenied,
    NoSpace,
    FileTooLarge,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryErrorKind {
    KeyAlreadyExists,
    KeyNotFound,
    ValueNotFound,
    PersistenceFailed,
    EncodingFailed,
    CorruptRegistry,
}

#[repr(C)]
#[derive(Debug)]
pub struct ErrorDiagnostics {
    message: Option<String>,
    message_location: Option<ErrorLocation>,
    contexts: Vec<ErrorContext>,
    related: Vec<RelatedError>,
    backtrace: Option<ErrorBacktrace>,
}

#[repr(C)]
#[derive(Clone, Debug)]
pub struct ErrorLocation {
    module: Option<String>,
    file: String,
    line: u32,
    column: u32,
    instruction_pointer: usize,
}

#[repr(C)]
#[derive(Clone, Debug)]
pub struct ErrorContext {
    message: String,
    module: Option<String>,
    file: String,
    line: u32,
    column: u32,
    instruction_pointer: usize,
}

#[repr(C)]
#[derive(Clone, Debug)]
pub struct RelatedError {
    relationship: String,
    error: KernelError,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ErrorBacktrace {
    frames: [usize; MAX_ERROR_BACKTRACE_DEPTH],
    depth: u8,
    status: BacktraceStatus,
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BacktraceStatus(u16);

impl BacktraceStatus {
    pub const TRUNCATED: Self = Self(1 << 0);
    pub const NO_UNWIND_INFO: Self = Self(1 << 1);
    pub const BAD_STACK_READ: Self = Self(1 << 2);
    pub const BAD_UNWIND_INFO: Self = Self(1 << 3);
    pub const UNSUPPORTED_OPERATION: Self = Self(1 << 4);
    pub const LEAF_FALLBACK: Self = Self(1 << 5);
    pub const UNKNOWN_FRAME: Self = Self(1 << 6);
    pub const STACK_BOUNDS_MISSING: Self = Self(1 << 7);
    pub const MODULE_LOOKUP_UNAVAILABLE: Self = Self(1 << 8);

    pub const fn from_bits(bits: u16) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u16 {
        self.0
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl Display for BacktraceStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 == 0 {
            return f.write_str("complete");
        }

        let mut first = true;
        for (flag, name) in [
            (Self::TRUNCATED, "truncated"),
            (Self::NO_UNWIND_INFO, "no unwind info"),
            (Self::BAD_STACK_READ, "bad stack read"),
            (Self::BAD_UNWIND_INFO, "bad unwind info"),
            (Self::UNSUPPORTED_OPERATION, "unsupported operation"),
            (Self::LEAF_FALLBACK, "leaf fallback"),
            (Self::UNKNOWN_FRAME, "unknown frame"),
            (Self::STACK_BOUNDS_MISSING, "stack bounds missing"),
            (Self::MODULE_LOOKUP_UNAVAILABLE, "module lookup unavailable"),
        ] {
            if self.contains(flag) {
                if !first {
                    f.write_str(", ")?;
                }
                f.write_str(name)?;
                first = false;
            }
        }

        let known_bits = Self::TRUNCATED.0
            | Self::NO_UNWIND_INFO.0
            | Self::BAD_STACK_READ.0
            | Self::BAD_UNWIND_INFO.0
            | Self::UNSUPPORTED_OPERATION.0
            | Self::LEAF_FALLBACK.0
            | Self::UNKNOWN_FRAME.0
            | Self::STACK_BOUNDS_MISSING.0
            | Self::MODULE_LOOKUP_UNAVAILABLE.0;
        let unknown_bits = self.0 & !known_bits;
        if unknown_bits != 0 {
            if !first {
                f.write_str(", ")?;
            }
            write!(f, "unknown flags {unknown_bits:#x}")?;
        }
        Ok(())
    }
}

impl ErrorBacktrace {
    pub const fn empty() -> Self {
        Self {
            frames: [0; MAX_ERROR_BACKTRACE_DEPTH],
            depth: 0,
            status: BacktraceStatus(0),
        }
    }

    pub fn from_frames(frames: &[usize], status: BacktraceStatus) -> Self {
        let mut trace = Self::empty();
        let depth = frames.len().min(MAX_ERROR_BACKTRACE_DEPTH);
        trace.frames[..depth].copy_from_slice(&frames[..depth]);
        trace.depth = depth as u8;
        trace.status = status;
        if frames.len() > MAX_ERROR_BACKTRACE_DEPTH {
            trace.status.0 |= BacktraceStatus::TRUNCATED.0;
        }
        trace
    }

    pub fn frames(&self) -> &[usize] {
        &self.frames[..self.depth as usize]
    }

    pub const fn depth(&self) -> usize {
        self.depth as usize
    }

    pub const fn status(&self) -> BacktraceStatus {
        self.status
    }
}

impl KernelError {
    #[track_caller]
    pub fn from_parts(
        kind: ErrorKind,
        message: Option<fmt::Arguments<'_>>,
        backtrace: Option<ErrorBacktrace>,
    ) -> Self {
        let (message, message_location) = match message {
            Some(message) => match (
                try_format(message),
                try_capture_error_location(core::panic::Location::caller()),
            ) {
                (Some(message), Some(location)) => (Some(message), Some(location)),
                _ => {
                    return Self {
                        kind,
                        diagnostics: None,
                    };
                }
            },
            None => (None, None),
        };
        let diagnostics = ErrorDiagnostics {
            message,
            message_location,
            contexts: Vec::new(),
            related: Vec::new(),
            backtrace,
        };

        Self {
            kind,
            diagnostics: Arc::try_new(diagnostics).ok(),
        }
    }

    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub fn message(&self) -> Option<&str> {
        self.diagnostics
            .as_deref()
            .and_then(|diagnostics| diagnostics.message.as_deref())
    }

    pub fn message_location(&self) -> Option<&ErrorLocation> {
        self.diagnostics
            .as_deref()
            .and_then(|diagnostics| diagnostics.message_location.as_ref())
    }

    pub fn contexts(&self) -> &[ErrorContext] {
        self.diagnostics
            .as_deref()
            .map_or(&[], |diagnostics| diagnostics.contexts.as_slice())
    }

    pub fn backtrace(&self) -> Option<&ErrorBacktrace> {
        self.diagnostics
            .as_deref()
            .and_then(|diagnostics| diagnostics.backtrace.as_ref())
    }

    pub fn related_errors(&self) -> &[RelatedError] {
        self.diagnostics
            .as_deref()
            .map_or(&[], |diagnostics| diagnostics.related.as_slice())
    }

    #[track_caller]
    pub fn with_context<C>(self, context: C) -> Self
    where
        C: Display,
    {
        self.with_context_at(context, core::panic::Location::caller())
    }

    fn with_context_at<C>(
        mut self,
        context: C,
        location: &'static core::panic::Location<'static>,
    ) -> Self
    where
        C: Display,
    {
        let instruction_pointer = capture_instruction_pointer();
        let Some(message) = try_format(format_args!("{context}")) else {
            self.diagnostics = None;
            return self;
        };
        let Some(file) = try_clone_str(location.file()) else {
            self.diagnostics = None;
            return self;
        };
        let module = try_resolve_context_module(instruction_pointer);
        let context = ErrorContext {
            message,
            module,
            file,
            line: location.line(),
            column: location.column(),
            instruction_pointer,
        };

        if self.diagnostics.is_none() {
            let diagnostics = ErrorDiagnostics {
                message: None,
                message_location: None,
                contexts: Vec::new(),
                related: Vec::new(),
                backtrace: None,
            };
            self.diagnostics = Arc::try_new(diagnostics).ok();
            if self.diagnostics.is_none() {
                return self;
            }
        }

        let Some(diagnostics) = self.diagnostics.as_mut() else {
            return self;
        };

        if Arc::get_mut(diagnostics).is_none() {
            let Some(cloned) = try_clone_diagnostics(diagnostics) else {
                self.diagnostics = None;
                return self;
            };
            let Ok(cloned) = Arc::try_new(cloned) else {
                self.diagnostics = None;
                return self;
            };
            *diagnostics = cloned;
        }

        let diagnostics = Arc::get_mut(diagnostics).expect("diagnostics must be uniquely owned");
        if diagnostics.contexts.try_reserve(1).is_err() {
            self.diagnostics = None;
            return self;
        }
        diagnostics.contexts.push(context);
        self
    }

    pub fn with_related_error<C>(mut self, relationship: C, related_error: KernelError) -> Self
    where
        C: Display,
    {
        let Some(relationship) = try_format(format_args!("{relationship}")) else {
            self.diagnostics = None;
            return self;
        };

        if self.diagnostics.is_none() {
            let diagnostics = ErrorDiagnostics {
                message: None,
                message_location: None,
                contexts: Vec::new(),
                related: Vec::new(),
                backtrace: None,
            };
            self.diagnostics = Arc::try_new(diagnostics).ok();
            if self.diagnostics.is_none() {
                return self;
            }
        }

        let Some(diagnostics) = self.diagnostics.as_mut() else {
            return self;
        };

        if Arc::get_mut(diagnostics).is_none() {
            let Some(cloned) = try_clone_diagnostics(diagnostics) else {
                self.diagnostics = None;
                return self;
            };
            let Ok(cloned) = Arc::try_new(cloned) else {
                self.diagnostics = None;
                return self;
            };
            *diagnostics = cloned;
        }

        let diagnostics = Arc::get_mut(diagnostics).expect("diagnostics must be uniquely owned");
        if diagnostics.related.try_reserve(1).is_err() {
            self.diagnostics = None;
            return self;
        }
        diagnostics.related.push(RelatedError {
            relationship,
            error: related_error,
        });
        self
    }
}

impl RelatedError {
    pub fn relationship(&self) -> &str {
        &self.relationship
    }

    pub fn error(&self) -> &KernelError {
        &self.error
    }
}

impl ErrorContext {
    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn module(&self) -> Option<&str> {
        self.module.as_deref()
    }

    pub fn file(&self) -> &str {
        &self.file
    }

    pub const fn line(&self) -> u32 {
        self.line
    }

    pub const fn column(&self) -> u32 {
        self.column
    }

    pub const fn instruction_pointer(&self) -> usize {
        self.instruction_pointer
    }
}

impl ErrorLocation {
    pub fn module(&self) -> Option<&str> {
        self.module.as_deref()
    }

    pub fn file(&self) -> &str {
        &self.file
    }

    pub const fn line(&self) -> u32 {
        self.line
    }

    pub const fn column(&self) -> u32 {
        self.column
    }

    pub const fn instruction_pointer(&self) -> usize {
        self.instruction_pointer
    }
}

impl PartialEq for KernelError {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind
    }
}

impl Eq for KernelError {}

impl Display for KernelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind)?;
        if let Some(message) = self.message() {
            write!(f, "\n\nMessage:\n  ")?;
            if let Some(location) = self.message_location() {
                write_error_location(f, location)?;
            }
            write_indented(f, message, "  ")?;
        }

        if !self.contexts().is_empty() {
            write!(f, "\n\nContext:")?;
            for (index, context) in self.contexts().iter().rev().enumerate() {
                write!(f, "\n  {:>2}. ", index + 1)?;
                write_context_location(f, context)?;
                write_indented(f, context.message(), "      ")?;
            }
        }

        if !self.related_errors().is_empty() {
            write!(f, "\n\nRelated errors:")?;
            for (index, related) in self.related_errors().iter().enumerate() {
                write!(
                    f,
                    "\n  {:>2}. {}:\n      ",
                    index + 1,
                    related.relationship()
                )?;
                related.error().fmt_summary(f, "      ")?;
            }
        }

        if let Some(backtrace) = self.backtrace() {
            write!(
                f,
                "\n\nOrigin backtrace ({} frames; {}):",
                backtrace.depth(),
                backtrace.status()
            )?;
            for (index, frame) in backtrace.frames().iter().enumerate() {
                write!(f, "\n  {index:>2}: {frame:#018x}")?;
            }
        }
        Ok(())
    }
}

impl fmt::Debug for KernelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl KernelError {
    fn fmt_summary(
        &self,
        formatter: &mut fmt::Formatter<'_>,
        continuation_indent: &str,
    ) -> fmt::Result {
        write!(formatter, "{}", self.kind)?;
        if let Some(message) = self.message() {
            write!(formatter, "\n{continuation_indent}Message: ")?;
            if let Some(location) = self.message_location() {
                write_error_location(formatter, location)?;
            }
            write_indented(formatter, message, continuation_indent)?;
        }
        if !self.contexts().is_empty() {
            write!(formatter, "\n{continuation_indent}Context:")?;
            for (index, context) in self.contexts().iter().rev().enumerate() {
                write!(formatter, "\n{continuation_indent}  {:>2}. ", index + 1)?;
                write_context_location(formatter, context)?;
                write_indented(formatter, context.message(), continuation_indent)?;
            }
        }
        if let Some(backtrace) = self.backtrace() {
            write!(
                formatter,
                "\n{continuation_indent}[origin backtrace retained: {} frames; {}]",
                backtrace.depth(),
                backtrace.status()
            )?;
        }
        Ok(())
    }
}

impl Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Driver(kind) => write!(f, "driver error: {kind:?}"),
            Self::File(kind) => write!(f, "file error: {kind:?}"),
            Self::Registry(kind) => write!(f, "registry error: {kind:?}"),
        }
    }
}

impl From<DriverErrorKind> for ErrorKind {
    fn from(kind: DriverErrorKind) -> Self {
        Self::Driver(kind)
    }
}

impl From<FileErrorKind> for ErrorKind {
    fn from(kind: FileErrorKind) -> Self {
        Self::File(kind)
    }
}

impl From<RegistryErrorKind> for ErrorKind {
    fn from(kind: RegistryErrorKind) -> Self {
        Self::Registry(kind)
    }
}

pub trait ResultErrorContext<T> {
    #[track_caller]
    fn with_context<C, F>(self, context: F) -> Result<T, KernelError>
    where
        C: Display,
        F: FnOnce() -> C;
}

impl<T> ResultErrorContext<T> for Result<T, KernelError> {
    #[track_caller]
    fn with_context<C, F>(self, context: F) -> Result<T, KernelError>
    where
        C: Display,
        F: FnOnce() -> C,
    {
        let location = core::panic::Location::caller();
        self.map_err(|error| error.with_context_at(context(), location))
    }
}

fn try_clone_diagnostics(diagnostics: &ErrorDiagnostics) -> Option<ErrorDiagnostics> {
    let message = match diagnostics.message.as_deref() {
        Some(message) => Some(try_clone_str(message)?),
        None => None,
    };
    let mut contexts = Vec::new();
    contexts
        .try_reserve_exact(diagnostics.contexts.len())
        .ok()?;
    for context in &diagnostics.contexts {
        contexts.push(ErrorContext {
            message: try_clone_str(&context.message)?,
            module: match context.module.as_deref() {
                Some(module) => Some(try_clone_str(module)?),
                None => None,
            },
            file: try_clone_str(&context.file)?,
            line: context.line,
            column: context.column,
            instruction_pointer: context.instruction_pointer,
        });
    }
    let mut related = Vec::new();
    related.try_reserve_exact(diagnostics.related.len()).ok()?;
    for related_error in &diagnostics.related {
        related.push(RelatedError {
            relationship: try_clone_str(&related_error.relationship)?,
            error: related_error.error.clone(),
        });
    }
    Some(ErrorDiagnostics {
        message,
        message_location: match diagnostics.message_location.as_ref() {
            Some(location) => Some(try_clone_error_location(location)?),
            None => None,
        },
        contexts,
        related,
        backtrace: diagnostics.backtrace,
    })
}

fn try_clone_str(value: &str) -> Option<String> {
    let mut output = String::new();
    output.try_reserve_exact(value.len()).ok()?;
    output.push_str(value);
    Some(output)
}

fn try_format(arguments: fmt::Arguments<'_>) -> Option<String> {
    struct FallibleString {
        output: String,
        allocation_failed: bool,
    }

    impl Write for FallibleString {
        fn write_str(&mut self, value: &str) -> fmt::Result {
            if self.output.try_reserve(value.len()).is_err() {
                self.allocation_failed = true;
                return Err(fmt::Error);
            }
            self.output.push_str(value);
            Ok(())
        }
    }

    let mut writer = FallibleString {
        output: String::new(),
        allocation_failed: false,
    };
    if fmt::write(&mut writer, arguments).is_err() || writer.allocation_failed {
        None
    } else {
        Some(writer.output)
    }
}

fn write_indented(
    formatter: &mut fmt::Formatter<'_>,
    value: &str,
    continuation_indent: &str,
) -> fmt::Result {
    let mut lines = value.split('\n');
    if let Some(first) = lines.next() {
        formatter.write_str(first)?;
    }
    for line in lines {
        formatter.write_str("\n")?;
        formatter.write_str(continuation_indent)?;
        formatter.write_str(line)?;
    }
    Ok(())
}

fn write_context_location(
    formatter: &mut fmt::Formatter<'_>,
    context: &ErrorContext,
) -> fmt::Result {
    formatter.write_str("[")?;
    if let Some(module) = context.module() {
        write!(formatter, "{module}!")?;
    }
    write!(
        formatter,
        "{}:{}:{}] ",
        context.file(),
        context.line(),
        context.column()
    )
}

fn write_error_location(
    formatter: &mut fmt::Formatter<'_>,
    location: &ErrorLocation,
) -> fmt::Result {
    formatter.write_str("[")?;
    if let Some(module) = location.module() {
        write!(formatter, "{module}!")?;
    }
    write!(
        formatter,
        "{}:{}:{}] ",
        location.file(),
        location.line(),
        location.column()
    )
}

fn try_capture_error_location(
    location: &'static core::panic::Location<'static>,
) -> Option<ErrorLocation> {
    let instruction_pointer = capture_instruction_pointer();
    Some(ErrorLocation {
        module: try_resolve_context_module(instruction_pointer),
        file: try_clone_str(location.file())?,
        line: location.line(),
        column: location.column(),
        instruction_pointer,
    })
}

fn try_clone_error_location(location: &ErrorLocation) -> Option<ErrorLocation> {
    Some(ErrorLocation {
        module: match location.module.as_deref() {
            Some(module) => Some(try_clone_str(module)?),
            None => None,
        },
        file: try_clone_str(&location.file)?,
        line: location.line,
        column: location.column,
        instruction_pointer: location.instruction_pointer,
    })
}

#[inline(always)]
fn capture_instruction_pointer() -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        let instruction_pointer: usize;
        unsafe {
            core::arch::asm!(
                "lea {}, [rip]",
                out(reg) instruction_pointer,
                options(nomem, nostack, preserves_flags),
            );
        }
        instruction_pointer
    }

    #[cfg(target_arch = "aarch64")]
    {
        let instruction_pointer: usize;
        unsafe {
            core::arch::asm!(
                "adr {}, .",
                out(reg) instruction_pointer,
                options(nomem, nostack, preserves_flags),
            );
        }
        instruction_pointer
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        0
    }
}

#[cfg(not(test))]
fn try_resolve_context_module(instruction_pointer: usize) -> Option<String> {
    unsafe { kernel_resolve_error_context_module(instruction_pointer) }
}

#[cfg(test)]
fn try_resolve_context_module(_instruction_pointer: usize) -> Option<String> {
    None
}
