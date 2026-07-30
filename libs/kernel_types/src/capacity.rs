//! Resource-independent capacity growth and shrink policies.
//!
//! Occupancy values are hints: concurrent users may make them stale as soon as
//! they are returned. Implementations must therefore validate resize requests.

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OccupancyHint {
    pub used: usize,
    pub capacity: usize,
    pub available: usize,
}

impl OccupancyHint {
    pub const fn new(used: usize, capacity: usize) -> Self {
        Self {
            used,
            capacity,
            available: capacity.saturating_sub(used),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResizeEvent {
    Inserted,
    Removed,
    CapacityReached,
    PolicyReplacement,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResizeContext {
    pub occupancy: OccupancyHint,
    pub in_interrupt_context: bool,
    pub event: ResizeEvent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResizeError {
    OutOfMemory,
    Contended,
    InvalidCapacity,
    MaximumCapacityReached,
    UnsafeContext,
}

/// A capacity-limited resource.
///
/// `try_grow(minimum_capacity)` takes an absolute target. Success guarantees
/// that the published capacity is at least the target and returns the resulting
/// capacity. Implementations may exceed the target to honor their allocation
/// granularity.
///
/// `try_shrink(requested_capacity)` is best effort and returns the number of
/// slots removed from published capacity. Zero is a successful result. The
/// resource may remain above the requested target when occupied slots,
/// granularity, or concurrent access prevent further shrinking.
pub trait Growable {
    fn occupancy_hint(&self) -> OccupancyHint;
    fn minimum_capacity(&self) -> usize;
    fn maximum_capacity(&self) -> Option<usize>;
    fn allocation_granularity(&self) -> usize;
    fn try_grow(&self, minimum_capacity: usize) -> Result<usize, ResizeError>;
    fn try_shrink(&self, requested_capacity: usize) -> Result<usize, ResizeError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyOutcome {
    NoChange,
    Resized,
    Reject,
    RetryLater,
    OutOfMemory,
    OwnerCannotContinue,
}

pub trait ResizePolicy<G: Growable + ?Sized> {
    fn on_insert(&self, resource: &G, context: ResizeContext) -> PolicyOutcome;
    fn on_remove(&self, resource: &G, context: ResizeContext) -> PolicyOutcome;
    fn on_capacity_reached(&self, resource: &G, context: ResizeContext) -> PolicyOutcome;
    fn on_policy_change(
        &self,
        resource: &G,
        context: ResizeContext,
        replacement: &ResizePolicyKind,
    ) -> PolicyOutcome;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinearResizePolicy {
    pub minimum_capacity: usize,
    pub grow_by: usize,
    pub shrink_by: usize,
    pub shrink_trigger_percent: u8,
    pub maximum_capacity: Option<usize>,
}

impl LinearResizePolicy {
    pub const fn new(
        minimum_capacity: usize,
        grow_by: usize,
        shrink_by: usize,
        shrink_trigger_percent: u8,
    ) -> Self {
        Self {
            minimum_capacity,
            grow_by,
            shrink_by,
            shrink_trigger_percent,
            maximum_capacity: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GeometricResizePolicy {
    pub minimum_capacity: usize,
    pub growth_factor: usize,
    pub shrink_trigger_percent: u8,
    pub shrink_target_percent: u8,
    pub maximum_capacity: Option<usize>,
}

impl GeometricResizePolicy {
    pub const fn new(
        minimum_capacity: usize,
        growth_factor: usize,
        shrink_trigger_percent: u8,
        shrink_target_percent: u8,
    ) -> Self {
        Self {
            minimum_capacity,
            growth_factor,
            shrink_trigger_percent,
            shrink_target_percent,
            maximum_capacity: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResizePolicyKind {
    Fixed,
    Linear(LinearResizePolicy),
    Geometric(GeometricResizePolicy),
}

impl Default for ResizePolicyKind {
    fn default() -> Self {
        Self::Geometric(GeometricResizePolicy::new(1, 2, 50, 75))
    }
}

impl ResizePolicyKind {
    pub fn validate(self) -> Result<Self, ResizeError> {
        match self {
            Self::Fixed => Ok(self),
            Self::Linear(policy)
                if policy.minimum_capacity != 0
                    && policy.grow_by != 0
                    && policy.shrink_by != 0
                    && (1..=100).contains(&policy.shrink_trigger_percent) =>
            {
                if policy
                    .maximum_capacity
                    .is_some_and(|maximum| maximum < policy.minimum_capacity)
                {
                    Err(ResizeError::InvalidCapacity)
                } else {
                    Ok(self)
                }
            }
            Self::Geometric(policy)
                if policy.minimum_capacity != 0
                    && policy.growth_factor >= 2
                    && (1..=100).contains(&policy.shrink_trigger_percent)
                    && (1..=100).contains(&policy.shrink_target_percent)
                    && policy.shrink_target_percent > policy.shrink_trigger_percent =>
            {
                if policy
                    .maximum_capacity
                    .is_some_and(|maximum| maximum < policy.minimum_capacity)
                {
                    Err(ResizeError::InvalidCapacity)
                } else {
                    Ok(self)
                }
            }
            _ => Err(ResizeError::InvalidCapacity),
        }
    }

    pub const fn maximum_capacity(self) -> Option<usize> {
        match self {
            Self::Fixed => None,
            Self::Linear(policy) => policy.maximum_capacity,
            Self::Geometric(policy) => policy.maximum_capacity,
        }
    }

    pub const fn minimum_capacity(self) -> usize {
        match self {
            Self::Fixed => 1,
            Self::Linear(policy) => policy.minimum_capacity,
            Self::Geometric(policy) => policy.minimum_capacity,
        }
    }

    fn map_resize(
        result: Result<usize, ResizeError>,
        changed_if: impl FnOnce(usize) -> bool,
    ) -> PolicyOutcome {
        match result {
            Ok(value) if changed_if(value) => PolicyOutcome::Resized,
            Ok(_) => PolicyOutcome::NoChange,
            Err(ResizeError::Contended | ResizeError::UnsafeContext) => PolicyOutcome::RetryLater,
            Err(ResizeError::MaximumCapacityReached) => PolicyOutcome::Reject,
            Err(ResizeError::OutOfMemory) => PolicyOutcome::OutOfMemory,
            Err(ResizeError::InvalidCapacity) => PolicyOutcome::Reject,
        }
    }

    fn should_shrink(occupancy: OccupancyHint, trigger: u8) -> bool {
        occupancy.capacity != 0
            && occupancy.used.saturating_mul(100)
                <= occupancy.capacity.saturating_mul(trigger as usize)
    }
}

impl<G: Growable + ?Sized> ResizePolicy<G> for ResizePolicyKind {
    fn on_insert(&self, _resource: &G, _context: ResizeContext) -> PolicyOutcome {
        PolicyOutcome::NoChange
    }

    fn on_remove(&self, resource: &G, context: ResizeContext) -> PolicyOutcome {
        if context.in_interrupt_context {
            return PolicyOutcome::RetryLater;
        }
        match *self {
            Self::Fixed => PolicyOutcome::NoChange,
            Self::Linear(policy) => {
                if !Self::should_shrink(context.occupancy, policy.shrink_trigger_percent) {
                    return PolicyOutcome::NoChange;
                }
                let target = context
                    .occupancy
                    .capacity
                    .saturating_sub(policy.shrink_by)
                    .max(policy.minimum_capacity)
                    .max(resource.minimum_capacity())
                    .max(context.occupancy.used);
                Self::map_resize(resource.try_shrink(target), |removed| removed != 0)
            }
            Self::Geometric(policy) => {
                if !Self::should_shrink(context.occupancy, policy.shrink_trigger_percent) {
                    return PolicyOutcome::NoChange;
                }
                let target = context
                    .occupancy
                    .used
                    .saturating_mul(100)
                    .div_ceil(policy.shrink_target_percent as usize)
                    .max(policy.minimum_capacity)
                    .max(resource.minimum_capacity());
                Self::map_resize(resource.try_shrink(target), |removed| removed != 0)
            }
        }
    }

    fn on_capacity_reached(&self, resource: &G, context: ResizeContext) -> PolicyOutcome {
        if context.in_interrupt_context {
            return PolicyOutcome::RetryLater;
        }
        let requested = match *self {
            Self::Fixed => return PolicyOutcome::Reject,
            Self::Linear(policy) => context.occupancy.capacity.checked_add(policy.grow_by),
            Self::Geometric(policy) => context.occupancy.capacity.checked_mul(policy.growth_factor),
        };
        let Some(mut requested) = requested else {
            return PolicyOutcome::Reject;
        };
        if let Some(maximum) = self.maximum_capacity().or(resource.maximum_capacity()) {
            if context.occupancy.capacity >= maximum {
                return PolicyOutcome::Reject;
            }
            requested = requested.min(maximum);
        }
        Self::map_resize(resource.try_grow(requested), |capacity| {
            capacity > context.occupancy.capacity
        })
    }

    fn on_policy_change(
        &self,
        _resource: &G,
        _context: ResizeContext,
        replacement: &ResizePolicyKind,
    ) -> PolicyOutcome {
        match replacement.validate() {
            Ok(_) => PolicyOutcome::NoChange,
            Err(_) => PolicyOutcome::Reject,
        }
    }
}
