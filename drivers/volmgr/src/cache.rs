use alloc::sync::Arc;
use kernel_api::util::random_number;
use schnellru::{LruMap, Unlimited};

pub use crate::cache_core::VolumeCache;
pub use crate::cache_traits::{
    CacheConfig, CacheError, CacheStats, VolumeCacheBackend, VolumeCacheOps,
};

pub trait CacheIndex<V>: Send {
    fn len(&self) -> usize;
    fn get(&mut self, key: &u64) -> Option<&mut V>;
    fn peek(&self, key: &u64) -> Option<&V>;
    fn insert(&mut self, key: u64, value: V) -> bool;
    fn remove(&mut self, key: &u64) -> Option<V>;
    fn pop_oldest(&mut self) -> Option<(u64, V)>;
    fn for_each<FN>(&self, f: FN)
    where
        FN: FnMut(u64, &V);

    /// Visit up to `limit` entries starting at logical position `start`.
    /// Returns the number of entries walked (<= limit). Ordering follows the
    /// underlying index iteration order.
    fn for_each_chunk<FN>(&self, start: usize, limit: usize, f: FN) -> usize
    where
        FN: FnMut(u64, &V);
}

pub trait CacheIndexFactory<V>: Clone + Send + Sync + 'static {
    type Index: CacheIndex<V>;

    fn build(&self, target_capacity: usize) -> Self::Index;
}

#[derive(Clone, Copy, Default)]
pub struct DefaultIndexFactory;

pub struct DefaultIndex<V> {
    inner: LruMap<u64, V, Unlimited>,
}

impl<V> DefaultIndex<V> {
    #[inline]
    pub fn new() -> Self {
        let seed = [
            random_number(),
            random_number(),
            random_number(),
            random_number(),
        ];
        Self {
            inner: LruMap::with_seed(Unlimited, seed),
        }
    }
}

impl<V> Default for DefaultIndex<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V> CacheIndex<V> for DefaultIndex<V>
where
    V: Send,
{
    #[inline]
    fn len(&self) -> usize {
        self.inner.len()
    }

    #[inline]
    fn get(&mut self, key: &u64) -> Option<&mut V> {
        self.inner.get(key)
    }

    #[inline]
    fn peek(&self, key: &u64) -> Option<&V> {
        self.inner.peek(key)
    }

    #[inline]
    fn insert(&mut self, key: u64, value: V) -> bool {
        self.inner.insert(key, value)
    }

    #[inline]
    fn remove(&mut self, key: &u64) -> Option<V> {
        self.inner.remove(key)
    }

    #[inline]
    fn pop_oldest(&mut self) -> Option<(u64, V)> {
        self.inner.pop_oldest()
    }

    #[inline]
    fn for_each<FN>(&self, mut f: FN)
    where
        FN: FnMut(u64, &V),
    {
        for (k, v) in self.inner.iter() {
            f(*k, v);
        }
    }

    #[inline]
    fn for_each_chunk<FN>(&self, start: usize, limit: usize, mut f: FN) -> usize
    where
        FN: FnMut(u64, &V),
    {
        let mut walked = 0usize;
        for (idx, (k, v)) in self.inner.iter().enumerate() {
            if idx < start {
                continue;
            }
            if walked >= limit {
                break;
            }
            walked += 1;
            f(*k, v);
        }
        walked
    }
}

impl<V> CacheIndexFactory<V> for DefaultIndexFactory
where
    V: Send + 'static,
{
    type Index = DefaultIndex<V>;

    #[inline]
    fn build(&self, _target_capacity: usize) -> Self::Index {
        DefaultIndex::new()
    }
}

pub type DefaultVolumeCache<B, const BLOCK_SIZE: usize> =
    VolumeCache<B, BLOCK_SIZE, DefaultIndexFactory>;

impl<B, const BLOCK_SIZE: usize> DefaultVolumeCache<B, BLOCK_SIZE>
where
    B: VolumeCacheBackend,
{
    pub fn new_default(backend: Arc<B>, cfg: CacheConfig) -> Result<Self, CacheError<B::Error>> {
        Self::new_with_index(backend, cfg, DefaultIndexFactory)
    }
}
