use kernel_api::util::random_number;
use schnellru::{LruMap, Unlimited};

pub trait CacheIndex<V>: Send {
    fn reserve_or_panic(&mut self, size: usize);
    fn len(&self) -> usize;
    fn get(&mut self, key: &u64) -> Option<&mut V>;
    fn peek(&self, key: &u64) -> Option<&V>;
    fn insert(&mut self, key: u64, value: V) -> bool;
    fn remove(&mut self, key: &u64) -> Option<V>;
    fn oldest_matching<FN>(&self, f: FN) -> Option<u64>
    where
        FN: FnMut(u64, &V) -> bool;
    fn for_each<FN>(&self, f: FN)
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
    fn reserve_or_panic(&mut self, size: usize) {
        self.inner.reserve_or_panic(size);
    }
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
    fn oldest_matching<FN>(&self, mut f: FN) -> Option<u64>
    where
        FN: FnMut(u64, &V) -> bool,
    {
        for (k, v) in self.inner.iter().rev() {
            if f(*k, v) {
                return Some(*k);
            }
        }
        None
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
