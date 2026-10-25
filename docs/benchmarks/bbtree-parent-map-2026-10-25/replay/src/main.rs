use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::{BTreeMap, HashMap};
use std::hint::black_box;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

struct CountedAllocator;

unsafe impl GlobalAlloc for CountedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            let live = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(live, Ordering::Relaxed);
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            let live = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(live, Ordering::Relaxed);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }
}

#[global_allocator]
static ALLOCATOR: CountedAllocator = CountedAllocator;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Role {
    Primary,
    Synthesized,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Key {
    node: u32,
    role: Role,
}

impl From<u64> for Key {
    fn from(value: u64) -> Self {
        Self {
            node: (value >> 1) as u32,
            role: if value & 1 == 0 {
                Role::Primary
            } else {
                Role::Synthesized
            },
        }
    }
}

type Value = [u64; 8];

trait ParentTable: Default {
    fn insert(&mut self, key: u64, parent: u64);
    fn get(&self, key: u64) -> Option<&Value>;
}

macro_rules! table {
    ($kind:ty) => {
        impl ParentTable for $kind {
            fn insert(&mut self, key: u64, parent: u64) {
                self.insert(Key::from(key), [parent; 8]);
            }
            fn get(&self, key: u64) -> Option<&Value> {
                self.get(&Key::from(key))
            }
        }
    };
}

table!(HashMap<Key, Value>);
table!(rustc_hash::FxHashMap<Key, Value>);
table!(BTreeMap<Key, Value>);
table!(bbtree::unsync::BBTreeMap<Key, Value>);

impl ParentTable for bbtree::unsync::BBTreeMap<u64, Value> {
    fn insert(&mut self, key: u64, parent: u64) {
        self.insert(key, [parent; 8]);
    }
    fn get(&self, key: u64) -> Option<&Value> {
        self.get(&key)
    }
}

#[derive(Clone, Copy, Default)]
struct Slot {
    parent: Option<NonZeroU32>,
    retained: Option<NonZeroU32>,
}

#[derive(Default)]
struct CompactParents {
    primary: Vec<Slot>,
    synthesized: HashMap<u32, Slot>,
    values: Vec<Value>,
}

impl CompactParents {
    fn slot_mut(&mut self, key: Key) -> &mut Slot {
        if key.role == Role::Synthesized {
            self.synthesized.entry(key.node).or_default()
        } else {
            let index = key.node as usize;
            if index >= self.primary.len() {
                self.primary.resize(index + 1, Slot::default());
            }
            &mut self.primary[index]
        }
    }

    fn slot(&self, key: Key) -> Option<&Slot> {
        if key.role == Role::Synthesized {
            self.synthesized.get(&key.node)
        } else {
            self.primary.get(key.node as usize)
        }
    }
}

impl ParentTable for CompactParents {
    fn insert(&mut self, key: u64, parent: u64) {
        let parent_key = Key::from(parent);
        let retained = self.slot_mut(parent_key).retained;
        let index = match retained {
            Some(index) => index,
            None => {
                self.values.push([parent; 8]);
                let index = NonZeroU32::new(u32::try_from(self.values.len()).unwrap()).unwrap();
                self.slot_mut(parent_key).retained = Some(index);
                index
            }
        };
        self.slot_mut(Key::from(key)).parent = Some(index);
    }

    fn get(&self, key: u64) -> Option<&Value> {
        let index = self.slot(Key::from(key))?.parent?;
        self.values.get(index.get() as usize - 1)
    }
}

fn measure<T: ParentTable>(name: &str, inserts: &[(u64, u64)], queries: &[(u64, u64)]) {
    let baseline = LIVE.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);
    let mut map = T::default();
    let started = Instant::now();
    for &(key, parent) in inserts {
        map.insert(key, parent);
    }
    let build_ms = started.elapsed().as_secs_f64() * 1000.0;
    let retained_bytes = LIVE.load(Ordering::Relaxed) - baseline;
    let peak_bytes = PEAK.load(Ordering::Relaxed) - baseline;

    let mut checksum = 0u64;
    let started = Instant::now();
    for _ in 0..3 {
        for &(key, expected_parent) in queries {
            let value = black_box(map.get(black_box(key))).expect("parent present");
            assert_eq!(value[0], expected_parent, "exact parent identity");
            checksum = checksum.wrapping_add(black_box(value[0]));
        }
    }
    let lookup_ms = started.elapsed().as_secs_f64() * 1000.0;
    drop(map);
    assert_eq!(
        LIVE.load(Ordering::Relaxed),
        baseline,
        "table releases allocations"
    );
    println!(
        "{{\"map\":\"{name}\",\"edges\":{},\"lookups\":{},\"value_bytes\":{},\"build_ms\":{build_ms:.3},\"lookup_ms\":{lookup_ms:.3},\"retained_requested_bytes\":{retained_bytes},\"peak_requested_bytes\":{peak_bytes},\"checksum\":{checksum}}}",
        inserts.len(),
        queries.len() * 3,
        size_of::<Value>()
    );
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    let bytes = std::fs::read(&args[1])?;
    assert!(bytes.len().is_multiple_of(16));
    let inserts: Vec<_> = bytes
        .chunks_exact(16)
        .map(|record| {
            (
                u64::from_le_bytes(record[..8].try_into().unwrap()),
                u64::from_le_bytes(record[8..].try_into().unwrap()),
            )
        })
        .collect();
    drop(bytes);
    let mut queries = inserts.clone();
    let mut random = 0x524541u64;
    for index in (1..queries.len()).rev() {
        random ^= random << 13;
        random ^= random >> 7;
        random ^= random << 17;
        queries.swap(index, random as usize % (index + 1));
    }
    match args[2].as_str() {
        "hash" => measure::<HashMap<Key, Value>>("std_hash", &inserts, &queries),
        "fx" => measure::<rustc_hash::FxHashMap<Key, Value>>("fx_hash", &inserts, &queries),
        "btree" => measure::<BTreeMap<Key, Value>>("std_btree", &inserts, &queries),
        "bbtree" => measure::<bbtree::unsync::BBTreeMap<Key, Value>>("bbtree", &inserts, &queries),
        "bbpacked" => {
            measure::<bbtree::unsync::BBTreeMap<u64, Value>>("bbtree_packed", &inserts, &queries)
        }
        "compact" => measure::<CompactParents>("compact_parents", &inserts, &queries),
        other => panic!("unknown map: {other}"),
    }
    Ok(())
}
