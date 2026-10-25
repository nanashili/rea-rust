//! A hard Rust-heap budget for the private JavaScript worker.
//!
//! The worker is a separate process, so terminating it on an allocation that
//! would cross the budget is safe for the parent and leaves the parent able to
//! report a resource constraint.  This counts allocations routed through Rust's
//! global allocator.  Native allocations performed by external libraries are
//! outside this budget and remain protected by the worker process boundary.

#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

pub const MEMORY_BUDGET_EXIT_CODE: i32 = 122;

struct BudgetAllocator {
    used: AtomicUsize,
    limit: AtomicUsize,
}

impl BudgetAllocator {
    const fn new() -> Self {
        Self {
            used: AtomicUsize::new(0),
            limit: AtomicUsize::new(usize::MAX),
        }
    }

    fn reserve(&self, amount: usize) {
        if amount == 0 {
            return;
        }

        let result = self
            .used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                let next = used.checked_add(amount)?;
                (next <= self.limit.load(Ordering::Acquire)).then_some(next)
            });
        if result.is_err() {
            terminate_for_budget();
        }
    }

    fn release(&self, amount: usize) {
        if amount != 0 {
            self.used.fetch_sub(amount, Ordering::AcqRel);
        }
    }

    fn set_limit_mb(&self, max_heap_mb: Option<u64>) {
        let limit = max_heap_mb
            .map(|megabytes| {
                megabytes
                    .saturating_mul(1024)
                    .saturating_mul(1024)
                    .min(usize::MAX as u64) as usize
            })
            .unwrap_or(usize::MAX);
        self.limit.store(limit, Ordering::Release);

        if self.used.load(Ordering::Acquire) > limit {
            terminate_for_budget();
        }
    }
}

#[global_allocator]
static GLOBAL_ALLOCATOR: BudgetAllocator = BudgetAllocator::new();

pub fn set_worker_limit(max_heap_mb: Option<u64>) {
    GLOBAL_ALLOCATOR.set_limit_mb(max_heap_mb);
}

// SAFETY: all allocation methods delegate to `System`; the atomics only
// account for currently live Rust allocations and never expose allocator state.
unsafe impl GlobalAlloc for BudgetAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.size() == 0 {
            // SAFETY: zero-sized layouts are valid inputs to the system allocator.
            return unsafe { System.alloc(layout) };
        }

        self.reserve(layout.size());
        // SAFETY: the caller supplied a valid allocation layout.
        let pointer = unsafe { System.alloc(layout) };
        if pointer.is_null() {
            self.release(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: the pointer and layout pair came from this allocator.
        unsafe { System.dealloc(pointer, layout) };
        self.release(layout.size());
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let old_size = layout.size();
        if new_size > old_size {
            self.reserve(new_size - old_size);
        }

        // SAFETY: the pointer and old layout pair came from this allocator.
        let result = unsafe { System.realloc(pointer, layout, new_size) };
        if result.is_null() {
            if new_size > old_size {
                self.release(new_size - old_size);
            }
            return result;
        }

        if old_size > new_size {
            self.release(old_size - new_size);
        }
        result
    }
}

#[cold]
#[inline(never)]
fn terminate_for_budget() -> ! {
    #[cfg(unix)]
    // SAFETY: `_exit` terminates this private worker without running parent
    // destructors after the allocator budget has been exceeded.
    unsafe {
        libc::_exit(MEMORY_BUDGET_EXIT_CODE);
    }

    #[cfg(windows)]
    // SAFETY: `ExitProcess` terminates this private worker after its budget
    // has been exceeded and does not access Rust-managed memory.
    unsafe {
        windows_sys::Win32::System::Threading::ExitProcess(MEMORY_BUDGET_EXIT_CODE as u32);
    }

    #[cfg(not(any(unix, windows)))]
    std::process::abort();
}
