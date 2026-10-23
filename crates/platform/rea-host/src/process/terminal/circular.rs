//! Ring of buffer lines, ported from xterm.js `common/CircularList.ts`.
//!
//! Slots hold owned lines. xterm moves references and leaves stale duplicates
//! that every caller overwrites or drops past `length`, so moving (`take`)
//! preserves its observable behavior without sharing. Event
//! emitters are omitted: in a headless terminal without markers or links
//! they only adjust marker bookkeeping that no observed field reads.

use super::line::BufferLine;

#[derive(Clone, Debug)]
pub struct CircularList {
    array: Vec<Option<BufferLine>>,
    start: usize,
    length: usize,
}

impl CircularList {
    pub fn new(max_length: usize) -> Self {
        Self {
            array: vec![None; max_length],
            start: 0,
            length: 0,
        }
    }

    pub fn max_length(&self) -> usize {
        self.array.len()
    }

    pub fn set_max_length(&mut self, new_max: usize) {
        if self.array.len() == new_max {
            return;
        }
        let mut array = vec![None; new_max];
        for (index, slot) in array.iter_mut().enumerate().take(new_max.min(self.length)) {
            let from = (self.start + index) % self.array.len();
            *slot = self.array[from].take();
        }
        self.array = array;
        self.start = 0;
    }

    pub fn len(&self) -> usize {
        self.length
    }

    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// xterm `length` setter: growing exposes empty slots.
    pub fn set_len(&mut self, new_length: usize) {
        if new_length > self.length {
            for index in self.length..new_length {
                if let Some(slot) = self.array.get_mut(index) {
                    *slot = None;
                }
            }
        }
        self.length = new_length;
    }

    fn cyclic(&self, index: usize) -> usize {
        (self.start + index) % self.array.len()
    }

    pub fn get(&self, index: usize) -> Option<&BufferLine> {
        if self.array.is_empty() {
            return None;
        }
        self.array[self.cyclic(index)].as_ref()
    }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut BufferLine> {
        if self.array.is_empty() {
            return None;
        }
        let slot = self.cyclic(index);
        self.array[slot].as_mut()
    }

    pub fn set(&mut self, index: usize, value: Option<BufferLine>) {
        let slot = self.cyclic(index);
        self.array[slot] = value;
    }

    /// Move a line out of its slot (the caller writes the slot back).
    pub fn take(&mut self, index: usize) -> Option<BufferLine> {
        if self.array.is_empty() {
            return None;
        }
        let slot = self.cyclic(index);
        self.array[slot].take()
    }

    pub fn push(&mut self, value: BufferLine) {
        let slot = self.cyclic(self.length);
        self.array[slot] = Some(value);
        if self.length == self.array.len() {
            self.start = (self.start + 1) % self.array.len();
        } else {
            self.length += 1;
        }
    }

    pub fn is_full(&self) -> bool {
        self.length == self.array.len()
    }

    /// xterm `recycle`: rotate a full ring and return the reused last slot.
    pub fn recycle(&mut self) -> Option<&mut BufferLine> {
        self.start = (self.start + 1) % self.array.len();
        let slot = self.cyclic(self.length - 1);
        self.array[slot].as_mut()
    }

    pub fn pop(&mut self) {
        self.length -= 1;
    }

    pub fn splice(&mut self, start: usize, delete_count: usize, items: Vec<BufferLine>) {
        if delete_count != 0 {
            let mut index = start;
            while index + delete_count < self.length {
                let from = self.cyclic(index + delete_count);
                let to = self.cyclic(index);
                self.array[to] = self.array[from].take();
                index += 1;
            }
            self.length -= delete_count;
        }
        let count = items.len();
        if count != 0 {
            let mut index = self.length;
            while index > start {
                index -= 1;
                let from = self.cyclic(index);
                let to = self.cyclic(index + count);
                self.array[to] = self.array[from].take();
            }
        }
        for (offset, item) in items.into_iter().enumerate() {
            let slot = self.cyclic(start + offset);
            self.array[slot] = Some(item);
        }
        if self.length + count > self.array.len() {
            let trim = self.length + count - self.array.len();
            self.start += trim;
            self.length = self.array.len();
        } else {
            self.length += count;
        }
    }

    pub fn trim_start(&mut self, count: usize) {
        let count = count.min(self.length);
        self.start += count;
        self.length -= count;
    }

    pub fn shift_elements(&mut self, start: usize, count: isize, offset: isize) {
        if count <= 0 {
            return;
        }
        let count = count as usize;
        if offset > 0 {
            let offset = offset as usize;
            for index in (0..count).rev() {
                let from = self.cyclic(start + index);
                let value = self.array[from].take();
                self.set(start + index + offset, value);
            }
            let end = start + count + offset;
            if end > self.length {
                self.length = end;
                while self.length > self.array.len() {
                    self.length -= 1;
                    self.start += 1;
                }
            }
        } else {
            let back = offset.unsigned_abs();
            for index in 0..count {
                let from = self.cyclic(start + index);
                let value = self.array[from].take();
                self.set(start + index - back, value);
            }
        }
    }
}
