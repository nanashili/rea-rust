//! JVM `.class` identity used to disambiguate a `CAFEBABE` Java class file
//! from a Mach-O FAT container.
//!
//! Compatibility owner: `src/domain/apple/jvmClassFile.ts` (`isJvmClassFile`).
//! The FAT reader passes the complete file bytes here only for a 32-bit
//! big-endian FAT magic within the 16 MiB bound, matching the TS condition.

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn at_end(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn has(&self, length: usize) -> bool {
        self.offset <= self.bytes.len().wrapping_sub(length)
            && self.offset + length <= self.bytes.len()
    }

    fn u1(&mut self) -> Option<u32> {
        if !self.has(1) {
            return None;
        }
        let value = self.bytes[self.offset] as u32;
        self.offset += 1;
        Some(value)
    }

    fn u2(&mut self) -> Option<u32> {
        if !self.has(2) {
            return None;
        }
        let value =
            u16::from_be_bytes([self.bytes[self.offset], self.bytes[self.offset + 1]]) as u32;
        self.offset += 2;
        Some(value)
    }

    fn u4(&mut self) -> Option<u32> {
        if !self.has(4) {
            return None;
        }
        let value = u32::from_be_bytes([
            self.bytes[self.offset],
            self.bytes[self.offset + 1],
            self.bytes[self.offset + 2],
            self.bytes[self.offset + 3],
        ]);
        self.offset += 4;
        Some(value)
    }

    fn skip(&mut self, length: usize) -> bool {
        if !self.has(length) {
            return false;
        }
        self.offset += length;
        true
    }
}

struct ConstantPool {
    tags: Vec<Option<u32>>,
    first: Vec<Option<u32>>,
    second: Vec<Option<u32>>,
}

fn read_constant(cursor: &mut Cursor<'_>, tag: u32, index: usize, pool: &mut ConstantPool) -> bool {
    match tag {
        1 => {
            let Some(length) = cursor.u2() else {
                return false;
            };
            if !cursor.skip(length as usize) {
                return false;
            }
        }
        3 | 4 => {
            if cursor.u4().is_none() {
                return false;
            }
        }
        5 | 6 => {
            if index + 1 >= pool.tags.len() || !cursor.skip(8) {
                return false;
            }
        }
        7 | 8 | 16 | 19 | 20 => {
            pool.first[index] = cursor.u2();
            if pool.first[index].is_none() {
                return false;
            }
        }
        9 | 10 | 11 | 12 | 17 | 18 => {
            pool.first[index] = cursor.u2();
            pool.second[index] = cursor.u2();
            if pool.first[index].is_none() || pool.second[index].is_none() {
                return false;
            }
        }
        15 => {
            pool.first[index] = cursor.u1();
            pool.second[index] = cursor.u2();
            if pool.first[index].is_none() || pool.second[index].is_none() {
                return false;
            }
        }
        _ => return false,
    }
    pool.tags[index] = Some(tag);
    true
}

fn read_constant_pool(cursor: &mut Cursor<'_>, count: usize) -> Option<ConstantPool> {
    let mut pool = ConstantPool {
        tags: vec![None; count],
        first: vec![None; count],
        second: vec![None; count],
    };
    let mut index = 1;
    while index < count {
        let tag = cursor.u1()?;
        if !read_constant(cursor, tag, index, &mut pool) {
            return None;
        }
        if tag == 5 || tag == 6 {
            index += 1;
        }
        index += 1;
    }
    Some(pool)
}

fn pool_has_tag(pool: &ConstantPool, index: Option<u32>, tags: &[u32]) -> bool {
    match index {
        Some(index) if index > 0 && (index as usize) < pool.tags.len() => {
            tags.contains(&pool.tags[index as usize].unwrap_or(u32::MAX))
        }
        _ => false,
    }
}

fn valid_method_handle(
    pool: &ConstantPool,
    kind: Option<u32>,
    reference: Option<u32>,
    major: u32,
) -> bool {
    let (Some(kind), Some(_)) = (kind, reference) else {
        return false;
    };
    if kind < 1 || kind > 9 || major < 51 {
        return false;
    }
    if kind <= 4 {
        return pool_has_tag(pool, reference, &[9]);
    }
    if kind == 5 || kind == 8 {
        return pool_has_tag(pool, reference, &[10]);
    }
    if kind == 6 || kind == 7 {
        return if major >= 52 {
            pool_has_tag(pool, reference, &[10, 11])
        } else {
            pool_has_tag(pool, reference, &[10])
        };
    }
    pool_has_tag(pool, reference, &[11])
}

fn has_valid_pool_references(pool: &ConstantPool, major: u32) -> bool {
    for index in 1..pool.tags.len() {
        let tag = pool.tags[index];
        let first = pool.first[index];
        let second = pool.second[index];
        let tag_value = tag.unwrap_or(u32::MAX);
        if [7, 8, 16, 19, 20].contains(&tag_value) {
            if first.is_none() || !pool_has_tag(pool, first, &[1]) {
                return false;
            }
            if (tag_value == 16 && major < 51)
                || ((tag_value == 19 || tag_value == 20) && major < 53)
            {
                return false;
            }
        } else if [9, 10, 11].contains(&tag_value) {
            if first.is_none()
                || second.is_none()
                || !pool_has_tag(pool, first, &[7])
                || !pool_has_tag(pool, second, &[12])
            {
                return false;
            }
        } else if tag_value == 12 {
            if first.is_none()
                || second.is_none()
                || !pool_has_tag(pool, first, &[1])
                || !pool_has_tag(pool, second, &[1])
            {
                return false;
            }
        } else if tag_value == 15 {
            if !valid_method_handle(pool, first, second, major) {
                return false;
            }
        } else if tag_value == 17 || tag_value == 18 {
            if second.is_none()
                || !pool_has_tag(pool, second, &[12])
                || major < (if tag_value == 17 { 55 } else { 51 })
            {
                return false;
            }
        }
    }
    true
}

fn read_attributes(cursor: &mut Cursor<'_>, pool: &ConstantPool, count: u32) -> bool {
    for _ in 0..count {
        let name = cursor.u2();
        let length = cursor.u4();
        let (Some(name_value), Some(length_value)) = (name, length) else {
            return false;
        };
        if !pool_has_tag(pool, Some(name_value), &[1]) || !cursor.skip(length_value as usize) {
            return false;
        }
    }
    true
}

fn read_members(cursor: &mut Cursor<'_>, pool: &ConstantPool) -> bool {
    let Some(count) = cursor.u2() else {
        return false;
    };
    for _ in 0..count {
        if cursor.u2().is_none() {
            return false;
        }
        let name = cursor.u2();
        let descriptor = cursor.u2();
        let attributes = cursor.u2();
        let (Some(name_value), Some(descriptor_value), Some(attributes_value)) =
            (name, descriptor, attributes)
        else {
            return false;
        };
        if !pool_has_tag(pool, Some(name_value), &[1])
            || !pool_has_tag(pool, Some(descriptor_value), &[1])
            || !read_attributes(cursor, pool, attributes_value)
        {
            return false;
        }
    }
    true
}

/// Validate class-file framing and constant-pool references before FAT parsing.
pub fn is_jvm_class_file(bytes: &[u8]) -> bool {
    let mut cursor = Cursor::new(bytes);
    if cursor.u4() != Some(0xcafe_babe) {
        return false;
    }
    let minor = cursor.u2();
    let major = cursor.u2();
    let pool_count = cursor.u2();
    let (Some(_minor), Some(major_value), Some(pool_count_value)) = (minor, major, pool_count)
    else {
        return false;
    };
    if major_value < 45 || pool_count_value == 0 {
        return false;
    }
    let Some(pool) = read_constant_pool(&mut cursor, pool_count_value as usize) else {
        return false;
    };
    if !has_valid_pool_references(&pool, major_value) {
        return false;
    }
    if cursor.u2().is_none() {
        return false;
    }
    let this_class = cursor.u2();
    let super_class = cursor.u2();
    let (Some(this_class_value), Some(super_class_value)) = (this_class, super_class) else {
        return false;
    };
    if !pool_has_tag(&pool, Some(this_class_value), &[7]) {
        return false;
    }
    if super_class_value != 0 && !pool_has_tag(&pool, Some(super_class_value), &[7]) {
        return false;
    }
    let Some(interfaces) = cursor.u2() else {
        return false;
    };
    if !cursor.skip(interfaces as usize * 2) {
        return false;
    }
    if !read_members(&mut cursor, &pool) || !read_members(&mut cursor, &pool) {
        return false;
    }
    let Some(attributes) = cursor.u2() else {
        return false;
    };
    read_attributes(&mut cursor, &pool, attributes) && cursor.at_end()
}
