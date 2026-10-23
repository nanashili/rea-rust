//! Static binary-format workflows: layouts, Mach-O, PE, ELF cores, Go and Rust
//! metadata and objdump captures.

pub mod go;
pub mod layout;
pub mod layout_view;
pub mod macho;
pub mod macho_view;
pub mod mips_elf_shared_load;
pub mod objdump_inspection;
#[cfg(unix)]
pub mod pe_resources;
#[cfg(unix)]
pub mod pe_target;
pub mod recorded_crash;
pub mod rust;
