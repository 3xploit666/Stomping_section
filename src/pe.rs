//! PE (Portable Executable) structure definitions and parsing utilities.
//!
//! Provides manual definitions of Windows PE structures for direct header
//! parsing without relying on external crates. Used to locate the `.text`
//! section of loaded DLLs for module stomping.

use std::ffi::c_void;
use std::mem;
use windows::core::{Error, Result};
use windows::Win32::Foundation::{E_FAIL, HMODULE};

use crate::debug_println;

// ---------------------------------------------------------------------------
// PE structure definitions
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct ImageDosHeader {
    pub e_magic: u16,
    _e_cblp: u16,
    _e_cp: u16,
    _e_crlc: u16,
    _e_cparhdr: u16,
    _e_minalloc: u16,
    _e_maxalloc: u16,
    _e_ss: u16,
    _e_sp: u16,
    _e_csum: u16,
    _e_ip: u16,
    _e_cs: u16,
    _e_lfarlc: u16,
    _e_ovno: u16,
    _e_res: [u16; 4],
    _e_oemid: u16,
    _e_oeminfo: u16,
    _e_res2: [u16; 10],
    pub e_lfanew: i32,
}

#[repr(C)]
pub struct ImageNtHeaders64 {
    pub signature: u32,
    pub file_header: ImageFileHeader,
    pub optional_header: ImageOptionalHeader64,
}

#[repr(C)]
pub struct ImageFileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    _time_date_stamp: u32,
    _pointer_to_symbol_table: u32,
    _number_of_symbols: u32,
    pub size_of_optional_header: u16,
    _characteristics: u16,
}

#[repr(C)]
pub struct ImageOptionalHeader64 {
    _magic: u16,
    _major_linker_version: u8,
    _minor_linker_version: u8,
    _size_of_code: u32,
    _size_of_initialized_data: u32,
    _size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    _base_of_code: u32,
    _image_base: u64,
    _section_alignment: u32,
    _file_alignment: u32,
    _major_os_version: u16,
    _minor_os_version: u16,
    _major_image_version: u16,
    _minor_image_version: u16,
    _major_subsystem_version: u16,
    _minor_subsystem_version: u16,
    _win32_version_value: u32,
    _size_of_image: u32,
    _size_of_headers: u32,
    _checksum: u32,
    _subsystem: u16,
    _dll_characteristics: u16,
    _size_of_stack_reserve: u64,
    _size_of_stack_commit: u64,
    _size_of_heap_reserve: u64,
    _size_of_heap_commit: u64,
    _loader_flags: u32,
    _number_of_rva_and_sizes: u32,
    _data_directory: [ImageDataDirectory; 16],
}

#[repr(C)]
struct ImageDataDirectory {
    _virtual_address: u32,
    _size: u32,
}

#[repr(C)]
pub struct ImageSectionHeader {
    pub name: [u8; 8],
    pub misc: ImageSectionHeaderMisc,
    pub virtual_address: u32,
    _size_of_raw_data: u32,
    _pointer_to_raw_data: u32,
    _pointer_to_relocations: u32,
    _pointer_to_line_numbers: u32,
    _number_of_relocations: u16,
    _number_of_line_numbers: u16,
    _characteristics: u32,
}

#[repr(C)]
pub union ImageSectionHeaderMisc {
    _physical_address: u32,
    pub virtual_size: u32,
}

// ---------------------------------------------------------------------------
// Text section info
// ---------------------------------------------------------------------------

/// Information about a located `.text` section within a loaded module.
pub struct TextSectionInfo {
    pub base_address: *mut c_void,
    pub size: usize,
    pub original_entry_point: *mut c_void,
}

// ---------------------------------------------------------------------------
// Section discovery
// ---------------------------------------------------------------------------

/// Parses PE headers of a loaded module to locate its `.text` section.
///
/// Walks DOS header → NT headers → section table to find the first section
/// whose name starts with `.text`. Returns base address, virtual size, and
/// the module's original entry point.
pub fn find_text_section(dll_handle: HMODULE) -> Result<TextSectionInfo> {
    debug_println!("[+] Parsing PE headers to locate .text section...");

    unsafe {
        let module_base = dll_handle.0 as *const u8;

        let dos_header = &*(module_base as *const ImageDosHeader);
        let nt_headers = &*((module_base.add(dos_header.e_lfanew as usize)) as *const ImageNtHeaders64);

        let original_entry = module_base
            .add(nt_headers.optional_header.address_of_entry_point as usize)
            as *mut c_void;

        let sections_ptr = (nt_headers as *const _ as *const u8)
            .add(mem::size_of::<ImageNtHeaders64>()) as *const ImageSectionHeader;

        for i in 0..nt_headers.file_header.number_of_sections {
            let section = &*sections_ptr.add(i as usize);
            let name = std::ffi::CStr::from_ptr(section.name.as_ptr() as *const i8);

            if name.to_string_lossy().starts_with(".text") {
                let text_base = module_base.add(section.virtual_address as usize) as *mut c_void;
                let text_size = section.misc.virtual_size as usize;

                debug_println!("[+] .text section found at 0x{:X} ({} bytes)", text_base as usize, text_size);

                return Ok(TextSectionInfo {
                    base_address: text_base,
                    size: text_size,
                    original_entry_point: original_entry,
                });
            }
        }

        Err(Error::new(E_FAIL, "Failed to locate .text section"))
    }
}
