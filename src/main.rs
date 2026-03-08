//! Module Stomping with Just-In-Time Decryption
//!
//! Demonstrates an advanced Windows process injection technique that replaces
//! the `.text` section of a legitimate DLL with encrypted shellcode, decrypting
//! it just milliseconds before execution.
//!
//! # Technique
//! Module Stomping is the foundation for several advanced injection methods:
//! - Function Stomping (targets individual exports)
//! - Hollow Stomping (combines process hollowing)
//! - Phantom DLL Hollowing (creates phantom sections)
//!
//! This implementation demonstrates the core technique with JIT decryption
//! for minimal exposure of cleartext shellcode in memory.
//!
//! # Build
//! ```bash
//! cargo build --release          # Silent, optimized
//! cargo build                    # Debug output enabled
//! cargo build --features debug_output --release  # Release with debug output
//! ```

mod crypto;
mod pe;
mod stomping;

// ---------------------------------------------------------------------------
// Conditional debug output macros
// ---------------------------------------------------------------------------

#[cfg(any(debug_assertions, feature = "debug_output"))]
#[macro_export]
macro_rules! debug_print {
    ($($arg:tt)*) => { print!($($arg)*); };
}

#[cfg(not(any(debug_assertions, feature = "debug_output")))]
#[macro_export]
macro_rules! debug_print {
    ($($arg:tt)*) => {};
}

#[cfg(any(debug_assertions, feature = "debug_output"))]
#[macro_export]
macro_rules! debug_println {
    ($($arg:tt)*) => { println!($($arg)*); };
}

#[cfg(not(any(debug_assertions, feature = "debug_output")))]
#[macro_export]
macro_rules! debug_println {
    ($($arg:tt)*) => {};
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() -> windows::core::Result<()> {
    debug_println!("=== Module Stomping with JIT Decryption ===");
    debug_println!("Target: bcrypt.dll .text section");
    debug_println!();

    stomping::run()?;

    debug_println!("[+] Done");
    Ok(())
}
