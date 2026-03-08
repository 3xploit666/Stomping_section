<div align="center">

# Module Stomping

**Just-In-Time Shellcode Decryption via .text Section Replacement**

![Module Stomping](assets/page.png)

[![Rust](https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Windows](https://img.shields.io/badge/Windows_x64-0078D6?style=for-the-badge&logo=windows&logoColor=white)](https://www.microsoft.com/windows)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

*Advanced process injection using legitimate DLL section replacement with encrypted shellcode*

</div>

---

## Overview

Module Stomping is a code injection technique that replaces the **entire `.text` section** of a legitimate Windows DLL with encrypted shellcode. The shellcode is decrypted just-in-time (< 1ms before execution), minimizing the exposure window for memory scanners.

This technique is the foundation for more advanced variants:

| Variant | Description |
|---------|-------------|
| **Module Stomping** ← this | Complete `.text` section replacement |
| **Function Stomping** | Targets specific exported functions |
| **Hollow Stomping** | Combines process hollowing + module stomping |
| **Phantom DLL Hollowing** | Creates phantom sections for code execution |

## Execution Pipeline

```
┌─────────────────────────────────────────────────────────┐
│  1. LoadLibraryA("bcrypt.dll")                          │
│  2. Parse PE headers → locate .text section             │
│  3. VirtualProtect → PAGE_READWRITE (no RWX)            │
│  4. Zero .text section (shellcode still encrypted)      │
│  5. XOR decrypt directly into .text (JIT)               │
│  6. VirtualProtect → PAGE_EXECUTE_READ                  │
│  7. CreateThread from stomped section                   │
└─────────────────────────────────────────────────────────┘
         ↑                                    ↑
    Cleartext shellcode exists ONLY between steps 5-7 (< 1ms)
```

## Evasion Techniques

| Technique | Detail |
|-----------|--------|
| **No RWX** | Write and execute phases separated — never combined |
| **JIT Decryption** | Shellcode encrypted until milliseconds before execution |
| **No Intermediate Buffer** | Decrypts directly into target section — no extra copies |
| **Legitimate Module** | Executes from `bcrypt.dll` .text — blends with normal loaded modules |
| **PEB-based Resolution** | PE headers parsed directly, no suspicious API calls for section lookup |
| **Conditional Debug** | Release builds produce zero console output |

## Project Structure

```
src/
├── main.rs       — Entry point, debug macros, orchestration
├── pe.rs         — PE structure definitions, .text section discovery
├── crypto.rs     — Multi-byte XOR decryption (JIT pattern)
└── stomping.rs   — Core stomping engine (7-step pipeline)
```

| Module | Responsibility |
|--------|---------------|
| `pe.rs` | DOS/NT/Section headers, `find_text_section()` |
| `crypto.rs` | XOR key, encrypted payload, `decrypt_to()` |
| `stomping.rs` | Load DLL → parse → clear → decrypt → execute |
| `main.rs` | Feature-gated debug macros, thin `main()` |

## Build

```bash
# Release (silent, optimized, stripped)
cargo build --release

# Debug (verbose output)
cargo build

# Release with debug output
cargo build --release --features debug_output
```

### Build Profile

| Setting | Value | Purpose |
|---------|-------|---------|
| `opt-level` | `"z"` | Minimize binary size |
| `lto` | `true` | Link-time optimization |
| `codegen-units` | `1` | Maximum optimization |
| `panic` | `"abort"` | No unwinding code |
| `strip` | `true` | Remove all symbols |

## Usage

### 1. Prepare Encrypted Shellcode

Update the `SHELLCODE_ENCRYPTED` array in `src/crypto.rs` with your XOR-encrypted payload:

```rust
// Encrypt: encrypted[i] = raw_shellcode[i] ^ XOR_KEY[i % 32]
pub const SHELLCODE_ENCRYPTED: [u8; N] = [ /* your encrypted bytes */ ];
```

### 2. Build & Execute

```bash
cargo build --release
.\target\release\module-stomping.exe
```

## Technical Details

- **Target DLL**: `bcrypt.dll` (configurable in `stomping.rs`)
- **Section**: `.text` — entire code section replaced
- **Encryption**: Multi-byte XOR with 32-byte key
- **Memory Flow**: `PAGE_READWRITE` → write → `PAGE_EXECUTE_READ` → execute
- **Thread**: Created via `CreateThread` at the section base address
- **PE Parsing**: Manual struct definitions — no external PE crate dependency

## Legal Disclaimer

> **This software is intended exclusively for educational and security research purposes.** Unauthorized use against systems you do not own or have explicit permission to test is illegal. The author assumes no liability for misuse.

## Author

**[@3xploit666](https://github.com/3xploit666)**

---

<div align="center">

*For educational and authorized security testing purposes only.*

</div>
