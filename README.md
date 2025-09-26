# Module Stomping with Just-In-Time Decryption

![Module Stomping Technique](assets/page.png)

## Overview

This project demonstrates an advanced Windows process injection technique called Module Stomping, enhanced with just-in-time (JIT) shellcode decryption for improved evasion capabilities. The implementation replaces the entire `.text` section of a legitimate Windows DLL with encrypted shellcode that is decrypted moments before execution.

### Foundation Technique

Module Stomping is the foundational technique for several advanced process injection methods. It serves as the base for more sophisticated variants including:

- **Function Stomping**: Targets specific functions rather than entire sections
- **Hollow Stomping**: Combines process hollowing with module stomping
- **Phantom DLL Hollowing**: Creates phantom sections for code execution
- **Module Shifting**: Relocates module sections before stomping

This implementation demonstrates the core Module Stomping technique in its purest form - complete section replacement with enhanced evasion through JIT decryption. Understanding this base technique is essential for comprehending more advanced injection methods that build upon these principles.

## Technical Description

Module Stomping is a code injection technique that leverages legitimate Windows DLLs already loaded in memory. Unlike traditional process injection methods, this technique modifies existing module sections, making detection more challenging for security solutions.

### Key Features

- **Complete Section Replacement**: Replaces the entire `.text` section of the target DLL, not just individual functions
- **Just-In-Time Decryption**: Shellcode remains encrypted until milliseconds before execution
- **PE Header Parsing**: Direct parsing of PE structures to locate target sections
- **Memory Protection Management**: Careful manipulation of memory permissions to avoid detection patterns
- **XOR Encryption**: Simple yet effective encryption to obfuscate shellcode in binary

## Implementation Details

### Architecture

The implementation consists of several key components:

1. **PE Structure Definitions**: Manual definitions of Windows PE structures for header parsing
2. **Decryption Engine**: XOR-based decryption that writes directly to target memory
3. **Section Locator**: PE parser to find and analyze the `.text` section
4. **Memory Manager**: Handles permission changes with minimal exposure windows
5. **Execution Handler**: Creates threads for shellcode execution

### Process Flow

1. **DLL Loading**: Load target DLL (bcrypt.dll) into process memory
2. **Section Discovery**: Parse PE headers to locate `.text` section boundaries
3. **Permission Modification**: Change section permissions to Read-Write (avoiding RWX)
4. **Area Preparation**: Clear the target section while shellcode remains encrypted
5. **JIT Decryption**: Decrypt shellcode directly into target memory location
6. **Permission Restoration**: Immediately change permissions to Read-Execute
7. **Execution**: Create thread to execute from stomped section

### Security Considerations

#### Evasion Techniques

- **Minimal Exposure Window**: Decrypted shellcode exists in memory for less than 1ms before execution
- **No Intermediate Copies**: Direct decryption to final destination reduces memory artifacts
- **Permission Separation**: Write and Execute permissions are never combined (no RWX)
- **Legitimate Module Usage**: Leverages trusted Windows DLLs to blend with normal operations

#### Detection Vectors

- Memory permission changes on legitimate DLL sections
- Modification of known module content
- Thread creation from modified sections
- Behavioral analysis of unexpected module activity

## Technical Specifications

### Requirements

- **Platform**: Windows x64
- **Language**: Rust
- **Dependencies**:
  - `windows` crate for Windows API access
  - Standard Rust toolchain

### Build Configuration

```toml
[package]
name = "Stomping_section"
version = "0.1.0"
edition = "2021"

[dependencies]
windows = { version = "0.58", features = [
    "Win32_Foundation",
    "Win32_System_LibraryLoader",
    "Win32_System_Memory",
    "Win32_System_Threading",
] }
```

### Compilation

Debug build with verbose output:
```bash
cargo build
```

Release build with minimal output:
```bash
cargo build --release
```

## Code Structure

### Core Functions

#### `decrypt_shellcode_in_place(dest: *mut u8, dest_size: usize)`
Performs in-place XOR decryption directly to target memory, eliminating intermediate buffers.

#### `find_text_section(dll_handle: HMODULE) -> Result<TextSectionInfo>`
Parses PE headers to locate the `.text` section of the loaded module.

#### `change_memory_protection(address: *mut c_void, size: usize) -> Result<PAGE_PROTECTION_FLAGS>`
Modifies memory permissions while maintaining stealth by avoiding RWX combinations.

#### `prepare_stomping_area(text_info: &TextSectionInfo)`
Clears the target section in preparation for shellcode injection.

#### `decrypt_and_execute_stomped_module(text_info: &TextSectionInfo) -> Result<()>`
Performs JIT decryption and immediate execution with minimal exposure time.

### Data Structures

#### `TextSectionInfo`
```rust
struct TextSectionInfo {
    base_address: *mut c_void,
    size: usize,
    original_entry_point: *mut c_void,
}
```

#### PE Structure Definitions
- `ImageDosHeader`: DOS header for PE file format
- `IMAGE_NT_HEADERS64`: NT headers for 64-bit PE files
- `ImageSectionHeader`: Section header information

## Usage

### Basic Execution

The program executes automatically upon launch:

```bash
./Stomping_section.exe
```

### Debug Mode

Enable verbose output by building in debug mode:

```bash
cargo run
```

### Configuration

Modify the following constants to customize behavior:

- `SHELLCODE_ENCRYPTED`: Encrypted payload bytes
- `XOR_KEY`: Decryption key
- Target DLL: Change from "bcrypt.dll" in `load_target_dll()`

## Security Notice

This code is provided for educational and research purposes only. It demonstrates advanced Windows internals and security concepts. Usage should be limited to:

- Security research and analysis
- Malware analysis environments
- Authorized penetration testing
- Educational purposes in controlled environments

**Warning**: Unauthorized use of code injection techniques may violate computer fraud and abuse laws. Always ensure proper authorization before testing on any system.

## Technical Limitations

- Requires administrative privileges for some operations
- Target DLL must be loadable in the current process context
- Shellcode size cannot exceed target section size
- Windows Defender and other AV solutions may flag this behavior

## References

- Windows PE Format Documentation
- Process Injection Techniques
- Windows Memory Protection Constants
- Rust Windows Crate Documentation

## License

This project is provided as-is for educational purposes. Use at your own risk and responsibility.

## Author
3xploit666

[LinkedIn Profile](https://www.linkedin.com/in/javier-perez-0582ba1b1/)

Developed for security research and educational demonstrations of Windows injection techniques.