use std::io::{self, Read, Write};

#[link(name = "kernel32")]
extern "system" {
    fn GetConsoleProcessList(process_list: *mut u32, process_count: u32) -> u32;
    fn SetConsoleOutputCP(code_page_id: u32) -> i32;
}

/// UTF-8 so the banner does not scramble on a default OEM code page.
pub fn prepare() {
    unsafe {
        let _ = SetConsoleOutputCP(65001);
    }
}

/// Explorer double-click owns the console alone; cmd/PowerShell share it.
/// Without a pause the window closes as soon as the scan finishes.
pub fn pause_if_owns_console() {
    let mut list = [0u32; 8];
    let n = unsafe { GetConsoleProcessList(list.as_mut_ptr(), list.len() as u32) };
    if n != 1 {
        return;
    }
    eprintln!("\n  Press Enter to close...");
    let _ = io::stdout().flush();
    let _ = io::stderr().flush();
    let _ = io::stdin().read(&mut [0u8; 32]);
}
