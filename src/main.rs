use std::{mem::{size_of,MaybeUninit}, collections, ffi::CStr};
use sysinfo::{SystemExt, ProcessExt};
use winapi::{
    ctypes::c_void,
    um::{tlhelp32, winnt,memoryapi,processthreadsapi,handleapi},
    shared::minwindef
};

#[derive(Debug)]
struct WinModule {
    handle: winnt::HANDLE,
    name: String,
    base_address: *mut u8,
}

unsafe fn str_from_null_terminated_utf8(s: &[u8]) -> &str {
    CStr::from_ptr(s.as_ptr() as *const _).to_str().unwrap()
}

fn str_from_null_terminated_utf8_safe(s: &[u8]) -> &str {
    if s.iter().any(|&x| x == 0) {
        unsafe { str_from_null_terminated_utf8(s) }
    } else {
        std::str::from_utf8(s).unwrap()
    }
}
unsafe fn char_array_to_string(char_array: &[winnt::CHAR]) -> String {
    let data: Vec<u8> = char_array.iter().map(|&c| c as u8).collect();
    let data = str_from_null_terminated_utf8_safe(&data);
    data.to_ascii_lowercase()
}

fn get_procId(pname:&str) -> u32{
    let mut system = sysinfo::System::new();
    system.refresh_all();
    let pid:u32 = system.processes_by_exact_name(pname).last().unwrap().pid().to_string().parse().unwrap();
    pid
}



fn get_modules_by_pid(pid: u32) -> Option<Vec<i32>> {
    use winapi::um::{libloaderapi::GetModuleFileNameW,psapi::{EnumProcessModulesEx, K32GetModuleBaseNameW}};
    // Open a handle to the process
    let handle = unsafe { processthreadsapi::OpenProcess(winnt::PROCESS_QUERY_INFORMATION | winnt::PROCESS_VM_READ, 0, pid) };
    if handle.is_null() {
        return None;
    }

    // Enumerate the modules in the process
    let mut buffer = [0; 1024];
    let mut bytes_required = 0;
    let result = unsafe {
        EnumProcessModulesEx(
            handle,
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
            &mut bytes_required,
            winapi::um::psapi::LIST_MODULES_ALL,
        )
    };
    if result == 0 {
        return None;
    }

    // Get the base address and name of each module
    let module_count = (bytes_required as usize) / size_of::<u64>();
    let mut modules = Vec::with_capacity(module_count as usize);
    println!("module c {:?}",buffer);
    for i in 0..module_count {
        let base_address = buffer[i];
        // let mut name = [0; 256];
        // let name_T =
        // unsafe {
        //     GetModuleFileNameW(
        //         handle.cast(),
        //         base_address as winnt::LPWSTR,
        //         name.len() as u32,
        //     )
        // };
        // println!("name l {:?}",name);
            
        modules.push(base_address);
        // if name_length > 0 {
        //     let name = String::from_utf16_lossy(&name[..name_length as usize]);
        // }
            
    }
    Some(modules)

}
unsafe fn get_modules_by_procid(handle: winnt::HANDLE, process_id: minwindef::DWORD) -> Option<collections::HashMap<String, WinModule>> {
    let module_snap = tlhelp32::CreateToolhelp32Snapshot(tlhelp32::TH32CS_SNAPMODULE, process_id);
    let mut module_entry = MaybeUninit::<tlhelp32::MODULEENTRY32>::uninit();
    if module_snap == handleapi::INVALID_HANDLE_VALUE {
        return None;
    }
    module_entry.assume_init().dwSize = size_of::<tlhelp32::MODULEENTRY32>() as u32;
    let result = tlhelp32::Module32First(module_snap, module_entry.as_mut_ptr() as *mut _);
    println!("{:?}",module_entry);
    if result != minwindef::TRUE {
        handleapi::CloseHandle(module_snap);
        return None;
    }
    let mut modules: collections::HashMap<String, WinModule> = collections::HashMap::new();
    loop {
        let module = module_entry.assume_init();
        let module_name = char_array_to_string(&module.szModule);
        modules.insert(module_name.clone(), WinModule {
            handle,
            name: module_name.clone(),
            base_address: module.modBaseAddr,
        });
        let next_result = tlhelp32::Module32Next(module_snap, module_entry.as_mut_ptr() as *mut _);
        if next_result != minwindef::TRUE {
            break;
        }
    }
    return Some(modules);
}


unsafe fn findDMA(hproc:*mut c_void,ptr:*mut u8,offsets:&[u32])->*mut u8{
    let mut addr = ptr.clone();
    let mut saves = [0;4];
    for i in offsets {
        memoryapi::ReadProcessMemory(hproc, addr.cast(), saves.as_mut_ptr().cast(), size_of::<*mut u8>(), 0 as *mut usize);
        addr = addr.add(*i as usize);
    }
    addr
}


fn main() {
    unsafe{
        let pid = get_procId("BleachBraveSouls.exe");
        println!("bbs pid : {}",pid);
        let phandler = processthreadsapi::OpenProcess(winnt::PROCESS_ALL_ACCESS, 0, pid);
        let modules = get_modules_by_pid(pid).unwrap();
        println!("{:?}",modules);
        for i in modules.iter(){
            
            // println!("0x{:016x}",i);
            let mut dynamic_ptr_address = (i.to_owned() as u128) as *mut u8;
            dynamic_ptr_address = dynamic_ptr_address.add(0x019C0B70);
            let hp = findDMA(phandler, dynamic_ptr_address, &[0x8,0x48,0xC0,0x28,0x140,0x170,0xC8]);
            println!("{} : {:#02x}",i,hp as i128);
            let mut saves = [0;4];
            memoryapi::ReadProcessMemory(phandler, hp.cast(), saves.as_mut_ptr().cast(), size_of::<i32>(), 0 as *mut usize);
            // println!("{} : {:?}",i,saves);
        }
    }
}
