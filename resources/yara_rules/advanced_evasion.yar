/*
    Advanced Evasion and Anti-Analysis Detection Rules
    Detection of sophisticated sandbox evasion, anti-debugging, and anti-VM techniques
*/

rule Evasion_Anti_Debug_Timing {
    meta:
        description = "Timing-based anti-debugging techniques"
        severity = "high"
        author = "AI-Cerberus"
    strings:
        $rdtsc = { 0F 31 }                             // RDTSC instruction
        $rdtscp = { 0F 01 F9 }                         // RDTSCP instruction
        $qpc1 = "QueryPerformanceCounter" ascii
        $qpc2 = "QueryPerformanceFrequency" ascii
        $gtc = "GetTickCount" ascii
        $gtc64 = "GetTickCount64" ascii
        $st = "GetSystemTime" ascii
        $sleep = "Sleep" ascii
    condition:
        uint16(0) == 0x5A4D and
        ((any of ($rdtsc*) and any of ($qpc*, $gtc*)) or
        (3 of ($qpc*, $gtc*, $st, $sleep)))
}

rule Evasion_Anti_Debug_API {
    meta:
        description = "API-based anti-debugging"
        severity = "high"
    strings:
        $api1 = "IsDebuggerPresent" ascii
        $api2 = "CheckRemoteDebuggerPresent" ascii
        $api3 = "NtQueryInformationProcess" ascii
        $api4 = "NtSetInformationThread" ascii
        $api5 = "OutputDebugStringA" ascii
        $api6 = "OutputDebugStringW" ascii
        $api7 = "CloseHandle" ascii
        $api8 = "NtClose" ascii
        $flag1 = { 83 3D ?? ?? ?? ?? 00 }             // ProcessDebugPort check
        $flag2 = { 3D 00 00 00 80 }                   // STATUS_INVALID_HANDLE
    condition:
        uint16(0) == 0x5A4D and
        (3 of ($api*) or (any of ($api*) and any of ($flag*)))
}

rule Evasion_Anti_Debug_PEB {
    meta:
        description = "PEB-based anti-debugging"
        severity = "high"
    strings:
        // BeingDebugged flag
        $peb1 = { 64 A1 30 00 00 00 8A 40 02 }       // fs:[0x30]->BeingDebugged
        $peb2 = { 65 48 8B 04 25 60 00 00 00 0F B6 40 02 }  // x64 BeingDebugged

        // NtGlobalFlag
        $ntg1 = { 64 A1 30 00 00 00 8B 40 68 }       // fs:[0x30]->NtGlobalFlag
        $ntg2 = { 65 48 8B 04 25 60 00 00 00 8B 80 BC 00 00 00 }  // x64

        // Heap flags
        $heap1 = { 64 A1 30 00 00 00 8B 40 18 8B 40 10 }  // Heap flags
        $heap2 = { 25 00 00 EE FF }                   // Heap flag mask
    condition:
        uint16(0) == 0x5A4D and
        any of them
}

rule Evasion_Anti_Debug_Hardware {
    meta:
        description = "Hardware breakpoint detection"
        severity = "high"
    strings:
        $ctx1 = "GetThreadContext" ascii
        $ctx2 = "SetThreadContext" ascii
        $ctx3 = "NtGetContextThread" ascii
        $dr = { 83 78 04 00 75 }                      // Check Dr0-Dr7
        $dr64 = { 48 83 78 08 00 75 }                 // x64 DR check
    condition:
        uint16(0) == 0x5A4D and
        (any of ($ctx*) and any of ($dr*))
}

rule Evasion_Anti_VM_CPUID {
    meta:
        description = "CPUID-based VM detection"
        severity = "high"
    strings:
        $cpuid = { 0F A2 }                            // CPUID instruction
        $vmware = "VMwareVMware" ascii
        $vbox = "VBoxVBoxVBox" ascii
        $hyperv = "Microsoft Hv" ascii
        $kvm = "KVMKVMKVM" ascii
        $xen = "XenVMMXenVMM" ascii
        $parallels = "prl hyperv" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        ($cpuid and any of ($vmware, $vbox, $hyperv, $kvm, $xen, $parallels))
}

rule Evasion_Anti_VM_Registry {
    meta:
        description = "Registry-based VM detection"
        severity = "high"
    strings:
        $reg1 = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port" ascii
        $reg2 = "SYSTEM\\CurrentControlSet\\Enum\\IDE" ascii
        $reg3 = "SYSTEM\\CurrentControlSet\\Enum\\SCSI" ascii
        $reg4 = "SOFTWARE\\VMware" ascii
        $reg5 = "SOFTWARE\\Oracle\\VirtualBox" ascii
        $reg6 = "HARDWARE\\ACPI\\DSDT\\VBOX" ascii
        $reg7 = "HARDWARE\\ACPI\\FADT\\VBOX" ascii
        $reg8 = "SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters" ascii
    condition:
        uint16(0) == 0x5A4D and
        3 of them
}

rule Evasion_Anti_VM_Files {
    meta:
        description = "File-based VM detection"
        severity = "high"
    strings:
        $f1 = "vmtoolsd.exe" ascii nocase
        $f2 = "vmwaretray.exe" ascii nocase
        $f3 = "vmwareuser.exe" ascii nocase
        $f4 = "VBoxService.exe" ascii nocase
        $f5 = "VBoxTray.exe" ascii nocase
        $f6 = "vmusrvc.exe" ascii nocase
        $f7 = "vmsrvc.exe" ascii nocase
        $f8 = "vmtools.dll" ascii nocase
        $f9 = "vboxhook.dll" ascii nocase
        $f10 = "vmGuestLib.dll" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        3 of them
}

rule Evasion_Anti_VM_Hardware {
    meta:
        description = "Hardware-based VM detection"
        severity = "high"
    strings:
        $hw1 = "VMware" ascii
        $hw2 = "VBOX" ascii
        $hw3 = "Virtual" ascii
        $hw4 = "QEMU" ascii
        $hw5 = "Xen" ascii
        $mac1 = { 00 0C 29 }                          // VMware MAC prefix
        $mac2 = { 00 50 56 }                          // VMware MAC prefix
        $mac3 = { 08 00 27 }                          // VirtualBox MAC prefix
        $mac4 = { 00 1C 42 }                          // Parallels MAC prefix
    condition:
        uint16(0) == 0x5A4D and
        (3 of ($hw*) or 2 of ($mac*))
}

rule Evasion_Anti_Sandbox_Process {
    meta:
        description = "Process-based sandbox detection"
        severity = "high"
    strings:
        $p1 = "wireshark.exe" ascii nocase
        $p2 = "fiddler.exe" ascii nocase
        $p3 = "procmon.exe" ascii nocase
        $p4 = "procexp.exe" ascii nocase
        $p5 = "idaq.exe" ascii nocase
        $p6 = "ollydbg.exe" ascii nocase
        $p7 = "x64dbg.exe" ascii nocase
        $p8 = "windbg.exe" ascii nocase
        $p9 = "immunitydebugger.exe" ascii nocase
        $p10 = "pestudio.exe" ascii nocase
        $p11 = "tcpview.exe" ascii nocase
        $p12 = "autoruns.exe" ascii nocase
        $p13 = "dumpcap.exe" ascii nocase
        $p14 = "hookexplorer.exe" ascii nocase
        $p15 = "sysanalyzer.exe" ascii nocase
        $api = "CreateToolhelp32Snapshot" ascii
    condition:
        uint16(0) == 0x5A4D and
        ($api and 5 of ($p*))
}

rule Evasion_Anti_Sandbox_User {
    meta:
        description = "User-based sandbox detection"
        severity = "high"
    strings:
        $u1 = "sandbox" ascii nocase
        $u2 = "malware" ascii nocase
        $u3 = "virus" ascii nocase
        $u4 = "sample" ascii nocase
        $u5 = "test" ascii nocase
        $u6 = "cuckoo" ascii nocase
        $u7 = "honey" ascii nocase
        $u8 = "john" ascii nocase
        $u9 = "admin" ascii nocase
        $u10 = "user" ascii nocase
        $api1 = "GetUserNameA" ascii
        $api2 = "GetComputerNameA" ascii
    condition:
        uint16(0) == 0x5A4D and
        ((any of ($api*) and 3 of ($u*)))
}

rule Evasion_Anti_Sandbox_Environment {
    meta:
        description = "Environment-based sandbox detection"
        severity = "high"
    strings:
        // Screen resolution
        $screen = "GetSystemMetrics" ascii
        $res1 = { 6A 00 FF 15 }                       // SM_CXSCREEN
        $res2 = { 6A 01 FF 15 }                       // SM_CYSCREEN

        // Mouse movement
        $mouse1 = "GetCursorPos" ascii
        $mouse2 = "SetCursorPos" ascii

        // Memory check
        $mem = "GlobalMemoryStatusEx" ascii

        // CPU count
        $cpu = "GetSystemInfo" ascii

        // Disk size
        $disk = "GetDiskFreeSpaceExA" ascii
    condition:
        uint16(0) == 0x5A4D and
        (($screen and any of ($res*)) or ($mouse1 and $mouse2) or
        ($mem and $cpu) or $disk)
}

rule Evasion_Anti_Sandbox_Timing {
    meta:
        description = "Timing-based sandbox detection"
        severity = "high"
    strings:
        $sleep1 = "Sleep" ascii
        $sleep2 = "NtDelayExecution" ascii
        $sleep3 = "WaitForSingleObject" ascii
        $sleep4 = "WaitForMultipleObjects" ascii
        // Long sleep values
        $long1 = { 68 ?? ?? ?? 00 FF 15 }            // Sleep(large_value)
        $long2 = { 68 60 EA 00 00 }                   // 60000ms = 1 minute
        $long3 = { 68 80 84 1E 00 }                   // 2000000ms
    condition:
        uint16(0) == 0x5A4D and
        (any of ($sleep*) and any of ($long*))
}

rule Evasion_Process_Hollowing {
    meta:
        description = "Process hollowing technique"
        severity = "critical"
    strings:
        $api1 = "CreateProcessA" ascii
        $api2 = "CreateProcessW" ascii
        $api3 = "NtUnmapViewOfSection" ascii
        $api4 = "ZwUnmapViewOfSection" ascii
        $api5 = "VirtualAllocEx" ascii
        $api6 = "WriteProcessMemory" ascii
        $api7 = "SetThreadContext" ascii
        $api8 = "ResumeThread" ascii
        $api9 = "GetThreadContext" ascii
        $flag = { 04 00 00 00 }                       // CREATE_SUSPENDED
    condition:
        uint16(0) == 0x5A4D and
        (any of ($api1, $api2) and any of ($api3, $api4) and
        $api5 and $api6 and any of ($api7, $api8, $api9))
}

rule Evasion_Process_Doppelganging {
    meta:
        description = "Process doppelganging technique"
        severity = "critical"
    strings:
        $api1 = "NtCreateTransaction" ascii
        $api2 = "NtCreateSection" ascii
        $api3 = "NtRollbackTransaction" ascii
        $api4 = "NtCreateProcessEx" ascii
        $api5 = "RtlCreateProcessParametersEx" ascii
        $api6 = "NtCreateThreadEx" ascii
    condition:
        uint16(0) == 0x5A4D and
        4 of them
}

rule Evasion_Heaven_Gate {
    meta:
        description = "Heaven's Gate (WoW64 bypass) technique"
        severity = "critical"
    strings:
        // Far jump to 64-bit code segment
        $gate1 = { EA ?? ?? ?? ?? 33 00 }            // jmp far 0x33:addr
        $gate2 = { 6A 33 E8 ?? ?? ?? ?? 83 C4 }     // push 0x33; call
        $gate3 = { 9A ?? ?? ?? ?? 33 00 }            // call far 0x33:addr

        // WoW64 syscall
        $wow1 = "Wow64Transition" ascii
        $wow2 = { 65 48 8B 04 25 30 00 00 00 }      // mov rax, gs:[0x30]
    condition:
        uint16(0) == 0x5A4D and
        any of them
}

rule Evasion_Syscall_Direct {
    meta:
        description = "Direct syscall invocation (userland hooks bypass)"
        severity = "critical"
    strings:
        // x86 syscall
        $sys32_1 = { B8 ?? ?? 00 00 BA ?? ?? ?? ?? FF D2 }  // mov eax, syscall#; call edx
        $sys32_2 = { B8 ?? ?? 00 00 CD 2E }                  // mov eax, syscall#; int 0x2e

        // x64 syscall
        $sys64_1 = { B8 ?? ?? 00 00 0F 05 }                  // mov eax, syscall#; syscall
        $sys64_2 = { 4C 8B D1 B8 ?? ?? 00 00 0F 05 }        // mov r10, rcx; mov eax, #; syscall

        // Common syscall numbers
        $syscall_ntallocate = { B8 18 00 00 00 }            // NtAllocateVirtualMemory
        $syscall_ntwrite = { B8 3A 00 00 00 }               // NtWriteVirtualMemory
        $syscall_ntprotect = { B8 50 00 00 00 }             // NtProtectVirtualMemory
    condition:
        uint16(0) == 0x5A4D and
        (any of ($sys*) or any of ($syscall_*))
}

rule Evasion_Module_Stomping {
    meta:
        description = "Module stomping (DLL hollowing)"
        severity = "critical"
    strings:
        $api1 = "LoadLibraryA" ascii
        $api2 = "LoadLibraryW" ascii
        $api3 = "LoadLibraryExA" ascii
        $api4 = "VirtualProtect" ascii
        $api5 = "memcpy" ascii
        $api6 = "memmove" ascii
        $rwx = { 68 40 00 00 00 }                    // PAGE_EXECUTE_READWRITE
    condition:
        uint16(0) == 0x5A4D and
        (any of ($api1, $api2, $api3) and $api4 and any of ($api5, $api6) and $rwx)
}

rule Evasion_ETW_Patching {
    meta:
        description = "ETW (Event Tracing for Windows) patching"
        severity = "critical"
    strings:
        $etw1 = "EtwEventWrite" ascii
        $etw2 = "NtTraceEvent" ascii
        $etw3 = "EtwEventRegister" ascii
        $patch = { C3 }                               // ret instruction
        $patch2 = { 33 C0 C3 }                       // xor eax, eax; ret
        $api = "GetProcAddress" ascii
    condition:
        uint16(0) == 0x5A4D and
        (any of ($etw*) and $api and any of ($patch*))
}

rule Evasion_AMSI_Bypass {
    meta:
        description = "AMSI bypass techniques"
        severity = "critical"
    strings:
        $amsi1 = "amsi.dll" ascii nocase
        $amsi2 = "AmsiScanBuffer" ascii
        $amsi3 = "AmsiInitialize" ascii
        $amsi4 = "AmsiOpenSession" ascii
        $patch1 = { B8 57 00 07 80 C3 }              // mov eax, 0x80070057; ret (E_INVALIDARG)
        $patch2 = { 31 C0 C3 }                        // xor eax, eax; ret
        $patch3 = { 48 31 C0 C3 }                     // xor rax, rax; ret (x64)
    condition:
        uint16(0) == 0x5A4D and
        (any of ($amsi*) and any of ($patch*))
}

rule Evasion_DLL_Search_Order_Hijacking {
    meta:
        description = "DLL search order hijacking preparation"
        severity = "high"
    strings:
        $api1 = "SetDllDirectoryA" ascii
        $api2 = "SetDllDirectoryW" ascii
        $api3 = "AddDllDirectory" ascii
        $api4 = "SetDefaultDllDirectories" ascii
        $path1 = "\\AppData\\Local" ascii nocase
        $path2 = "\\Temp\\" ascii nocase
        $path3 = "\\Downloads\\" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        (any of ($api*) and any of ($path*))
}
