/*
    Code Injection Technique Detection
    Process injection, DLL injection, and memory manipulation techniques
*/

rule Injection_CreateRemoteThread {
    meta:
        description = "CreateRemoteThread injection"
        severity = "critical"
    strings:
        $api1 = "OpenProcess" ascii
        $api2 = "VirtualAllocEx" ascii
        $api3 = "WriteProcessMemory" ascii
        $api4 = "CreateRemoteThread" ascii
        $api5 = "NtCreateThreadEx" ascii
        $flag = { 00 30 00 00 }  // MEM_COMMIT | MEM_RESERVE
        $rwx = { 40 00 00 00 }   // PAGE_EXECUTE_READWRITE
    condition:
        uint16(0) == 0x5A4D and
        ($api1 and $api2 and $api3 and ($api4 or $api5)) and ($flag or $rwx)
}

rule Injection_QueueUserAPC {
    meta:
        description = "QueueUserAPC injection"
        severity = "critical"
    strings:
        $api1 = "OpenThread" ascii
        $api2 = "VirtualAllocEx" ascii
        $api3 = "WriteProcessMemory" ascii
        $api4 = "QueueUserAPC" ascii
        $api5 = "NtQueueApcThread" ascii
        $api6 = "ResumeThread" ascii
    condition:
        uint16(0) == 0x5A4D and
        ($api2 and $api3) and (($api4 or $api5) and ($api1 or $api6))
}

rule Injection_SetWindowsHookEx {
    meta:
        description = "SetWindowsHookEx DLL injection"
        severity = "high"
    strings:
        $api1 = "SetWindowsHookExA" ascii
        $api2 = "SetWindowsHookExW" ascii
        $api3 = "LoadLibraryA" ascii
        $api4 = "LoadLibraryW" ascii
        $api5 = "GetProcAddress" ascii
        // UNUSED: $hook1 = { 0D 00 00 00 }  // WH_KEYBOARD_LL
        // UNUSED: $hook2 = { 0E 00 00 00 }  // WH_MOUSE_LL
        // UNUSED: $hook3 = { 05 00 00 00 }  // WH_CBT
    condition:
        uint16(0) == 0x5A4D and
        (any of ($api1, $api2)) and (any of ($api3, $api4) and $api5)
}

rule Injection_NtMapViewOfSection {
    meta:
        description = "NtMapViewOfSection injection"
        severity = "critical"
    strings:
        $api1 = "NtCreateSection" ascii
        $api2 = "ZwCreateSection" ascii
        $api3 = "NtMapViewOfSection" ascii
        $api4 = "ZwMapViewOfSection" ascii
        $api5 = "NtUnmapViewOfSection" ascii
        $api6 = "RtlCreateUserThread" ascii
    condition:
        uint16(0) == 0x5A4D and
        (any of ($api1, $api2)) and (any of ($api3, $api4)) and (any of ($api5, $api6))
}

rule Injection_Process_Hollowing {
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
        // UNUSED: $suspend = { 04 00 00 00 }  // CREATE_SUSPENDED
    condition:
        uint16(0) == 0x5A4D and
        (any of ($api1, $api2)) and (any of ($api3, $api4)) and
        $api5 and $api6 and (any of ($api7, $api8, $api9))
}

rule Injection_Process_Doppelganging {
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
        uint16(0) == 0x5A4D and 4 of them
}

rule Injection_AtomBombing {
    meta:
        description = "AtomBombing injection"
        severity = "critical"
    strings:
        $api1 = "GlobalAddAtomA" ascii
        $api2 = "GlobalAddAtomW" ascii
        $api3 = "GlobalGetAtomNameA" ascii
        $api4 = "GlobalGetAtomNameW" ascii
        $api5 = "NtQueueApcThread" ascii
        $api6 = "QueueUserAPC" ascii
        // UNUSED: $api7 = "ntdll" ascii
    condition:
        uint16(0) == 0x5A4D and
        (any of ($api1, $api2)) and (any of ($api3, $api4)) and (any of ($api5, $api6))
}

rule Injection_Early_Bird {
    meta:
        description = "Early Bird injection"
        severity = "critical"
    strings:
        $api1 = "CreateProcessA" ascii
        $api2 = "CreateProcessW" ascii
        $api3 = "VirtualAllocEx" ascii
        $api4 = "WriteProcessMemory" ascii
        $api5 = "QueueUserAPC" ascii
        $api6 = "NtQueueApcThread" ascii
        $api7 = "ResumeThread" ascii
        // UNUSED: $suspend = "CREATE_SUSPENDED" ascii
    condition:
        uint16(0) == 0x5A4D and
        (any of ($api1, $api2)) and $api3 and $api4 and (any of ($api5, $api6)) and $api7
}

rule Injection_Thread_Hijacking {
    meta:
        description = "Thread execution hijacking"
        severity = "critical"
    strings:
        $api1 = "OpenThread" ascii
        $api2 = "SuspendThread" ascii
        $api3 = "GetThreadContext" ascii
        $api4 = "SetThreadContext" ascii
        $api5 = "ResumeThread" ascii
        $api6 = "VirtualAllocEx" ascii
        $api7 = "WriteProcessMemory" ascii
    condition:
        uint16(0) == 0x5A4D and
        $api1 and $api2 and $api3 and $api4 and $api5 and (any of ($api6, $api7))
}

rule Injection_Reflective_DLL {
    meta:
        description = "Reflective DLL injection"
        severity = "critical"
    strings:
        $s1 = "ReflectiveLoader" ascii
        $s2 = "ReflectiveDll" ascii
        $api1 = "VirtualAlloc" ascii
        $api2 = "VirtualProtect" ascii
        $pe = { 4D 5A }  // MZ header
        $reloc = ".reloc" ascii
        $export = "DllMain" ascii
    condition:
        uint16(0) == 0x5A4D and
        (any of ($s*) or (all of ($api*) and $pe and ($reloc or $export)))
}

rule Injection_DLL_Sideloading {
    meta:
        description = "DLL side-loading preparation"
        severity = "high"
    strings:
        $api1 = "LoadLibraryA" ascii
        $api2 = "LoadLibraryW" ascii
        $api3 = "LoadLibraryExA" ascii
        $api4 = "LoadLibraryExW" ascii
        $copy1 = "CopyFileA" ascii
        $copy2 = "CopyFileW" ascii
        $dll = ".dll" ascii nocase
        $exe = ".exe" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        (any of ($api*)) and (any of ($copy*)) and $dll and $exe
}

rule Injection_Phantom_DLL {
    meta:
        description = "Phantom DLL hollowing"
        severity = "critical"
    strings:
        $api1 = "NtOpenSection" ascii
        $api2 = "NtMapViewOfSection" ascii
        $api3 = "NtUnmapViewOfSection" ascii
        $api4 = "NtProtectVirtualMemory" ascii
        $knowndll = "\\KnownDlls\\" ascii
        $ntdll = "ntdll.dll" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        2 of ($api*) and ($knowndll or $ntdll)
}

rule Injection_Module_Stomping {
    meta:
        description = "Module stomping/DLL hollowing"
        severity = "critical"
    strings:
        $api1 = "LoadLibraryA" ascii
        $api2 = "LoadLibraryW" ascii
        $api3 = "VirtualProtect" ascii
        $api4 = "memcpy" ascii
        $api5 = "RtlCopyMemory" ascii
        $rwx = { 40 00 00 00 }  // PAGE_EXECUTE_READWRITE
    condition:
        uint16(0) == 0x5A4D and
        (any of ($api1, $api2)) and $api3 and (any of ($api4, $api5)) and $rwx
}

rule Injection_Callback_Overwrite {
    meta:
        description = "Callback function overwrite"
        severity = "high"
    strings:
        $api1 = "EnumWindows" ascii
        $api2 = "EnumChildWindows" ascii
        $api3 = "EnumFonts" ascii
        $api4 = "EnumResourceTypes" ascii
        $api5 = "SetTimer" ascii
        $api6 = "CreateTimerQueueTimer" ascii
        $write = "WriteProcessMemory" ascii
        $alloc = "VirtualAllocEx" ascii
    condition:
        uint16(0) == 0x5A4D and
        (any of ($api*)) and $write and $alloc
}

rule Injection_NTFS_Transaction {
    meta:
        description = "NTFS transaction-based injection"
        severity = "critical"
    strings:
        $api1 = "CreateTransaction" ascii
        $api2 = "CreateFileTransactedA" ascii
        $api3 = "CreateFileTransactedW" ascii
        $api4 = "RollbackTransaction" ascii
        $api5 = "CommitTransaction" ascii
        $write = "WriteFile" ascii
    condition:
        uint16(0) == 0x5A4D and
        $api1 and (any of ($api2, $api3)) and (any of ($api4, $api5)) and $write
}

rule Injection_Ghostwriting {
    meta:
        description = "Ghostwriting injection technique"
        severity = "critical"
    strings:
        $api1 = "RtlCreateUserThread" ascii
        $api2 = "NtCreateThreadEx" ascii
        $api3 = "SetThreadContext" ascii
        $api4 = "SuspendThread" ascii
        $api5 = "GetThreadContext" ascii
        $wow64 = "Wow64SetThreadContext" ascii
    condition:
        uint16(0) == 0x5A4D and
        (any of ($api1, $api2)) and ($api3 or $wow64) and ($api4 and $api5)
}

rule Injection_Syscall_Direct {
    meta:
        description = "Direct syscall for injection"
        severity = "critical"
    strings:
        // x64 syscall
        $sys1 = { B8 ?? ?? 00 00 0F 05 }  // mov eax, syscall#; syscall
        $sys2 = { 4C 8B D1 B8 ?? ?? 00 00 0F 05 }  // mov r10, rcx; mov eax; syscall
        // x86 syscall
        $sys3 = { B8 ?? ?? 00 00 CD 2E }  // mov eax, syscall#; int 2e
        // Common injection syscalls
        $alloc = { B8 18 00 00 00 }   // NtAllocateVirtualMemory
        $write = { B8 3A 00 00 00 }   // NtWriteVirtualMemory
        $protect = { B8 50 00 00 00 } // NtProtectVirtualMemory
    condition:
        uint16(0) == 0x5A4D and
        (any of ($sys*)) and (2 of ($alloc, $write, $protect))
}
