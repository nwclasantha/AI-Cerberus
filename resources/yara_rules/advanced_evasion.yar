/*
    Advanced Evasion and Anti-Analysis Detection Rules
    Detection of sophisticated sandbox evasion, anti-debugging, and anti-VM techniques
*/

rule Evasion_Anti_Debug_Timing {
    meta:
        description = "Timing-based anti-debugging techniques"
        severity = "high"
    strings:
        $rdtsc = { 0F 31 }
        $rdtscp = { 0F 01 F9 }
        $qpc = "QueryPerformanceCounter" ascii
        $gtc = "GetTickCount" ascii
        $st = "GetSystemTime" ascii
        $sleep = "Sleep" ascii
    condition:
        uint16(0) == 0x5A4D and
        ((any of ($rdtsc*) and any of ($qpc, $gtc, $st)) or
        (3 of ($qpc, $gtc, $st, $sleep)))
}

rule Evasion_Anti_Debug_API {
    meta:
        description = "API-based anti-debugging"
        severity = "high"
    strings:
        $api1 = "IsDebuggerPresent" ascii
        $api2 = "CheckRemoteDebuggerPresent" ascii
        $api3 = "NtQueryInformationProcess" ascii
        $api4 = "OutputDebugString" ascii
        $api5 = "NtSetInformationThread" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Evasion_Anti_VM {
    meta:
        description = "Anti-VM/sandbox detection"
        severity = "high"
    strings:
        $vm1 = "vmware" ascii nocase
        $vm2 = "virtualbox" ascii nocase
        $vm3 = "vbox" ascii nocase
        $vm4 = "qemu" ascii nocase
        $vm5 = "xen" ascii nocase
        $vm6 = "hyperv" ascii nocase
        $vm7 = "sandboxie" ascii nocase
        $vm8 = "wine" ascii nocase
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule Evasion_PEB_BeingDebugged {
    meta:
        description = "PEB BeingDebugged flag check"
        severity = "medium"
    strings:
        $peb1 = { 64 A1 30 00 00 00 }
        $peb2 = { 65 48 8B 04 25 60 00 00 00 }
        $peb3 = { 64 8B 0D 30 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and any of them
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
    condition:
        uint16(0) == 0x5A4D and
        (any of ($api1, $api2) and any of ($api3, $api4) and
        $api5 and $api6 and any of ($api7, $api8))
}

rule Evasion_Direct_Syscall {
    meta:
        description = "Direct syscall evasion technique"
        severity = "high"
    strings:
        $syscall = { 0F 05 }
        $sysenter = { 0F 34 }
        $int2e = { CD 2E }
    condition:
        uint16(0) == 0x5A4D and (#syscall > 5 or #sysenter > 3 or #int2e > 2)
}
