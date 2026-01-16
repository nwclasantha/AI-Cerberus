/*
    Evasion and Anti-Analysis Technique Detection
    Covers: Anti-debugging, Anti-VM, Obfuscation, etc.
*/

rule AntiDebug_IsDebuggerPresent {
    meta:
        description = "IsDebuggerPresent anti-debugging"
        severity = "high"
    strings:
        $api = "IsDebuggerPresent" ascii
        $code = {64 A1 30 00 00 00 8B 40 02}
    condition:
        any of them
}

rule AntiDebug_CheckRemoteDebugger {
    meta:
        description = "CheckRemoteDebuggerPresent anti-debugging"
        severity = "high"
    strings:
        $api = "CheckRemoteDebuggerPresent" ascii
    condition:
        $api
}

rule AntiDebug_NtQueryInformationProcess {
    meta:
        description = "NtQueryInformationProcess anti-debugging"
        severity = "high"
    strings:
        $api = "NtQueryInformationProcess" ascii
        $zwapi = "ZwQueryInformationProcess" ascii
    condition:
        any of them
}

rule AntiDebug_OutputDebugString {
    meta:
        description = "OutputDebugString anti-debugging"
        severity = "medium"
    strings:
        $api = "OutputDebugString" ascii
        $code = {68 ?? ?? ?? ?? FF 15}
    condition:
        $api and $code
}

rule AntiDebug_Timing {
    meta:
        description = "Timing-based anti-debugging"
        severity = "high"
    strings:
        $api1 = "GetTickCount" ascii
        $api2 = "QueryPerformanceCounter" ascii
        $api3 = "GetSystemTime" ascii
        $api4 = "timeGetTime" ascii
        $rdtsc = {0F 31}
    condition:
        2 of ($api*) or $rdtsc
}

rule AntiDebug_NtSetInformationThread {
    meta:
        description = "NtSetInformationThread anti-debugging"
        severity = "high"
    strings:
        $api = "NtSetInformationThread" ascii
        $zwapi = "ZwSetInformationThread" ascii
    condition:
        any of them
}

rule AntiDebug_CloseHandle_Exception {
    meta:
        description = "CloseHandle exception anti-debugging"
        severity = "medium"
    strings:
        $api = "CloseHandle" ascii
        $invalid = {6A FF}
    condition:
        $api and $invalid
}

rule AntiDebug_INT3_Check {
    meta:
        description = "INT3 breakpoint detection"
        severity = "high"
    strings:
        $int3 = {CC}
        $check = {80 38 CC}
    condition:
        $check
}

rule AntiDebug_Hardware_Breakpoint {
    meta:
        description = "Hardware breakpoint detection"
        severity = "high"
    strings:
        $api = "GetThreadContext" ascii
        $check = {83 78 04 00}
    condition:
        $api and $check
}

rule AntiVM_VMware {
    meta:
        description = "VMware detection"
        severity = "high"
    strings:
        $s1 = "VMware" nocase
        $s2 = "vmtoolsd" ascii
        $s3 = "vmwaretray" ascii
        $s4 = "vmwareuser" ascii
        $s5 = "vmhgfs" ascii
        $io = {B8 58 4D 56 68}
    condition:
        2 of ($s*) or $io
}

rule AntiVM_VirtualBox {
    meta:
        description = "VirtualBox detection"
        severity = "high"
    strings:
        $s1 = "VirtualBox" nocase
        $s2 = "VBoxService" ascii
        $s3 = "VBoxTray" ascii
        $s4 = "VBoxGuest" ascii
        $s5 = "VBOX" ascii
        $acpi = "VBOX__" ascii
    condition:
        2 of ($s*) or $acpi
}

rule AntiVM_QEMU {
    meta:
        description = "QEMU detection"
        severity = "high"
    strings:
        $s1 = "QEMU" nocase
        $s2 = "qemu-ga" ascii
        $s3 = "Bochs" nocase
        $cpuid = {0F A2}
    condition:
        any of ($s*) or $cpuid
}

rule AntiVM_HyperV {
    meta:
        description = "Hyper-V detection"
        severity = "high"
    strings:
        $s1 = "Hyper-V" nocase
        $s2 = "vmicheartbeat" ascii
        $s3 = "vmicshutdown" ascii
    condition:
        any of them
}

rule AntiVM_Xen {
    meta:
        description = "Xen detection"
        severity = "high"
    strings:
        $s1 = "Xen" nocase
        $s2 = "xenservice" ascii
        $s3 = "XenVMM" ascii
    condition:
        any of them
}

rule AntiVM_Sandbox_Generic {
    meta:
        description = "Generic sandbox detection"
        severity = "high"
    strings:
        $s1 = "sandbox" nocase
        $s2 = "malware" nocase
        $s3 = "virus" nocase
        $s4 = "sample" nocase
        $s5 = "cuckoomon" ascii
        $s6 = "SbieDll" ascii
    condition:
        2 of them
}

rule AntiVM_Wine {
    meta:
        description = "Wine detection"
        severity = "medium"
    strings:
        $s1 = "wine" nocase
        $api = "wine_get_version" ascii
        $dll = "ntdll.dll" ascii
    condition:
        any of ($s*) or $api
}

rule AntiVM_Registry_Check {
    meta:
        description = "VM detection via registry"
        severity = "high"
    strings:
        $reg1 = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0" ascii
        $reg2 = "SYSTEM\\CurrentControlSet\\Enum\\IDE" ascii
        $reg3 = "SOFTWARE\\VMware" ascii
        $reg4 = "SOFTWARE\\Oracle\\VirtualBox" ascii
    condition:
        any of them
}

rule AntiVM_MAC_Check {
    meta:
        description = "VM detection via MAC address"
        severity = "high"
    strings:
        $mac1 = "00:0C:29" ascii
        $mac2 = "00:50:56" ascii
        $mac3 = "08:00:27" ascii
        $mac4 = "00:1C:14" ascii
    condition:
        any of them
}

rule AntiVM_Process_Check {
    meta:
        description = "VM detection via process enumeration"
        severity = "high"
    strings:
        $s1 = "vmtoolsd.exe" nocase
        $s2 = "VBoxService.exe" nocase
        $s3 = "VBoxTray.exe" nocase
        $s4 = "xenservice.exe" nocase
        $api = "CreateToolhelp32Snapshot" ascii
    condition:
        2 of ($s*) or $api
}

rule Obfuscation_String_Stack {
    meta:
        description = "Stack-based string obfuscation"
        severity = "medium"
    strings:
        $stack1 = {C6 45 ?? ?? C6 45 ?? ?? C6 45 ?? ??}
        $stack2 = {66 C7 45 ?? ?? ?? 66 C7 45 ?? ?? ??}
    condition:
        any of them
}

rule Obfuscation_XOR_Loop {
    meta:
        description = "XOR decryption loop"
        severity = "medium"
    strings:
        $xor1 = {30 ?? 4? E? F?}
        $xor2 = {32 ?? 4? E? F?}
        $xor3 = {80 3? ?? ?? 0F 84}
    condition:
        any of them
}

rule Obfuscation_API_Hashing {
    meta:
        description = "API name hashing"
        severity = "high"
    strings:
        $ror = {C1 C? 0D}
        $hash = {3D ?? ?? ?? ?? 74}
    condition:
        $ror and $hash
}

rule Obfuscation_Base64_Decode {
    meta:
        description = "Base64 decoding routine"
        severity = "low"
    strings:
        $alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" ascii
        $decode = {83 E0 3F}
    condition:
        $alphabet or $decode
}

rule Obfuscation_RC4 {
    meta:
        description = "RC4 encryption/decryption"
        severity = "medium"
    strings:
        $sbox = {C6 84 ?? ?? ?? ?? ?? 00}
        $swap = {8A ?? 8A ?? 88 ?? 88 ??}
    condition:
        $sbox and $swap
}

rule Obfuscation_AES {
    meta:
        description = "AES encryption constants"
        severity = "medium"
    strings:
        $sbox = {63 7C 77 7B F2 6B 6F C5}
        $rcon = {01 02 04 08 10 20 40 80}
    condition:
        any of them
}

rule Packed_UPX {
    meta:
        description = "UPX packed"
        severity = "medium"
    strings:
        $upx1 = "UPX0" ascii
        $upx2 = "UPX1" ascii
        $upx3 = "UPX!" ascii
    condition:
        any of them
}

rule Packed_Themida {
    meta:
        description = "Themida/WinLicense packed"
        severity = "high"
    strings:
        $s1 = ".themida" ascii
        $s2 = "Themida" ascii
        $s3 = "WinLicense" ascii
    condition:
        any of them
}

rule Packed_VMProtect {
    meta:
        description = "VMProtect packed"
        severity = "high"
    strings:
        $s1 = ".vmp0" ascii
        $s2 = ".vmp1" ascii
        $s3 = "VMProtect" ascii
    condition:
        any of them
}

rule Packed_Enigma {
    meta:
        description = "Enigma Protector packed"
        severity = "high"
    strings:
        $s1 = ".enigma1" ascii
        $s2 = ".enigma2" ascii
        $s3 = "ENIGMA" ascii
    condition:
        any of them
}

rule Process_Hollowing {
    meta:
        description = "Process hollowing technique"
        severity = "critical"
    strings:
        $api1 = "NtUnmapViewOfSection" ascii
        $api2 = "ZwUnmapViewOfSection" ascii
        $api3 = "VirtualAllocEx" ascii
        $api4 = "WriteProcessMemory" ascii
        $api5 = "SetThreadContext" ascii
    condition:
        (any of ($api1, $api2)) and 2 of ($api3, $api4, $api5)
}

rule DLL_Injection {
    meta:
        description = "DLL injection technique"
        severity = "critical"
    strings:
        $api1 = "VirtualAllocEx" ascii
        $api2 = "WriteProcessMemory" ascii
        $api3 = "CreateRemoteThread" ascii
        $api4 = "LoadLibraryA" ascii
        $api5 = "LoadLibraryW" ascii
    condition:
        3 of them
}

rule APC_Injection {
    meta:
        description = "APC injection technique"
        severity = "critical"
    strings:
        $api1 = "QueueUserAPC" ascii
        $api2 = "NtQueueApcThread" ascii
        $api3 = "VirtualAllocEx" ascii
    condition:
        any of ($api1, $api2) and $api3
}
