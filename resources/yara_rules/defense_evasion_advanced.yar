/*
    Advanced Defense Evasion Detection
    AV bypass, logging evasion, and security tool disabling
*/

rule Evasion_AMSI_Patch {
    meta:
        description = "AMSI memory patching"
        severity = "critical"
    strings:
        $amsi = "amsi.dll" ascii nocase
        $func = "AmsiScanBuffer" ascii
        $patch1 = { B8 57 00 07 80 C3 }  // mov eax, 0x80070057; ret
        $patch2 = { 31 C0 C3 }           // xor eax, eax; ret
        $patch3 = { 48 31 C0 C3 }        // xor rax, rax; ret
        $write = "VirtualProtect" ascii
    condition:
        uint16(0) == 0x5A4D and
        $amsi and $func and (any of ($patch*) or $write)
}

rule Evasion_ETW_Disable {
    meta:
        description = "ETW event logging disabled"
        severity = "critical"
    strings:
        $etw1 = "EtwEventWrite" ascii
        $etw2 = "NtTraceEvent" ascii
        $etw3 = "EtwEventRegister" ascii
        $ntdll = "ntdll.dll" ascii nocase
        $patch = { C3 }  // ret
        $api = "VirtualProtect" ascii
    condition:
        uint16(0) == 0x5A4D and
        (any of ($etw*) and $ntdll) and ($patch or $api)
}

rule Evasion_Windows_Defender_Disable {
    meta:
        description = "Windows Defender tampering"
        severity = "critical"
    strings:
        $def1 = "Windows Defender" ascii
        $def2 = "WinDefend" ascii
        $def3 = "MpCmdRun" ascii nocase
        $disable1 = "DisableRealtimeMonitoring" ascii
        $disable2 = "DisableBehaviorMonitoring" ascii
        $disable3 = "DisableBlockAtFirstSeen" ascii
        $stop = "sc stop" ascii nocase
        $reg = "Set-MpPreference" ascii
    condition:
        uint16(0) == 0x5A4D and
        (any of ($def*) and any of ($disable*, $stop, $reg))
}

rule Evasion_Firewall_Disable {
    meta:
        description = "Windows Firewall tampering"
        severity = "high"
    strings:
        $fw1 = "netsh firewall" ascii nocase
        $fw2 = "netsh advfirewall" ascii nocase
        $fw3 = "MpsSvc" ascii
        $disable = "disable" ascii nocase
        $off = "off" ascii nocase
        $rule = "rule" ascii nocase
        $add = "add" ascii nocase
        $allow = "allow" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        (any of ($fw*) and any of ($disable, $off)) or (any of ($fw*) and $rule and $add and $allow)
}

rule Evasion_Event_Log_Clear {
    meta:
        description = "Event log clearing"
        severity = "critical"
    strings:
        $wevtutil = "wevtutil" ascii nocase
        $clear = "cl" ascii nocase
        $security = "Security" ascii
        $system = "System" ascii
        $app = "Application" ascii
        $api = "ClearEventLogA" ascii
        $ps = "Clear-EventLog" ascii
    condition:
        uint16(0) == 0x5A4D and
        (($wevtutil and $clear) or $api or $ps) and any of ($security, $system, $app)
}

rule Evasion_Sysmon_Disable {
    meta:
        description = "Sysmon tampering"
        severity = "critical"
    strings:
        $sysmon = "Sysmon" ascii nocase
        $sysmon64 = "Sysmon64" ascii nocase
        $uninstall = "-u" ascii
        $stop = "sc stop" ascii nocase
        $delete = "sc delete" ascii nocase
        $driver = "SysmonDrv" ascii
    condition:
        uint16(0) == 0x5A4D and
        (any of ($sysmon, $sysmon64)) and (any of ($uninstall, $stop, $delete, $driver))
}

rule Evasion_Timestomp {
    meta:
        description = "File timestamp manipulation"
        severity = "high"
    strings:
        $api1 = "SetFileTime" ascii
        $api2 = "NtSetInformationFile" ascii
        $create = "CreationTime" ascii
        $modify = "LastWriteTime" ascii
        $access = "LastAccessTime" ascii
        $touch = "touch" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        (any of ($api*)) and (2 of ($create, $modify, $access))
}

rule Evasion_Indicator_Removal {
    meta:
        description = "Indicator removal from host"
        severity = "high"
    strings:
        $del1 = "DeleteFileA" ascii
        $del2 = "DeleteFileW" ascii
        $del3 = "SHFileOperation" ascii
        $wipe = { 00 00 00 00 00 00 00 00 }
        $secure = "secure delete" ascii nocase
        $shred = "shred" ascii nocase
        $temp = "\\Temp\\" ascii
        $prefetch = "\\Prefetch\\" ascii
    condition:
        uint16(0) == 0x5A4D and
        (any of ($del*) and any of ($wipe, $secure, $shred)) or (any of ($del*) and any of ($temp, $prefetch))
}

rule Evasion_Process_Name_Spoof {
    meta:
        description = "Process name/path spoofing"
        severity = "high"
    strings:
        $api1 = "NtQueryInformationProcess" ascii
        $api2 = "PEB" ascii
        $api3 = "ProcessParameters" ascii
        $image = "ImagePathName" ascii
        $cmd = "CommandLine" ascii
        $write = "WriteProcessMemory" ascii
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($api*) and any of ($image, $cmd)) or $write
}

rule Evasion_Parent_PID_Spoof {
    meta:
        description = "Parent PID spoofing"
        severity = "critical"
    strings:
        $api1 = "NtCreateUserProcess" ascii
        $api2 = "UpdateProcThreadAttribute" ascii
        $api3 = "InitializeProcThreadAttributeList" ascii
        $parent = "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS" ascii
        $handle = "OpenProcess" ascii
    condition:
        uint16(0) == 0x5A4D and
        (any of ($api1, $api2, $api3)) and ($parent or $handle)
}

rule Evasion_Ntdll_Unhooking {
    meta:
        description = "NTDLL unhooking"
        severity = "critical"
    strings:
        $ntdll = "ntdll.dll" ascii nocase
        $read = "ReadFile" ascii
        $map = "MapViewOfFile" ascii
        $copy = "memcpy" ascii
        $protect = "VirtualProtect" ascii
        $text = ".text" ascii
    condition:
        uint16(0) == 0x5A4D and
        $ntdll and (($read or $map) and $copy and $protect)
}

rule Evasion_EDR_Unhook {
    meta:
        description = "EDR API unhooking"
        severity = "critical"
    strings:
        $trampoline = { E9 }  // JMP
        $hook_check = { FF 25 }  // JMP indirect
        $syscall = { 0F 05 }    // syscall
        $api1 = "VirtualProtect" ascii
        $api2 = "NtProtectVirtualMemory" ascii
        $restore = "restore" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        (any of ($api*)) and (($trampoline or $hook_check) and $syscall)
}

rule Evasion_API_Hashing {
    meta:
        description = "API name hashing to evade detection"
        severity = "high"
    strings:
        $ror = { C1 C? 0D }  // ROR by 13
        $hash1 = { 8B ?? 83 ?? ?? 74 }  // Hash comparison
        $hash2 = { 3D ?? ?? ?? ?? 74 }  // CMP EAX, hash; JZ
        $kernel32 = "kernel32" ascii nocase
        $getproc = "GetProcAddress" ascii
    condition:
        uint16(0) == 0x5A4D and
        (any of ($ror, $hash1, $hash2)) and ($kernel32 and $getproc)
}

rule Evasion_String_Encryption {
    meta:
        description = "String encryption/obfuscation"
        severity = "medium"
    strings:
        $xor = { 80 3? ?? 74 ?? 80 ?? ?? }  // XOR decryption loop
        $rc4 = { 8A 04 01 32 04 02 88 04 01 }  // RC4 pattern
        $stack = { C6 45 ?? ?? C6 45 ?? ?? }  // Stack strings
        $decrypt = "decrypt" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (2 of them)
}

rule Evasion_Code_Signing_Bypass {
    meta:
        description = "Code signing bypass"
        severity = "high"
    strings:
        $sign1 = "CryptCATAdminAcquireContext" ascii
        $sign2 = "WinVerifyTrust" ascii
        $sign3 = "CertGetCertificateChain" ascii
        $patch = { 31 C0 C3 }  // xor eax, eax; ret
        $api = "GetProcAddress" ascii
    condition:
        uint16(0) == 0x5A4D and
        (any of ($sign*)) and ($patch or $api)
}

rule Evasion_Security_Tool_Kill {
    meta:
        description = "Security tool process termination"
        severity = "critical"
    strings:
        $term = "TerminateProcess" ascii
        $kill = "taskkill" ascii nocase
        $av1 = "MsMpEng" ascii nocase
        $av2 = "avp.exe" ascii nocase
        $av3 = "avgnt" ascii nocase
        $av4 = "bdagent" ascii nocase
        $av5 = "mcshield" ascii nocase
        $edr1 = "CrowdStrike" ascii nocase
        $edr2 = "SentinelOne" ascii nocase
        $edr3 = "CarbonBlack" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        (any of ($term, $kill)) and (2 of ($av*, $edr*))
}
