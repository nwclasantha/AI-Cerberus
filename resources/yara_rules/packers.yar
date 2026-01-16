/*
   Packer and Obfuscator Detection Rules
   Patterns for detecting packed and obfuscated executables
*/

rule Packer_UPX {
    meta:
        description = "UPX Packer"
        author = "Malware Analyzer Team"
        date = "2025-01-15"
        severity = "low"
        category = "packer"
    strings:
        $upx1 = "UPX0" ascii
        $upx2 = "UPX1" ascii
        $upx3 = "UPX!" ascii
        $upx4 = "UPX2" ascii
    condition:
        2 of them
}

rule Packer_Generic {
    meta:
        description = "Generic packer indicators"
        severity = "medium"
        category = "packer"
    strings:
        $stub1 = "This program cannot be run in DOS mode"
        $stub2 = "This program must be run under Win32"
        $virt1 = "VirtualAlloc" nocase
        $virt2 = "VirtualProtect" nocase
        $load1 = "LoadLibrary" nocase
        $load2 = "GetProcAddress" nocase
    condition:
        not ($stub1 or $stub2) and
        (any of ($virt*) and 2 of ($load*))
}

rule Runtime_Unpacker {
    meta:
        description = "Runtime unpacking behavior"
        severity = "high"
        category = "packer"
    strings:
        $alloc1 = "VirtualAlloc" nocase
        $alloc2 = "VirtualAllocEx" nocase
        $protect = "VirtualProtect" nocase
        $write = "WriteProcessMemory" nocase
        $thread = "CreateThread" nocase
        $remote = "CreateRemoteThread" nocase
    condition:
        (any of ($alloc*) and $protect) or
        ($write and ($thread or $remote))
}

rule Themida_Packer {
    meta:
        description = "Themida/WinLicense packer"
        severity = "medium"
        category = "packer"
    strings:
        $themida1 = "Themida" ascii
        $themida2 = "WinLicense" ascii
        $themida3 = "Oreans" ascii
        $vm1 = "VM detected" ascii
        $vm2 = "debugger detected" ascii
    condition:
        any of ($themida*) or 2 of ($vm*)
}

rule VMProtect_Packer {
    meta:
        description = "VMProtect packer"
        severity = "medium"
        category = "packer"
    strings:
        $vmp1 = ".vmp0" ascii
        $vmp2 = ".vmp1" ascii
        $vmp3 = "VMProtect" ascii
    condition:
        any of them
}

rule ASPack_Packer {
    meta:
        description = "ASPack packer"
        severity = "low"
        category = "packer"
    strings:
        $asp1 = "ASPack" ascii
        $asp2 = ".aspack" ascii
        $asp3 = ".adata" ascii
    condition:
        any of them
}

rule PECompact_Packer {
    meta:
        description = "PECompact packer"
        severity = "low"
        category = "packer"
    strings:
        $pec1 = "PECompact2" ascii
        $pec2 = "PEC2TO" ascii
        $pec3 = "PEC2" ascii
        $pec4 = "pec1" ascii
        $pec5 = "pec2" ascii
    condition:
        any of them
}

rule MPRESS_Packer {
    meta:
        description = "MPRESS packer"
        severity = "low"
        category = "packer"
    strings:
        $mpress1 = ".MPRESS1" ascii
        $mpress2 = ".MPRESS2" ascii
        $mpress3 = "MPRESS" ascii wide
    condition:
        any of them
}

rule High_Entropy_Section {
    meta:
        description = "High entropy section (possible packing/encryption)"
        severity = "medium"
        category = "obfuscation"
    strings:
        $sus1 = { 00 00 00 00 [4-8] FF FF FF FF }
        $sus2 = { 90 90 90 90 [4-8] C3 }
    condition:
        any of them or
        (filesize > 10KB and filesize < 10MB and #sus1 > 50) or
        #sus2 > 100
}

rule Dotnet_Obfuscator {
    meta:
        description = ".NET obfuscation indicators"
        severity = "medium"
        category = "obfuscation"
    strings:
        $dotnet = "mscoree.dll" nocase
        $confuser = "ConfuserEx" ascii
        $dotfuscator = "Dotfuscator" ascii
        $obfus1 = "<Module>" ascii
        $obfus2 = { 00 00 00 [2-4] 00 00 }
    condition:
        $dotnet and (any of ($confuser, $dotfuscator) or ($obfus1 and #obfus2 > 50))
}
