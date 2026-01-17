/*
    Packers and Crypters Detection
    Executable obfuscation, protection, and packing tools
*/

rule Packer_UPX {
    meta:
        description = "UPX packed executable"
        severity = "medium"
    strings:
        $upx1 = "UPX0" ascii
        $upx2 = "UPX1" ascii
        $upx3 = "UPX!" ascii
        $upx4 = "UPX2" ascii
        $upx_sig = { 55 50 58 21 }
    condition:
        uint16(0) == 0x5A4D and (any of them)
}

rule Packer_ASPack {
    meta:
        description = "ASPack packed executable"
        severity = "medium"
    strings:
        $aspack = ".aspack" ascii
        $aspack2 = "ASPack" ascii
        $adata = ".adata" ascii
        $sig = { 60 E8 03 00 00 00 E9 EB }
    condition:
        uint16(0) == 0x5A4D and (any of them)
}

rule Packer_FSG {
    meta:
        description = "FSG packed executable"
        severity = "medium"
    strings:
        $fsg = "FSG" ascii
        $sig1 = { 87 25 ?? ?? ?? ?? 61 94 55 A4 B6 80 FF 13 }
        $sig2 = { BE ?? ?? ?? ?? BF ?? ?? ?? ?? EB 02 }
    condition:
        uint16(0) == 0x5A4D and (any of them)
}

rule Packer_PECompact {
    meta:
        description = "PECompact packed executable"
        severity = "medium"
    strings:
        $pec = "PEC2" ascii
        $pec2 = "PECompact2" ascii
        $sig = { B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and (any of them)
}

rule Packer_Themida {
    meta:
        description = "Themida protected executable"
        severity = "high"
    strings:
        $themida = "Themida" ascii nocase
        $oreans = "Oreans" ascii
        $winlicense = "WinLicense" ascii
        $section = ".themida" ascii
        $section2 = ".Themida" ascii
    condition:
        uint16(0) == 0x5A4D and (any of them)
}

rule Packer_VMProtect {
    meta:
        description = "VMProtect protected executable"
        severity = "high"
    strings:
        $vmp1 = ".vmp0" ascii
        $vmp2 = ".vmp1" ascii
        $vmp3 = "VMProtect" ascii
        $vmp4 = ".VMP0" ascii
        $vmp5 = ".VMP1" ascii
    condition:
        uint16(0) == 0x5A4D and (any of them)
}

rule Packer_Obsidium {
    meta:
        description = "Obsidium protected executable"
        severity = "high"
    strings:
        $obsidium = "Obsidium" ascii
        $sig = { EB 02 ?? ?? E8 25 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and (any of them)
}

rule Packer_Enigma {
    meta:
        description = "Enigma Protector"
        severity = "high"
    strings:
        $enigma = "Enigma" ascii
        $enigma2 = "ENIGMA" ascii
        $section = ".enigma" ascii
        $sig = { 45 6E 69 67 6D 61 20 }
    condition:
        uint16(0) == 0x5A4D and (any of them)
}

rule Packer_Armadillo {
    meta:
        description = "Armadillo protected executable"
        severity = "high"
    strings:
        $armadillo = "Armadillo" ascii
        $siliconrealms = "SiliconRealms" ascii
        $section = ".armd" ascii
    condition:
        uint16(0) == 0x5A4D and (any of them)
}

rule Packer_MPRESS {
    meta:
        description = "MPRESS packed executable"
        severity = "medium"
    strings:
        $mpress = "MPRESS" ascii
        $mpress1 = ".MPRESS1" ascii
        $mpress2 = ".MPRESS2" ascii
        $sig = { 60 E8 00 00 00 00 58 05 }
    condition:
        uint16(0) == 0x5A4D and (any of them)
}

rule Packer_NSPack {
    meta:
        description = "NSPack packed executable"
        severity = "medium"
    strings:
        $nspack = "nsPack" ascii
        $nspack2 = "NSPack" ascii
        $section = ".nsp0" ascii
        $section2 = ".nsp1" ascii
    condition:
        uint16(0) == 0x5A4D and (any of them)
}

rule Packer_PEtite {
    meta:
        description = "PEtite packed executable"
        severity = "medium"
    strings:
        $petite = "PEtite" ascii
        $section = ".petite" ascii
        $sig = { B8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 FF 35 }
    condition:
        uint16(0) == 0x5A4D and (any of them)
}

rule Packer_ConfuserEx {
    meta:
        description = "ConfuserEx protected .NET"
        severity = "high"
    strings:
        $confuser = "ConfuserEx" ascii
        $confuser2 = "Confuser" ascii
        $netguard = "NetGuard" ascii
        $attribute = "ConfusedByAttribute" ascii
    condition:
        uint16(0) == 0x5A4D and (any of them)
}

rule Packer_SmartAssembly {
    meta:
        description = "SmartAssembly protected .NET"
        severity = "medium"
    strings:
        $smart = "SmartAssembly" ascii
        $redgate = "RedGate" ascii
        $powered = "PoweredByAttribute" ascii
    condition:
        uint16(0) == 0x5A4D and (any of them)
}

rule Packer_Eazfuscator {
    meta:
        description = "Eazfuscator.NET protected"
        severity = "medium"
    strings:
        $eaz = "Eazfuscator" ascii
        $eaz2 = "EazfuscatorAttribute" ascii
        $section = ".eaz" ascii
    condition:
        uint16(0) == 0x5A4D and (any of them)
}

rule Packer_Babel {
    meta:
        description = "Babel Obfuscator .NET"
        severity = "medium"
    strings:
        $babel = "BabelAttribute" ascii
        $babel2 = "Babel.NET" ascii
        $babel3 = "babelobfuscator" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of them)
}

rule Packer_Dotfuscator {
    meta:
        description = "Dotfuscator protected .NET"
        severity = "medium"
    strings:
        $dotf = "Dotfuscator" ascii
        $dotf2 = "DotfuscatorAttribute" ascii
        $preemptive = "PreEmptive" ascii
    condition:
        uint16(0) == 0x5A4D and (any of them)
}

rule Crypter_Generic {
    meta:
        description = "Generic crypter indicators"
        severity = "high"
    strings:
        $decrypt = "decrypt" ascii nocase
        $stub = "stub" ascii nocase
        $loader = "loader" ascii nocase
        $runtime = "runtime" ascii nocase
        $memory = "memory" ascii nocase
        $inject = "inject" ascii nocase
        $fud = "FUD" ascii
    condition:
        uint16(0) == 0x5A4D and (3 of them)
}

rule Crypter_RunPE {
    meta:
        description = "RunPE crypter technique"
        severity = "critical"
    strings:
        $runpe = "RunPE" ascii nocase
        $api1 = "CreateProcess" ascii
        $api2 = "NtUnmapViewOfSection" ascii
        $api3 = "VirtualAllocEx" ascii
        $api4 = "WriteProcessMemory" ascii
        $api5 = "SetThreadContext" ascii
        $api6 = "ResumeThread" ascii
    condition:
        uint16(0) == 0x5A4D and ($runpe or (4 of ($api*)))
}

rule Packer_Costura {
    meta:
        description = "Costura embedded assembly"
        severity = "medium"
    strings:
        $costura = "Costura" ascii
        $costura2 = "costura." ascii
        $compress = "costura.dll.compressed" ascii
        $resource = "costura.metadata" ascii
    condition:
        uint16(0) == 0x5A4D and (any of them)
}

rule Packer_BoxedApp {
    meta:
        description = "BoxedApp Packer"
        severity = "medium"
    strings:
        $boxedapp = "BoxedApp" ascii
        $softanics = "Softanics" ascii
        $section = ".bxpck" ascii
    condition:
        uint16(0) == 0x5A4D and (any of them)
}

rule Packer_Morphine {
    meta:
        description = "Morphine packer"
        severity = "medium"
    strings:
        $morphine = "Morphine" ascii
        $sig = { 83 EC ?? E8 ?? ?? ?? ?? 83 C4 }
    condition:
        uint16(0) == 0x5A4D and (any of them)
}

rule Packer_Yoda {
    meta:
        description = "Yoda's Crypter"
        severity = "medium"
    strings:
        $yoda = "Yoda" ascii
        $crypter = "Crypter" ascii
        $section = ".yc" ascii
        $sig = { 60 E8 00 00 00 00 5D 81 ED }
    condition:
        uint16(0) == 0x5A4D and (any of them)
}

rule Packer_Telock {
    meta:
        description = "Telock packer"
        severity = "medium"
    strings:
        $telock = "tElock" ascii
        $sig = { E9 ?? ?? ?? ?? 00 00 00 00 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and (any of them)
}

rule Packer_Molebox {
    meta:
        description = "Molebox packer"
        severity = "medium"
    strings:
        $molebox = "MoleBox" ascii
        $mole = ".mole" ascii
        $sig = { E8 00 00 00 00 60 E8 }
    condition:
        uint16(0) == 0x5A4D and (any of them)
}

rule Packer_Suspicious_Entropy {
    meta:
        description = "High entropy packed section"
        severity = "medium"
    strings:
        $mz = { 4D 5A }
        $pe = { 50 45 00 00 }
    condition:
        $mz at 0 and $pe and math.entropy(0, filesize) > 7.0
}

