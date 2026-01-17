/*
    Advanced Ransomware Detection Rules
    Comprehensive coverage of ransomware families and behaviors
*/

rule Ransomware_LockBit_3 {
    meta:
        description = "LockBit 3.0 ransomware"
        severity = "critical"
        author = "AI-Cerberus"
    strings:
        $s1 = "LockBit 3.0" ascii wide
        $s2 = ".lockbit" ascii
        $api1 = "CryptGenRandom" ascii
        $api2 = "CryptAcquireContext" ascii
        $api3 = "BCryptGenRandom" ascii
        $enc = {48 8B ?? 48 33 ?? 48 89 ?? 48 8B}
        $ransom = "Restore-My-Files.txt" ascii wide
        $onion = ".onion" ascii
    condition:
        uint16(0) == 0x5A4D and
        (any of ($s*) or (2 of ($api*) and $enc) or ($ransom and $onion))
}

rule Ransomware_BlackCat_ALPHV {
    meta:
        description = "BlackCat/ALPHV ransomware (Rust-based)"
        severity = "critical"
    strings:
        $rust1 = "std::panicking" ascii
        $rust2 = "core::fmt" ascii
        $s1 = "access-key" ascii
        $s2 = "--child" ascii
        $s3 = "RECOVER-" ascii
        $cfg = {48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B}
        $ext = /\.[a-z0-9]{6,8}/ ascii
    condition:
        uint16(0) == 0x5A4D and
        (all of ($rust*) and any of ($s*)) or ($cfg and $ext)
}

rule Ransomware_Hive_V2 {
    meta:
        description = "Hive ransomware v2"
        severity = "critical"
    strings:
        $s1 = "hive" nocase
        $s2 = "HOW_TO_DECRYPT" ascii
        $api1 = "RtlGenRandom" ascii
        $api2 = "SystemFunction036" ascii
        $go1 = "main.main" ascii
        $go2 = "encryptor" ascii
        $key = {48 8D ?? 24 ?? 48 89 ?? 24 ?? 4C 8D}
    condition:
        uint16(0) == 0x5A4D and
        (any of ($s*) or (any of ($api*) and any of ($go*)) or $key)
}

rule Ransomware_Royal {
    meta:
        description = "Royal ransomware"
        severity = "critical"
    strings:
        $s1 = "Royal" ascii
        $s2 = "README.TXT" ascii
        $api1 = "GetLogicalDrives" ascii
        $api2 = "FindFirstFileW" ascii
        $api3 = "GetDriveTypeW" ascii
        $enc = {41 8B ?? 41 33 ?? 89 ?? 24}
        $ext = ".royal" ascii
    condition:
        uint16(0) == 0x5A4D and
        (($s1 and $s2) or (all of ($api*) and $enc) or $ext)
}

rule Ransomware_Play {
    meta:
        description = "Play ransomware"
        severity = "critical"
    strings:
        $s1 = "PLAY" ascii
        $s2 = "ReadMe.txt" ascii
        $api1 = "CryptEncrypt" ascii
        $api2 = "CryptDestroyKey" ascii
        $thread = {6A 00 68 ?? ?? ?? ?? 6A 00 6A 00 6A 00}
        $ext = ".play" ascii
    condition:
        uint16(0) == 0x5A4D and
        (($s1 and $s2) or (all of ($api*) and $thread) or $ext)
}

rule Ransomware_Vice_Society {
    meta:
        description = "Vice Society ransomware"
        severity = "critical"
    strings:
        $s1 = "ViceSociety" ascii
        $s2 = "!!! ALL YOUR FILES" ascii
        $api1 = "NtQueryInformationProcess" ascii
        $api2 = "RtlAdjustPrivilege" ascii
        $ps = "powershell" ascii nocase
        $del = "vssadmin delete shadows" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        (any of ($s*) or (any of ($api*) and ($ps or $del)))
}

rule Ransomware_BlackBasta {
    meta:
        description = "Black Basta ransomware"
        severity = "critical"
    strings:
        $s1 = "basta" nocase
        $s2 = "readme.txt" ascii nocase
        $api1 = "CreateFileMappingW" ascii
        $api2 = "MapViewOfFile" ascii
        $enc = {44 8B ?? 45 33 ?? 44 89}
        $ext = ".basta" ascii
        $onion = ".onion" ascii
    condition:
        uint16(0) == 0x5A4D and
        (any of ($s*) or (all of ($api*) and $enc) or ($ext and $onion))
}

rule Ransomware_Akira {
    meta:
        description = "Akira ransomware"
        severity = "critical"
    strings:
        $s1 = "akira" nocase
        $s2 = "akira_readme.txt" ascii
        $cpp1 = "std::exception" ascii
        $cpp2 = "std::runtime_error" ascii
        $api1 = "CryptStringToBinaryA" ascii
        $ext = ".akira" ascii
    condition:
        uint16(0) == 0x5A4D and
        (any of ($s*) or (all of ($cpp*) and $api1) or $ext)
}

rule Ransomware_Rhysida {
    meta:
        description = "Rhysida ransomware"
        severity = "critical"
    strings:
        $s1 = "Rhysida" ascii
        $s2 = "CriticalBreachDetected" ascii
        $pdf = "PDF-" ascii
        $api1 = "ChaCha20" ascii
        $api2 = "RSA" ascii
        $ext = ".rhysida" ascii
    condition:
        uint16(0) == 0x5A4D and
        (any of ($s*) or ($pdf and any of ($api*)) or $ext)
}

rule Ransomware_Medusa_Locker {
    meta:
        description = "MedusaLocker ransomware"
        severity = "critical"
    strings:
        $s1 = "Medusa" ascii nocase
        $s2 = "!!!HOW_TO_DECRYPT!!!" ascii
        $api1 = "BCryptEncrypt" ascii
        $api2 = "BCryptGenerateSymmetricKey" ascii
        $mutex = "Global\\MedusaLocker" ascii
        $kill = "taskkill" ascii
    condition:
        uint16(0) == 0x5A4D and
        (any of ($s*) or all of ($api*) or ($mutex and $kill))
}

rule Ransomware_Phobos {
    meta:
        description = "Phobos ransomware family"
        severity = "critical"
    strings:
        $s1 = "phobos" nocase
        $s2 = "Eking" ascii
        $s3 = "Eight" ascii
        $api1 = "CryptGenKey" ascii
        $api2 = "CryptExportKey" ascii
        $marker = {AE 00 00 00}
        $ext = /\.[a-z]{4,8}$/ ascii
    condition:
        uint16(0) == 0x5A4D and
        (any of ($s*) or (all of ($api*) and $marker))
}

rule Ransomware_Clop {
    meta:
        description = "Clop/Cl0p ransomware"
        severity = "critical"
    strings:
        $s1 = "Clop" ascii
        $s2 = "Cl0p" ascii
        $s3 = "!_READ_ME" ascii
        $api1 = "CryptAcquireContextW" ascii
        $api2 = "CryptGenRandom" ascii
        $ext = ".Clop" ascii
        $kill1 = "SQLAGENT" ascii
        $kill2 = "MSSQL" ascii
    condition:
        uint16(0) == 0x5A4D and
        (any of ($s*) or (all of ($api*) and any of ($kill*)) or $ext)
}

rule Ransomware_Cuba {
    meta:
        description = "Cuba ransomware"
        severity = "critical"
    strings:
        $s1 = "CUBA" ascii
        $s2 = "!!FAQ for Decryption!!" ascii
        $api1 = "RtlCompressBuffer" ascii
        $api2 = "CryptImportKey" ascii
        $ext = ".cuba" ascii
        $mutex = "YOUROFF" ascii
    condition:
        uint16(0) == 0x5A4D and
        (any of ($s*) or all of ($api*) or ($ext and $mutex))
}

rule Ransomware_AvosLocker {
    meta:
        description = "AvosLocker ransomware"
        severity = "critical"
    strings:
        $s1 = "AvosLocker" ascii
        $s2 = "GET_YOUR_FILES_BACK" ascii
        $api1 = "GetLogicalDriveStringsW" ascii
        $api2 = "SetFileAttributesW" ascii
        $ext = ".avos" ascii
        $safe = "safe mode" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        (any of ($s*) or (all of ($api*) and $safe) or $ext)
}

rule Ransomware_Yanluowang {
    meta:
        description = "Yanluowang ransomware"
        severity = "critical"
    strings:
        $s1 = "yanluowang" ascii nocase
        $s2 = "README.txt" ascii
        $api1 = "CryptBinaryToStringA" ascii
        $api2 = "CryptStringToBinaryA" ascii
        $cpp = ".?AV" ascii
        $ext = ".yanluowang" ascii
    condition:
        uint16(0) == 0x5A4D and
        (any of ($s*) or (all of ($api*) and $cpp) or $ext)
}

rule Ransomware_Behavior_VSS_Delete {
    meta:
        description = "Ransomware behavior - Shadow copy deletion"
        severity = "high"
    strings:
        $vss1 = "vssadmin delete shadows" ascii nocase
        $vss2 = "vssadmin.exe Delete Shadows" ascii nocase
        $vss3 = "wmic shadowcopy delete" ascii nocase
        $vss4 = "/all /quiet" ascii nocase
        $ps1 = "Get-WmiObject Win32_Shadowcopy" ascii nocase
        $ps2 = "Remove-WmiObject" ascii nocase
        $bcdedit = "bcdedit /set {default} recoveryenabled no" ascii nocase
    condition:
        any of them
}

rule Ransomware_Behavior_Service_Stop {
    meta:
        description = "Ransomware behavior - Service termination"
        severity = "high"
    strings:
        $net1 = "net stop" ascii nocase
        $sc1 = "sc stop" ascii nocase
        $sc2 = "sc delete" ascii nocase
        $kill1 = "taskkill /f /im" ascii nocase
        $svc1 = "SQLServer" ascii nocase
        $svc2 = "Exchange" ascii nocase
        $svc3 = "veeam" ascii nocase
        $svc4 = "backup" ascii nocase
    condition:
        (any of ($net*, $sc*, $kill*)) and (any of ($svc*))
}

rule Ransomware_Behavior_Encryption_API {
    meta:
        description = "Ransomware behavior - Cryptographic API usage"
        severity = "medium"
    strings:
        $capi1 = "CryptEncrypt" ascii
        $capi2 = "CryptGenKey" ascii
        $capi3 = "CryptAcquireContext" ascii
        $capi4 = "CryptImportKey" ascii
        $bcrypt1 = "BCryptEncrypt" ascii
        $bcrypt2 = "BCryptGenerateSymmetricKey" ascii
        $openssl1 = "EVP_EncryptInit" ascii
        $openssl2 = "EVP_CIPHER_CTX_new" ascii
        $file1 = "CreateFileW" ascii
        $file2 = "WriteFile" ascii
        $file3 = "FindFirstFileW" ascii
    condition:
        uint16(0) == 0x5A4D and
        ((2 of ($capi*)) or (2 of ($bcrypt*)) or (2 of ($openssl*))) and (2 of ($file*))
}

rule Ransomware_Behavior_File_Enum {
    meta:
        description = "Ransomware behavior - Aggressive file enumeration"
        severity = "medium"
    strings:
        $api1 = "FindFirstFileW" ascii
        $api2 = "FindNextFileW" ascii
        $api3 = "GetLogicalDrives" ascii
        $api4 = "GetDriveTypeW" ascii
        $ext1 = ".doc" ascii
        $ext2 = ".xls" ascii
        $ext3 = ".pdf" ascii
        $ext4 = ".sql" ascii
        $ext5 = ".mdb" ascii
        $ext6 = ".bak" ascii
        $skip1 = "Windows" ascii
        $skip2 = "Program Files" ascii
    condition:
        uint16(0) == 0x5A4D and
        all of ($api*) and 3 of ($ext*) and any of ($skip*)
}

rule Ransomware_Ransom_Note_Patterns {
    meta:
        description = "Common ransomware note patterns"
        severity = "high"
    strings:
        $n1 = "Your files have been encrypted" ascii nocase wide
        $n2 = "All your important files" ascii nocase wide
        $n3 = "decrypt your files" ascii nocase wide
        $n4 = "pay the ransom" ascii nocase wide
        $n5 = "bitcoin" ascii nocase wide
        $n6 = "BTC" ascii
        $n7 = ".onion" ascii
        $n8 = "tor browser" ascii nocase wide
        $n9 = "unique ID" ascii nocase wide
        $n10 = "DO NOT" ascii wide
        $n11 = "personal key" ascii nocase wide
        $email = /[a-zA-Z0-9._%+-]+@(protonmail|tutanota|onionmail|cock\.li)/ ascii
        $btc = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ ascii
    condition:
        3 of ($n*) or $email or $btc
}

rule Ransomware_Double_Extortion {
    meta:
        description = "Double extortion ransomware indicators"
        severity = "critical"
    strings:
        $exfil1 = "upload" ascii nocase
        $exfil2 = "exfiltrate" ascii nocase
        $exfil3 = "leak" ascii nocase
        $exfil4 = "publish" ascii nocase
        $exfil5 = "stolen data" ascii nocase wide
        $threat1 = "publicly available" ascii nocase wide
        $threat2 = "sold to competitors" ascii nocase wide
        $threat3 = "publish the data" ascii nocase wide
        $site1 = ".onion" ascii
        $site2 = "blog" ascii
        $time = /\d{1,3}\s*(hours?|days?)/ ascii nocase
    condition:
        2 of ($exfil*) or 2 of ($threat*) or (any of ($site*) and $time)
}
