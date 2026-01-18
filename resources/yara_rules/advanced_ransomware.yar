/*
    Advanced Ransomware Detection Rules
    Comprehensive coverage of ransomware families and behaviors
*/

rule Ransomware_Generic_Crypto {
    meta:
        description = "Generic ransomware encryption patterns"
        severity = "critical"
    strings:
        $api1 = "CryptAcquireContext" ascii
        $api2 = "CryptGenKey" ascii
        $api3 = "CryptEncrypt" ascii
        $api4 = "CryptDecrypt" ascii
        $api5 = "CryptImportKey" ascii
        $ext1 = ".encrypted" ascii nocase
        $ext2 = ".locked" ascii nocase
        $ext3 = ".crypto" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (3 of ($api*) or (any of ($api*) and any of ($ext*)))
}

rule Ransomware_Note_Pattern {
    meta:
        description = "Ransomware ransom note patterns"
        severity = "critical"
    strings:
        $note1 = "your files have been encrypted" ascii nocase
        $note2 = "to decrypt your files" ascii nocase
        $note3 = "bitcoin" ascii nocase
        $note4 = "pay the ransom" ascii nocase
        $note5 = "unique key" ascii nocase
        $note6 = "tor browser" ascii nocase
        $note7 = "onion" ascii nocase
    condition:
        3 of them
}

rule Ransomware_Shadow_Delete {
    meta:
        description = "Shadow copy deletion (ransomware behavior)"
        severity = "critical"
    strings:
        $vss1 = "vssadmin delete shadows" ascii nocase
        $vss2 = "vssadmin.exe delete shadows" ascii nocase
        $vss3 = "wmic shadowcopy delete" ascii nocase
        $bcdedit = "bcdedit /set" ascii nocase
    condition:
        any of them
}

rule Ransomware_LockBit {
    meta:
        description = "LockBit ransomware"
        severity = "critical"
    strings:
        $s1 = "LockBit" ascii nocase
        $s2 = "LOCKBIT" ascii
        $note = "Restore-My-Files.txt" ascii
        $mutex = "Global\\lockbit" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (($s1 or $s2) or ($note and $mutex))
}

rule Ransomware_Conti {
    meta:
        description = "Conti ransomware"
        severity = "critical"
    strings:
        $s1 = "CONTI" ascii
        // UNUSED: $s2 = "conti_" ascii nocase
        $note = "readme.txt" ascii nocase
        $ext = ".CONTI" ascii
    condition:
        uint16(0) == 0x5A4D and (($s1 and $note) or $ext)
}

rule Ransomware_REvil {
    meta:
        description = "REvil/Sodinokibi ransomware"
        severity = "critical"
    strings:
        $s1 = "REvil" ascii nocase
        $s2 = "Sodinokibi" ascii nocase
        $cfg = "\"pk\":" ascii
        $cfg2 = "\"pid\":" ascii
    condition:
        uint16(0) == 0x5A4D and (($s1 or $s2) or ($cfg and $cfg2))
}

rule Ransomware_BlackCat {
    meta:
        description = "BlackCat/ALPHV ransomware"
        severity = "critical"
    strings:
        $s1 = "ALPHV" ascii
        $s2 = "BlackCat" ascii nocase
        $rust1 = "Rust" ascii
        $rust2 = ".rdata" ascii
        $ext = ".7z" ascii
    condition:
        uint16(0) == 0x5A4D and (($s1 or $s2) or (all of ($rust*) and $ext))
}
