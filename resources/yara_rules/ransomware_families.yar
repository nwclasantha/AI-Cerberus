/*
    Ransomware Family Detection Rules
    Covers: LockBit, Conti, REvil, Ryuk, WannaCry, etc.
*/

rule LockBit_2_0 {
    meta:
        description = "LockBit 2.0 ransomware"
        severity = "critical"
    strings:
        $s1 = "LockBit" ascii
        $s2 = ".lockbit" ascii
        $s3 = "Restore-My-Files.txt" ascii
        $s4 = "All your files have been encrypted" ascii
        $s5 = {4C 6F 63 6B 42 69 74}
    condition:
        2 of them
}

rule LockBit_3_0 {
    meta:
        description = "LockBit 3.0/Black ransomware"
        severity = "critical"
    strings:
        $s1 = "LockBit 3.0" ascii
        $s2 = "LockBit Black" ascii
        $s3 = ".lockbit3" ascii
        $note = "README.txt" ascii
    condition:
        any of ($s*) or ($note and $s3)
}

rule Conti_Ransomware {
    meta:
        description = "Conti ransomware"
        severity = "critical"
    strings:
        $s1 = "CONTI" ascii
        $s2 = ".CONTI" ascii
        $s3 = "CONTI_README.txt" ascii
        $s4 = "All of your files are currently encrypted" ascii
        $mutex = "hsdfasd9" ascii
    condition:
        2 of them
}

rule REvil_Sodinokibi {
    meta:
        description = "REvil/Sodinokibi ransomware"
        severity = "critical"
    strings:
        $s1 = "sodinokibi" nocase
        $s2 = "REvil" ascii
        $s3 = "-readme.txt" ascii
        $s4 = "Welcome. Again" ascii
        $cfg = "exp" ascii
    condition:
        2 of them
}

rule Ryuk_Ransomware {
    meta:
        description = "Ryuk ransomware"
        severity = "critical"
    strings:
        $s1 = "RYUK" ascii
        $s2 = ".RYK" ascii
        $s3 = "RyukReadMe.html" ascii
        $s4 = "balance of shadow universe" ascii
        $hermes = "HERMES" ascii
    condition:
        2 of ($s*) or $hermes
}

rule WannaCry_Ransomware {
    meta:
        description = "WannaCry ransomware"
        severity = "critical"
    strings:
        $s1 = "WannaCry" ascii
        $s2 = "WanaCrypt0r" ascii
        $s3 = ".WNCRY" ascii
        $s4 = "@WanaDecryptor@" ascii
        $s5 = "tasksche.exe" ascii
        $killswitch = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii
    condition:
        2 of them
}

rule Maze_Ransomware {
    meta:
        description = "Maze ransomware"
        severity = "critical"
    strings:
        $s1 = "MAZE" ascii
        $s2 = "ChaCha" ascii
        $s3 = "DECRYPT-FILES.html" ascii
        $s4 = "maze-corp" ascii
    condition:
        2 of them
}

rule Egregor_Ransomware {
    meta:
        description = "Egregor ransomware"
        severity = "critical"
    strings:
        $s1 = "EGREGOR" ascii
        $s2 = "RECOVER-FILES.txt" ascii
        $s3 = "egregor news" ascii
        $sekhmet = "sekhmet" nocase
    condition:
        2 of ($s*) or $sekhmet
}

rule DarkSide_Ransomware {
    meta:
        description = "DarkSide ransomware"
        severity = "critical"
    strings:
        $s1 = "DarkSide" ascii
        $s2 = "README.txt" ascii
        $s3 = "darksidc" ascii
        $s4 = "Welcome to Dark" ascii
    condition:
        2 of them
}

rule BlackMatter_Ransomware {
    meta:
        description = "BlackMatter ransomware"
        severity = "critical"
    strings:
        $s1 = "BlackMatter" ascii
        $s2 = ".BlackMatter" ascii
        $s3 = "attention" ascii
        $cfg = {C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ??}
    condition:
        any of ($s*) or $cfg
}

rule Hive_Ransomware {
    meta:
        description = "Hive ransomware"
        severity = "critical"
    strings:
        $s1 = "HIVE" ascii
        $s2 = ".hive" ascii
        $s3 = "HOW_TO_DECRYPT.txt" ascii
        $s4 = "hive.go" ascii
        $go = "main.main" ascii
    condition:
        2 of ($s*) or ($go and any of ($s*))
}

rule BlackCat_ALPHV {
    meta:
        description = "BlackCat/ALPHV ransomware"
        severity = "critical"
    strings:
        $s1 = "ALPHV" ascii
        $s2 = "BlackCat" ascii
        $s3 = "RECOVER-FILES.txt" ascii
        $rust = "rust_panic" ascii
    condition:
        any of ($s*) or $rust
}

rule Babuk_Ransomware {
    meta:
        description = "Babuk ransomware"
        severity = "critical"
    strings:
        $s1 = "Babuk" ascii
        $s2 = "BABYK" ascii
        $s3 = ".babyk" ascii
        $s4 = "How To Restore Your Files" ascii
    condition:
        2 of them
}

rule Avaddon_Ransomware {
    meta:
        description = "Avaddon ransomware"
        severity = "critical"
    strings:
        $s1 = "Avaddon" ascii
        $s2 = ".avdn" ascii
        $s3 = "readme-avaddon" ascii
        $xor = {33 C0 8A 04 01 32 04 02}
    condition:
        any of ($s*) or $xor
}

rule NetWalker_Ransomware {
    meta:
        description = "NetWalker/Mailto ransomware"
        severity = "critical"
    strings:
        $s1 = "NetWalker" ascii
        $s2 = "Mailto" ascii
        $s3 = ".mailto" ascii
        $s4 = "Hi!" ascii
    condition:
        2 of them
}

rule Clop_Ransomware {
    meta:
        description = "Clop ransomware"
        severity = "critical"
    strings:
        $s1 = "Clop" ascii
        $s2 = "CLOP" ascii
        $s3 = ".Clop" ascii
        $s4 = "ClopReadMe.txt" ascii
        $s5 = "DON'T PANIC" ascii
    condition:
        2 of them
}

rule DoppelPaymer_Ransomware {
    meta:
        description = "DoppelPaymer ransomware"
        severity = "critical"
    strings:
        $s1 = "DoppelPaymer" ascii
        $s2 = ".doppeled" ascii
        $s3 = "dopple" ascii
        $bitpaymer = "BitPaymer" ascii
    condition:
        any of ($s*) or $bitpaymer
}

rule Ragnar_Locker {
    meta:
        description = "Ragnar Locker ransomware"
        severity = "critical"
    strings:
        $s1 = "RAGNAR" ascii
        $s2 = "ragnar_locker" ascii
        $s3 = "RGNR_" ascii
        $s4 = "---RAGNAR SECRET---" ascii
    condition:
        any of them
}

rule Phobos_Ransomware {
    meta:
        description = "Phobos ransomware"
        severity = "critical"
    strings:
        $s1 = "Phobos" ascii
        $s2 = ".phobos" ascii
        $s3 = ".eight" ascii
        $s4 = "info.txt" ascii
        $dharma = "dharma" nocase
    condition:
        2 of ($s*) or $dharma
}

rule Stop_Djvu_Ransomware {
    meta:
        description = "STOP/Djvu ransomware"
        severity = "critical"
    strings:
        $s1 = "STOP" ascii
        $s2 = "Djvu" ascii
        $s3 = "_readme.txt" ascii
        $s4 = ".djvu" ascii
        $s5 = ".rumba" ascii
        $s6 = ".tro" ascii
    condition:
        2 of them
}

rule GandCrab_Ransomware {
    meta:
        description = "GandCrab ransomware"
        severity = "critical"
    strings:
        $s1 = "GandCrab" ascii
        $s2 = "GANDCRAB" ascii
        $s3 = "-DECRYPT.txt" ascii
        $s4 = "KRAB" ascii
    condition:
        2 of them
}

rule Petya_NotPetya {
    meta:
        description = "Petya/NotPetya ransomware"
        severity = "critical"
    strings:
        $s1 = "PETYA" ascii
        $s2 = "NotPetya" ascii
        $s3 = "wowsmith123456" ascii
        $mbr = {EB 3F 90 4E 54 46 53}
    condition:
        any of ($s*) or $mbr
}

rule LockerGoga_Ransomware {
    meta:
        description = "LockerGoga ransomware"
        severity = "critical"
    strings:
        $s1 = "LockerGoga" ascii
        $s2 = "README-NOW.txt" ascii
        $s3 = "ciph" ascii
        $cert = {30 82 ?? ?? 30 82 ?? ??}
    condition:
        any of ($s*) or $cert
}

rule MegaCortex_Ransomware {
    meta:
        description = "MegaCortex ransomware"
        severity = "critical"
    strings:
        $s1 = "MegaCortex" ascii
        $s2 = "!!!_READ-ME_!!!.txt" ascii
        $s3 = "YOURFILES" ascii
    condition:
        2 of them
}

rule Cuba_Ransomware {
    meta:
        description = "Cuba ransomware"
        severity = "critical"
    strings:
        $s1 = "CUBA" ascii
        $s2 = ".cuba" ascii
        $s3 = "!!FAQ for Decryption!!.txt" ascii
    condition:
        2 of them
}
