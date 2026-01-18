/*
    Detailed Ransomware Family Detection
    Specific ransomware variants and behaviors
*/

rule Ransomware_LockBit_3 {
    meta:
        description = "LockBit 3.0 ransomware"
        severity = "critical"
    strings:
        $s1 = "LockBit" ascii nocase
        $s2 = "lockbit" ascii nocase
        $s3 = "LockBit Black" ascii nocase
        $note = "Restore-My-Files.txt" ascii nocase
        $ext = ".lockbit" ascii nocase
        $mutex = "Global\\" ascii
    condition:
        uint16(0) == 0x5A4D and ((any of ($s*)) or ($note and $ext) or ($mutex and any of ($s*)))
}

rule Ransomware_BlackCat_ALPHV {
    meta:
        description = "BlackCat/ALPHV ransomware"
        severity = "critical"
    strings:
        $s1 = "BlackCat" ascii nocase
        $s2 = "ALPHV" ascii nocase
        $rust = "Rust" ascii
        $note = "RECOVER-" ascii
        $ext1 = ".cat" ascii nocase
        $ext2 = ".alphv" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ((any of ($s*)) or $rust and any of ($note, $ext1, $ext2))
}

rule Ransomware_Hive {
    meta:
        description = "Hive ransomware"
        severity = "critical"
    strings:
        $s1 = "Hive" ascii nocase
        $s2 = "HIVE" ascii
        $note = "HOW_TO_DECRYPT.txt" ascii
        $ext = ".hive" ascii nocase
        $key = "key.hive" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ((any of ($s*) and ($note or $ext)) or $key)
}

rule Ransomware_Royal {
    meta:
        description = "Royal ransomware"
        severity = "critical"
    strings:
        $s1 = "Royal" ascii nocase
        $s2 = "ROYAL" ascii
        $note = "README.TXT" ascii
        $ext = ".royal" ascii nocase
        $onion = ".onion" ascii
    condition:
        uint16(0) == 0x5A4D and ((any of ($s*)) and any of ($note, $ext, $onion))
}

rule Ransomware_BlackBasta {
    meta:
        description = "Black Basta ransomware"
        severity = "critical"
    strings:
        $s1 = "Black Basta" ascii nocase
        $s2 = "BlackBasta" ascii nocase
        $note = "readme.txt" ascii nocase
        $ext = ".basta" ascii nocase
        $chat = "chat" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ((any of ($s*)) or ($note and $ext and $chat))
}

rule Ransomware_Conti {
    meta:
        description = "Conti ransomware"
        severity = "critical"
    strings:
        $s1 = "Conti" ascii nocase
        $s2 = "CONTI" ascii
        $note = "CONTI_README.txt" ascii
        $ext = ".CONTI" ascii
        $mutex = "hsfjuukjz" ascii
    condition:
        uint16(0) == 0x5A4D and ((any of ($s*)) or ($note and $ext) or $mutex)
}

rule Ransomware_REvil_Sodinokibi {
    meta:
        description = "REvil/Sodinokibi ransomware"
        severity = "critical"
    strings:
        $s1 = "REvil" ascii nocase
        $s2 = "Sodinokibi" ascii nocase
        $note = "-readme.txt" ascii nocase
        $config = "pk" ascii
        $sub = "sub" ascii
        $pid = "pid" ascii
    condition:
        uint16(0) == 0x5A4D and ((any of ($s*)) or (3 of ($config, $sub, $pid, $note)))
}

rule Ransomware_Ryuk {
    meta:
        description = "Ryuk ransomware"
        severity = "critical"
    strings:
        $s1 = "Ryuk" ascii nocase
        $s2 = "RYUK" ascii
        $note = "RyukReadMe" ascii
        $ext = ".RYK" ascii
        $hermes = "HERMES" ascii
    condition:
        uint16(0) == 0x5A4D and ((any of ($s*)) or ($note and $ext) or $hermes)
}

rule Ransomware_Maze {
    meta:
        description = "Maze ransomware"
        severity = "critical"
    strings:
        $s1 = "Maze" ascii nocase
        $s2 = "MAZE" ascii
        $note = "DECRYPT-FILES.txt" ascii
        $mutex = "Global\\MsqDxv" ascii
        $shadow = "vssadmin" ascii
    condition:
        uint16(0) == 0x5A4D and ((any of ($s*) and $note) or $mutex or ($shadow and any of ($s*)))
}

rule Ransomware_DarkSide {
    meta:
        description = "DarkSide ransomware"
        severity = "critical"
    strings:
        $s1 = "DarkSide" ascii nocase
        $s2 = "darkside" ascii nocase
        $note = "README." ascii
        $affiliate = "affiliate" ascii nocase
        $blog = "blog" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ((any of ($s*)) and any of ($note, $affiliate, $blog))
}

rule Ransomware_Babuk {
    meta:
        description = "Babuk ransomware"
        severity = "critical"
    strings:
        $s1 = "Babuk" ascii nocase
        $s2 = "BABUK" ascii
        $note = "How To Restore Your Files.txt" ascii
        $ext = ".babyk" ascii nocase
        $linux = "ELF" ascii
    condition:
        ((any of ($s*)) and ($note or $ext)) or ($linux and any of ($s*))
}

rule Ransomware_Avaddon {
    meta:
        description = "Avaddon ransomware"
        severity = "critical"
    strings:
        $s1 = "Avaddon" ascii nocase
        $s2 = "AVADDON" ascii
        $note = "readme-warning" ascii
        $ext1 = ".avdn" ascii nocase
        $ext2 = ".AvD" ascii
    condition:
        uint16(0) == 0x5A4D and ((any of ($s*)) or ($note and any of ($ext1, $ext2)))
}

rule Ransomware_Clop {
    meta:
        description = "Clop ransomware"
        severity = "critical"
    strings:
        $s1 = "Clop" ascii nocase
        $s2 = "CLOP" ascii
        $note = "ClopReadMe.txt" ascii
        $ext = ".Clop" ascii
        $signature = "Don't Worry" ascii
    condition:
        uint16(0) == 0x5A4D and ((any of ($s*)) or ($note and $ext) or $signature)
}

rule Ransomware_Phobos {
    meta:
        description = "Phobos ransomware"
        severity = "critical"
    strings:
        $s1 = "Phobos" ascii nocase
        $s2 = "PHOBOS" ascii
        $note = "info.hta" ascii nocase
        $ext = ".phobos" ascii nocase
        $id = "[" ascii
    condition:
        uint16(0) == 0x5A4D and ((any of ($s*)) or ($note and $ext and $id))
}

rule Ransomware_Medusa {
    meta:
        description = "Medusa ransomware"
        severity = "critical"
    strings:
        $s1 = "Medusa" ascii nocase
        $s2 = "MEDUSA" ascii
        $note = "!!!READ_ME_MEDUSA!!!.txt" ascii
        $ext = ".MEDUSA" ascii
        $blog = "medusablog" ascii
    condition:
        uint16(0) == 0x5A4D and ((any of ($s*) and $note) or ($ext and $blog))
}

rule Ransomware_Play {
    meta:
        description = "Play ransomware"
        severity = "critical"
    strings:
        $s1 = "Play" ascii nocase
        $s2 = "PLAY" ascii
        $note = "ReadMe.txt" ascii
        $ext = ".PLAY" ascii
        $pattern = "PLAY" ascii
    condition:
        uint16(0) == 0x5A4D and (($s1 and $note) or ($s2 and $note) or ($ext and $pattern))
}

rule Ransomware_Vice_Society {
    meta:
        description = "Vice Society ransomware"
        severity = "critical"
    strings:
        $s1 = "Vice Society" ascii nocase
        $s2 = "ViceSociety" ascii nocase
        $note = "AllYFilesAE" ascii
        $ext = ".v-society" ascii nocase
        $blog = "vsociethok" ascii
    condition:
        uint16(0) == 0x5A4D and ((any of ($s*)) or ($note and any of ($ext, $blog)))
}

rule Ransomware_BianLian {
    meta:
        description = "BianLian ransomware"
        severity = "critical"
    strings:
        $s1 = "BianLian" ascii nocase
        $go = "Go build" ascii
        $note = "Look at this instruction.txt" ascii
        $ext = ".bianlian" ascii nocase
    condition:
        ($s1 or $go) and any of ($note, $ext)
}

rule Ransomware_Akira {
    meta:
        description = "Akira ransomware"
        severity = "critical"
    strings:
        $s1 = "Akira" ascii nocase
        $s2 = "AKIRA" ascii
        $note = "akira_readme.txt" ascii
        $ext = ".akira" ascii nocase
        $tor = ".onion" ascii
    condition:
        uint16(0) == 0x5A4D and ((any of ($s*)) and any of ($note, $ext, $tor))
}

rule Ransomware_Nokoyawa {
    meta:
        description = "Nokoyawa ransomware"
        severity = "critical"
    strings:
        $s1 = "Nokoyawa" ascii nocase
        $rust = "Rust" ascii
        $note = "NOKOYAWA" ascii
        $ext = ".NOKOYAWA" ascii
        $leak = "leak" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (($s1 or $rust) and any of ($note, $ext, $leak))
}

