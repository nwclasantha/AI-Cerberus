/*
    Data Destruction and Wiper Malware Detection
    Destructive malware and data wiping tools
*/

rule Wiper_Generic {
    meta:
        description = "Generic wiper malware"
        severity = "critical"
    strings:
        $wipe = "wipe" ascii nocase
        $destroy = "destroy" ascii nocase
        $overwrite = "overwrite" ascii nocase
        $mbr = "MBR" ascii
        $disk = "PhysicalDrive" ascii
        $zero = { 00 00 00 00 00 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and (any of ($wipe, $destroy, $overwrite)) and any of ($mbr, $disk, $zero)
}

rule Wiper_MBR_Overwrite {
    meta:
        description = "MBR overwriting wiper"
        severity = "critical"
    strings:
        $mbr1 = "\\\\.\\ PhysicalDrive0" ascii
        $mbr2 = "\\\\.\\PhysicalDrive" ascii
        $write = "WriteFile" ascii
        $seek = "SetFilePointer" ascii
        $raw = "CreateFile" ascii
        $zero = { 00 00 00 00 00 00 00 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and (any of ($mbr1, $mbr2)) and ($write and any of ($seek, $raw, $zero))
}

rule Wiper_Shamoon {
    meta:
        description = "Shamoon/Disttrack wiper"
        severity = "critical"
    strings:
        $s1 = "Shamoon" ascii nocase
        $s2 = "Disttrack" ascii nocase
        $s3 = "ArabianGulf" ascii nocase
        $driver = "RawDisk" ascii
        $eldos = "ElDos" ascii
        $flag = "burning flag" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ((any of ($s*)) or ($driver and $eldos) or $flag)
}

rule Wiper_NotPetya {
    meta:
        description = "NotPetya wiper"
        severity = "critical"
    strings:
        $s1 = "NotPetya" ascii nocase
        $s2 = "Petya" ascii nocase
        $mbr = "MBR" ascii
        $crypt = "encrypt" ascii nocase
        $boot = "CHKDSK" ascii
        $ransom = "ransom" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ((any of ($s*)) or ($mbr and $boot) or ($crypt and $ransom))
}

rule Wiper_HermeticWiper {
    meta:
        description = "HermeticWiper malware"
        severity = "critical"
    strings:
        $s1 = "HermeticWiper" ascii nocase
        $s2 = "Hermetic" ascii nocase
        $driver = "epmntdrv" ascii
        $compress = "EaseUS" ascii
        $partition = "partition" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ((any of ($s*)) or ($driver and any of ($compress, $partition)))
}

rule Wiper_WhisperGate {
    meta:
        description = "WhisperGate wiper"
        severity = "critical"
    strings:
        $s1 = "WhisperGate" ascii nocase
        $s2 = "Whisper" ascii nocase
        $mbr = "MBR" ascii
        $ransom = "ransom" ascii nocase
        $corrupt = "corrupt" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($s1 or ($s2 and any of ($mbr, $ransom, $corrupt)))
}

rule Wiper_CaddyWiper {
    meta:
        description = "CaddyWiper malware"
        severity = "critical"
    strings:
        $s1 = "CaddyWiper" ascii nocase
        $s2 = "Caddy" ascii nocase
        $disk = "PhysicalDrive" ascii
        $wipe = "wipe" ascii nocase
        $zero = "zero" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($s1 or ($s2 and any of ($disk, $wipe, $zero)))
}

rule Wiper_IsaacWiper {
    meta:
        description = "IsaacWiper malware"
        severity = "critical"
    strings:
        $s1 = "IsaacWiper" ascii nocase
        $s2 = "Isaac" ascii nocase
        $random = "random" ascii nocase
        $overwrite = "overwrite" ascii nocase
        $file = "file" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($s1 or ($s2 and $random and any of ($overwrite, $file)))
}

rule Wiper_DoubleZero {
    meta:
        description = "DoubleZero wiper"
        severity = "critical"
    strings:
        $s1 = "DoubleZero" ascii nocase
        $s2 = "Double Zero" ascii nocase
        $dotnet = "System.IO" ascii
        $wipe = "wipe" ascii nocase
        $zero = "zero" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ((any of ($s*)) or ($dotnet and any of ($wipe, $zero)))
}

rule Wiper_Agrius {
    meta:
        description = "Agrius wiper variants"
        severity = "critical"
    strings:
        $apostle = "Apostle" ascii nocase
        $deadwood = "Deadwood" ascii nocase
        $fantasy = "Fantasy" ascii nocase
        $wipe = "wipe" ascii nocase
        $destroy = "destroy" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($apostle, $deadwood, $fantasy)) and any of ($wipe, $destroy)
}

rule Wiper_ZeroCleare {
    meta:
        description = "ZeroCleare wiper"
        severity = "critical"
    strings:
        $s1 = "ZeroCleare" ascii nocase
        $driver = "EldoS RawDisk" ascii
        $soji = "Soji" ascii
        $dustman = "Dustman" ascii
    condition:
        uint16(0) == 0x5A4D and ($s1 or $driver or any of ($soji, $dustman))
}

rule Wiper_Ordinypt {
    meta:
        description = "Ordinypt wiper"
        severity = "critical"
    strings:
        $s1 = "Ordinypt" ascii nocase
        $german = "German" ascii nocase
        $wiper = "wiper" ascii nocase
        $fake = "fake" ascii nocase
        $ransom = "ransom" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($s1 or ($german and $wiper) or ($fake and $ransom))
}

rule Wiper_KillDisk {
    meta:
        description = "KillDisk wiper"
        severity = "critical"
    strings:
        $s1 = "KillDisk" ascii nocase
        $s2 = "Kill Disk" ascii nocase
        $disk = "disk" ascii nocase
        $wipe = "wipe" ascii nocase
        $mbr = "MBR" ascii
    condition:
        uint16(0) == 0x5A4D and ((any of ($s*)) or ($disk and $wipe and $mbr))
}

rule Wiper_Destover {
    meta:
        description = "Destover wiper (Sony)"
        severity = "critical"
    strings:
        $s1 = "Destover" ascii nocase
        $sony = "Sony" ascii nocase
        $rawdisk = "RawDisk" ascii
        $wipe = "wipe" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($s1 or ($sony and any of ($rawdisk, $wipe)))
}

rule Wiper_Meteor {
    meta:
        description = "Meteor wiper"
        severity = "critical"
    strings:
        $s1 = "Meteor" ascii nocase
        $iran = "Iran" ascii nocase
        $railway = "railway" ascii nocase
        $wipe = "wipe" ascii nocase
        $destroy = "destroy" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($s1 or ($iran and $railway)) and any of ($wipe, $destroy)
}

rule Wiper_SwiftSlicer {
    meta:
        description = "SwiftSlicer wiper"
        severity = "critical"
    strings:
        $s1 = "SwiftSlicer" ascii nocase
        $go = "Go build" ascii
        $wipe = "wipe" ascii nocase
        $policy = "Group Policy" ascii nocase
    condition:
        ($s1 or $go) and any of ($wipe, $policy)
}

rule Destruction_Shadow_Delete {
    meta:
        description = "Shadow copy deletion"
        severity = "critical"
    strings:
        $vss1 = "vssadmin" ascii nocase
        $vss2 = "delete shadows" ascii nocase
        $wmic = "wmic shadowcopy" ascii nocase
        $delete = "delete" ascii nocase
        $all = "/all" ascii nocase
    condition:
        (($vss1 and $vss2) or ($wmic and $delete)) and $all
}

rule Destruction_Backup_Delete {
    meta:
        description = "Backup deletion"
        severity = "critical"
    strings:
        $wbadmin = "wbadmin" ascii nocase
        $bcdedit = "bcdedit" ascii nocase
        $delete = "delete" ascii nocase
        $catalog = "catalog" ascii nocase
        $recovery = "recoveryenabled" ascii nocase
    condition:
        (($wbadmin and $delete and $catalog) or ($bcdedit and $recovery))
}

rule Destruction_Secure_Erase {
    meta:
        description = "Secure file erasure"
        severity = "high"
    strings:
        $sdelete = "SDelete" ascii nocase
        $cipher = "cipher" ascii nocase
        $dod = "DoD" ascii
        $pass = "pass" ascii nocase
        $overwrite = "overwrite" ascii nocase
        $shred = "shred" ascii nocase
    condition:
        ($sdelete or $cipher or $shred) and any of ($dod, $pass, $overwrite)
}

rule Destruction_Disk_Zero {
    meta:
        description = "Disk zeroing"
        severity = "critical"
    strings:
        $disk = "PhysicalDrive" ascii
        $raw = "\\\\.\\C:" ascii
        $zero = "zero" ascii nocase
        $format = "format" ascii nocase
        $wipe = "wipe" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($disk, $raw)) and any of ($zero, $format, $wipe)
}

