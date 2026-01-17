/*
    Wiper and Destructive Malware Detection
    Detection of disk wipers, MBR destroyers, and data destruction malware
*/

rule Wiper_Generic_MBR {
    meta:
        description = "Generic MBR wiper"
        severity = "critical"
    strings:
        $mbr1 = { 00 7C 00 00 }  // MBR location
        $mbr2 = { 55 AA }        // MBR signature
        $phys = "\\\\.\\PhysicalDrive" ascii
        $rawdisk = "\\??\\PhysicalDrive" ascii
        $write = "WriteFile" ascii
        $seek = "SetFilePointer" ascii
        $zero = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and
        (any of ($phys, $rawdisk)) and $write and ($zero or $mbr1 or $mbr2)
}

rule Wiper_Shamoon {
    meta:
        description = "Shamoon/DistTrack wiper"
        severity = "critical"
    strings:
        $s1 = "RawDisk" ascii
        $s2 = "\\??\\ElRawDisk" ascii
        $s3 = "\\Device\\Harddisk" ascii
        $drv = "eldos" ascii nocase
        $wipe = { C7 00 00 00 00 00 }  // Write zeros pattern
        $service = "RasAutoService" ascii
    condition:
        uint16(0) == 0x5A4D and (2 of ($s*) or ($drv and $wipe) or $service)
}

rule Wiper_NotPetya {
    meta:
        description = "NotPetya/ExPetr wiper"
        severity = "critical"
    strings:
        $s1 = "perfc.dat" ascii
        $s2 = "dllhost.dat" ascii
        $psexec = "psexec" ascii nocase
        $wmic = "wmic" ascii nocase
        $mbr = "MBR" ascii
        $salsa = { 65 78 70 61 6E 64 20 33 32 2D 62 79 74 65 20 6B }  // expand 32-byte k
    condition:
        uint16(0) == 0x5A4D and (2 of ($s*) or ($mbr and $salsa) or ($psexec and $wmic))
}

rule Wiper_Petya {
    meta:
        description = "Petya ransomware/wiper family"
        severity = "critical"
    strings:
        $skull = "1nPU1" ascii
        $mbr = { FA 66 31 C0 8E D8 8E C0 8E D0 }  // MBR code
        $salsa = "salsa20" ascii nocase
        $drive = "\\\\.\\PhysicalDrive0" ascii
    condition:
        uint16(0) == 0x5A4D and (($skull or $salsa) or ($mbr and $drive))
}

rule Wiper_HermeticWiper {
    meta:
        description = "HermeticWiper (Ukraine 2022)"
        severity = "critical"
    strings:
        $s1 = "EPMNTDRV" ascii
        $s2 = "PhysicalDrive" ascii
        $cert = "Hermetica Digital" ascii
        $compress = "compress" ascii nocase
        $driver = ".sys" ascii
        $ioctl = "DeviceIoControl" ascii
    condition:
        uint16(0) == 0x5A4D and (($s1 and $s2) or $cert or (all of ($compress, $driver, $ioctl)))
}

rule Wiper_WhisperGate {
    meta:
        description = "WhisperGate wiper (Ukraine 2022)"
        severity = "critical"
    strings:
        $s1 = "WhisperGate" ascii
        $stage1 = "stage1.exe" ascii
        $stage2 = "stage2.exe" ascii
        $mbr = "\\\\.\\PhysicalDrive" ascii
        $ransom_fake = "Your hard drive has been corrupted" ascii
        $btc = "1AVNM68gj6PGPFcJuftKATa4WLnzg8fpfv" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($s*) or ($mbr and $ransom_fake) or $btc)
}

rule Wiper_CaddyWiper {
    meta:
        description = "CaddyWiper"
        severity = "critical"
    strings:
        $s1 = "CaddyWiper" ascii
        $drive = "C:\\" ascii
        $users = "C:\\Users" ascii
        $zero = { 00 00 00 00 00 00 00 00 }
        $del = "DeleteFileW" ascii
        $phys = "PhysicalDrive" ascii
    condition:
        uint16(0) == 0x5A4D and (3 of ($drive, $users, $zero, $del, $phys))
}

rule Wiper_IsaacWiper {
    meta:
        description = "IsaacWiper"
        severity = "critical"
    strings:
        $log = "IsaacWiper.log" ascii
        $drive = "\\\\.\\PHYSICALDRIVE" ascii
        $rand = "CryptGenRandom" ascii
        $write = "WriteFile" ascii
        $loop = "for" ascii
    condition:
        uint16(0) == 0x5A4D and ($log or ($drive and $rand and $write))
}

rule Wiper_DoubleZero {
    meta:
        description = "DoubleZero wiper"
        severity = "critical"
    strings:
        $net = ".NET" ascii
        $zero1 = { 00 00 00 00 }
        $del = "File.Delete" ascii
        $dir = "Directory.Delete" ascii
        $reg = "Registry" ascii
        $wipe = "wipe" ascii nocase
    condition:
        $net and 3 of ($zero1, $del, $dir, $reg, $wipe)
}

rule Wiper_AcidRain {
    meta:
        description = "AcidRain wiper (Viasat attack)"
        severity = "critical"
    strings:
        $s1 = "AcidRain" ascii
        $dev1 = "/dev/sd" ascii
        $dev2 = "/dev/mtd" ascii
        $dev3 = "/dev/block" ascii
        $dd = "dd" ascii
        $zero = "/dev/zero" ascii
        $urandom = "/dev/urandom" ascii
    condition:
        (uint32(0) == 0x464C457F) and  // ELF magic
        (any of ($dev*) and (any of ($zero, $urandom, $dd)))
}

rule Wiper_Industroyer {
    meta:
        description = "Industroyer/CrashOverride wiper component"
        severity = "critical"
    strings:
        $s1 = "haslo.dat" ascii
        $s2 = "iec104.dll" ascii
        $s3 = "61850.dll" ascii
        $scada = "SCADA" ascii nocase
        $iec = "IEC" ascii
        $wipe = { C6 00 00 C6 40 01 00 }  // Zero write
    condition:
        uint16(0) == 0x5A4D and (2 of ($s*) or ($scada and $iec) or $wipe)
}

rule Wiper_StoneDrill {
    meta:
        description = "StoneDrill wiper"
        severity = "critical"
    strings:
        $s1 = "StoneDrill" ascii
        $s2 = "Shamoon" ascii nocase
        $elrawdisk = "ElRawDisk" ascii
        $rawdisk = "RawDisk" ascii
        $service = "NtRaiseHardError" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($s*) or (any of ($elrawdisk, $rawdisk) and $service))
}

rule Wiper_ZeroCleare {
    meta:
        description = "ZeroCleare wiper"
        severity = "critical"
    strings:
        $s1 = "ZeroCleare" ascii
        $raw = "RawDisk" ascii
        $zero = { 00 00 00 00 00 00 00 00 00 00 }
        $driver = "EldoS" ascii
        $phys = "PhysicalDrive" ascii
    condition:
        uint16(0) == 0x5A4D and ($s1 or (2 of ($raw, $driver, $phys) and $zero))
}

rule Wiper_Behavior_Disk_Write {
    meta:
        description = "Suspicious direct disk write behavior"
        severity = "high"
    strings:
        $api1 = "CreateFileA" ascii
        $api2 = "CreateFileW" ascii
        $api3 = "WriteFile" ascii
        $api4 = "DeviceIoControl" ascii
        $phys1 = "\\\\.\\PhysicalDrive" ascii
        $phys2 = "\\\\.\\C:" ascii
        $raw = "GENERIC_WRITE" ascii
        $ioctl = { 00 00 07 00 }  // IOCTL code
    condition:
        uint16(0) == 0x5A4D and
        (any of ($api1, $api2) and $api3) and
        (any of ($phys*) or $raw or $ioctl)
}

rule Wiper_Behavior_File_Destruction {
    meta:
        description = "Mass file deletion/destruction"
        severity = "high"
    strings:
        $del1 = "DeleteFileA" ascii
        $del2 = "DeleteFileW" ascii
        $del3 = "SHFileOperation" ascii
        $find1 = "FindFirstFileA" ascii
        $find2 = "FindFirstFileW" ascii
        $find3 = "FindNextFileA" ascii
        $ext1 = ".doc" ascii
        $ext2 = ".xls" ascii
        $ext3 = ".pdf" ascii
        $ext4 = ".sql" ascii
        $recursive = "recursive" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        (any of ($del*) and any of ($find*)) and
        (3 of ($ext*) or $recursive)
}

rule Wiper_Behavior_Service_Destruction {
    meta:
        description = "Critical service destruction"
        severity = "critical"
    strings:
        $api1 = "ControlService" ascii
        $api2 = "DeleteService" ascii
        $api3 = "OpenServiceA" ascii
        $stop = "SERVICE_CONTROL_STOP" ascii
        $svc1 = "VSS" ascii
        $svc2 = "backup" ascii nocase
        $svc3 = "sql" ascii nocase
        $svc4 = "exchange" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($api*)) and (2 of ($svc*))
}
