/*
    Bootkit and UEFI Malware Detection
    MBR, VBR, UEFI firmware threats
*/

rule Bootkit_MBR_Generic {
    meta:
        description = "Generic MBR bootkit"
        severity = "critical"
    strings:
        $mbr = "\\\\.\\\\" ascii
        $physdisk = "PhysicalDrive0" ascii
        $read = "ReadFile" ascii
        $write = "WriteFile" ascii
        // UNUSED: $offset = { 00 7C }  // MBR offset
        // UNUSED: $boot = { 55 AA }    // Boot signature
    condition:
        uint16(0) == 0x5A4D and ($mbr or $physdisk) and ($read or $write)
}

rule Bootkit_VBR_Generic {
    meta:
        description = "Generic VBR bootkit"
        severity = "critical"
    strings:
        $vbr = "VBR" ascii
        $ntfs = "NTFS" ascii
        $boot = "boot" ascii nocase
        // UNUSED: $sector = "sector" ascii nocase
        $hook = "hook" ascii nocase
        $chain = "chain" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($vbr or $ntfs) and ($boot and any of ($hook, $chain))
}

rule Bootkit_TDL_Alureon {
    meta:
        description = "TDL/Alureon bootkit"
        severity = "critical"
    strings:
        $tdl1 = "TDL" ascii nocase
        // UNUSED: $tdl2 = "TDSS" ascii nocase
        $alureon = "Alureon" ascii nocase
        // UNUSED: $mbr = "MBR" ascii
        // UNUSED: $hook = "hook" ascii nocase
        // UNUSED: $rootkit = "rootkit" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($tdl*, $alureon))
}

rule Bootkit_Rovnix {
    meta:
        description = "Rovnix bootkit"
        severity = "critical"
    strings:
        $rovnix = "Rovnix" ascii nocase
        $carberp = "Carberp" ascii nocase
        // UNUSED: $vbr = "VBR" ascii
        // UNUSED: $nt = "NT" ascii
        // UNUSED: $boot = "boot" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($rovnix, $carberp))
}

rule Bootkit_Gapz {
    meta:
        description = "Gapz bootkit"
        severity = "critical"
    strings:
        $gapz = "Gapz" ascii nocase
        $vbr = "VBR" ascii
        $stealth = "stealth" ascii nocase
        $hook = "hook" ascii nocase
        // UNUSED: $inject = "inject" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($gapz or ($vbr and $stealth and $hook))
}

rule Bootkit_Mebroot {
    meta:
        description = "Mebroot/Sinowal bootkit"
        severity = "critical"
    strings:
        $mebroot = "Mebroot" ascii nocase
        $sinowal = "Sinowal" ascii nocase
        $torpig = "Torpig" ascii nocase
        // UNUSED: $mbr = "MBR" ascii
        // UNUSED: $driver = "driver" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($mebroot, $sinowal, $torpig))
}

rule UEFI_LoJax {
    meta:
        description = "LoJax UEFI rootkit"
        severity = "critical"
    strings:
        $lojax = "LoJax" ascii nocase
        $lojack = "LoJack" ascii nocase
        $computrace = "Computrace" ascii nocase
        $uefi = "UEFI" ascii
        $spi = "SPI" ascii
        $flash = "flash" ascii nocase
        $firmware = "firmware" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($lojax, $lojack, $computrace) or ($uefi and any of ($spi, $flash, $firmware)))
}

rule UEFI_MosaicRegressor {
    meta:
        description = "MosaicRegressor UEFI implant"
        severity = "critical"
    strings:
        $mosaic = "MosaicRegressor" ascii nocase
        $uefi = "UEFI" ascii
        $dxe = "DXE" ascii
        $smi = "SMI" ascii
        $nvram = "NVRAM" ascii
        // UNUSED: $firmware = "firmware" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($mosaic or ($uefi and any of ($dxe, $smi, $nvram)))
}

rule UEFI_FinSpy {
    meta:
        description = "FinSpy UEFI bootkit"
        severity = "critical"
    strings:
        $finspy = "FinSpy" ascii nocase
        $finfisher = "FinFisher" ascii nocase
        $uefi = "UEFI" ascii
        $esp = "ESP" ascii
        $boot = "boot" ascii nocase
        $manager = "bootmgr" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($finspy, $finfisher) or ($uefi and any of ($esp, $boot, $manager)))
}

rule UEFI_Hacking_Team {
    meta:
        description = "Hacking Team UEFI rootkit"
        severity = "critical"
    strings:
        $ht = "HackingTeam" ascii nocase
        $uefi = "UEFI" ascii
        $rcs = "RCS" ascii
        $galileo = "Galileo" ascii nocase
        $firmware = "firmware" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($ht, $rcs, $galileo) and ($uefi or $firmware))
}

rule UEFI_MoonBounce {
    meta:
        description = "MoonBounce UEFI implant"
        severity = "critical"
    strings:
        $moonbounce = "MoonBounce" ascii nocase
        $uefi = "UEFI" ascii
        $spi = "SPI" ascii
        $flash = "flash" ascii nocase
        $core_dxe = "CORE_DXE" ascii
        // UNUSED: $firmware = "firmware" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($moonbounce or ($uefi and any of ($spi, $flash, $core_dxe)))
}

rule UEFI_CosmicStrand {
    meta:
        description = "CosmicStrand UEFI implant"
        severity = "critical"
    strings:
        $cosmic = "CosmicStrand" ascii nocase
        $uefi = "UEFI" ascii
        $spy = "spy" ascii nocase
        $motherboard = "motherboard" ascii nocase
        $firmware = "firmware" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($cosmic or ($uefi and any of ($spy, $motherboard, $firmware)))
}

rule UEFI_ESPecter {
    meta:
        description = "ESPecter UEFI bootkit"
        severity = "critical"
    strings:
        $especter = "ESPecter" ascii nocase
        $esp = "ESP" ascii
        $uefi = "UEFI" ascii
        $boot = "boot" ascii nocase
        $partition = "partition" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($especter or ($esp and $uefi and any of ($boot, $partition)))
}

rule UEFI_BlackLotus {
    meta:
        description = "BlackLotus UEFI bootkit"
        severity = "critical"
    strings:
        $blacklotus = "BlackLotus" ascii nocase
        $uefi = "UEFI" ascii
        $secureboot = "Secure Boot" ascii nocase
        $bypass = "bypass" ascii nocase
        // UNUSED: $bootkit = "bootkit" ascii nocase
        $cve = "CVE-2022-21894" ascii
    condition:
        uint16(0) == 0x5A4D and ($blacklotus or $cve or ($uefi and $secureboot and $bypass))
}

rule UEFI_Firmware_Dump {
    meta:
        description = "UEFI firmware dumping"
        severity = "high"
    strings:
        $uefi = "UEFI" ascii
        $dump = "dump" ascii nocase
        $flash = "flash" ascii nocase
        $read = "read" ascii nocase
        $spi = "SPI" ascii
        $bios = "BIOS" ascii
        $firmware = "firmware" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($uefi or $bios) and ($dump and any of ($flash, $read, $spi, $firmware))
}

rule UEFI_SPI_Flash_Write {
    meta:
        description = "SPI flash write access"
        severity = "critical"
    strings:
        $spi = "SPI" ascii
        $flash = "flash" ascii nocase
        $write = "write" ascii nocase
        $erase = "erase" ascii nocase
        $program = "program" ascii nocase
        $bios = "BIOS" ascii
        // UNUSED: $driver = "driver" ascii nocase
    condition:
        uint16(0) == 0x5A4D and $spi and ($flash or $bios) and (any of ($write, $erase, $program))
}

rule UEFI_Secure_Boot_Bypass {
    meta:
        description = "Secure Boot bypass"
        severity = "critical"
    strings:
        $secureboot = "Secure Boot" ascii nocase
        $sb = "SecureBoot" ascii
        $bypass = "bypass" ascii nocase
        $disable = "disable" ascii nocase
        $pk = "PK" ascii
        $kek = "KEK" ascii
        $db = "db" ascii
        $dbx = "dbx" ascii
    condition:
        uint16(0) == 0x5A4D and ($secureboot or $sb) and (any of ($bypass, $disable) or (2 of ($pk, $kek, $db, $dbx)))
}

rule UEFI_NVRAM_Manipulation {
    meta:
        description = "NVRAM manipulation"
        severity = "high"
    strings:
        $nvram = "NVRAM" ascii
        $efi_var = "EFI variable" ascii nocase
        $get = "GetVariable" ascii
        $set = "SetVariable" ascii
        $runtime = "Runtime" ascii
        $services = "Services" ascii
    condition:
        uint16(0) == 0x5A4D and ($nvram or $efi_var) and (any of ($get, $set) or ($runtime and $services))
}

rule UEFI_DXE_Driver {
    meta:
        description = "Malicious DXE driver"
        severity = "critical"
    strings:
        $dxe = "DXE" ascii
        $driver = "Driver" ascii
        $protocol = "Protocol" ascii
        $guid = "GUID" ascii
        $efi = "EFI" ascii
        $image = "Image" ascii
        $entry = "Entry" ascii
    condition:
        uint16(0) == 0x5A4D and $dxe and $driver and (any of ($protocol, $guid, $efi) or ($image and $entry))
}

rule UEFI_SMM_Rootkit {
    meta:
        description = "SMM rootkit"
        severity = "critical"
    strings:
        $smm = "SMM" ascii
        $smi = "SMI" ascii
        $smram = "SMRAM" ascii
        $handler = "handler" ascii nocase
        $ring = "ring" ascii nocase
        $mode = "mode" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($smm, $smi, $smram)) and (any of ($handler, $ring, $mode))
}

