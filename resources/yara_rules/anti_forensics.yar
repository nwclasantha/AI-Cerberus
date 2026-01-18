/*
    Anti-Forensics Detection
    Tools and techniques used to hide evidence and avoid analysis
*/

rule AntiForensics_Timestomping {
    meta:
        description = "Timestomping - modifying file timestamps"
        severity = "high"
    strings:
        $api1 = "SetFileTime" ascii
        $api2 = "NtSetInformationFile" ascii
        $api3 = "ZwSetInformationFile" ascii
        $touch = "touch" ascii nocase
        $mace = "$STANDARD_INFORMATION" ascii
        $mft = "$MFT" ascii
        $timestomp = "timestomp" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (2 of ($api*) or $timestomp or ($touch and any of ($mace, $mft)))
}

rule AntiForensics_Log_Clearing {
    meta:
        description = "Event log clearing"
        severity = "critical"
    strings:
        $api1 = "ClearEventLog" ascii
        $api2 = "EvtClearLog" ascii
        $wevtutil = "wevtutil" ascii nocase
        $clear = "clear-eventlog" ascii nocase
        $security = "Security" ascii
        $system = "System" ascii
        $application = "Application" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($api*) or $wevtutil or $clear) and any of ($security, $system, $application)
}

rule AntiForensics_Shadow_Copy_Delete {
    meta:
        description = "Volume shadow copy deletion"
        severity = "critical"
    strings:
        $vssadmin = "vssadmin" ascii nocase
        $delete = "delete" ascii nocase
        $shadows = "shadows" ascii nocase
        $wmic = "wmic" ascii nocase
        $shadowcopy = "shadowcopy" ascii nocase
        // UNUSED: $resize = "resize" ascii nocase
        $bcdedit = "bcdedit" ascii nocase
        $recoveryenabled = "recoveryenabled" ascii nocase
    condition:
        (($vssadmin and $delete and $shadows) or ($wmic and $shadowcopy and $delete)) or ($bcdedit and $recoveryenabled)
}

rule AntiForensics_Secure_Delete {
    meta:
        description = "Secure file deletion"
        severity = "high"
    strings:
        $sdelete = "sdelete" ascii nocase
        $cipher = "cipher /w" ascii nocase
        $eraser = "Eraser" ascii nocase
        $dban = "DBAN" ascii
        $shred = "shred" ascii nocase
        $wipe = "wipe" ascii nocase
        $secure = "secure" ascii nocase
        $overwrite = "overwrite" ascii nocase
        $pass = "pass" ascii nocase
    condition:
        (any of ($sdelete, $cipher, $eraser, $dban)) or ($shred and any of ($wipe, $secure)) or ($overwrite and $pass)
}

rule AntiForensics_MFT_Manipulation {
    meta:
        description = "MFT manipulation/corruption"
        severity = "critical"
    strings:
        $mft = "$MFT" ascii
        $mftmirr = "$MFTMirr" ascii
        // UNUSED: $ntfs = "NTFS" ascii
        $raw = "\\\\.\\PhysicalDrive" ascii
        $sector = "sector" ascii nocase
        $corrupt = "corrupt" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($mft, $mftmirr)) and ($raw or any of ($sector, $corrupt))
}

rule AntiForensics_Registry_Cleaning {
    meta:
        description = "Registry evidence cleaning"
        severity = "high"
    strings:
        $reg1 = "RegDeleteKey" ascii
        $reg2 = "RegDeleteValue" ascii
        $userassist = "UserAssist" ascii
        $recentdocs = "RecentDocs" ascii
        $runmru = "RunMRU" ascii
        $typedurls = "TypedURLs" ascii
        $shellbags = "ShellBags" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($reg*)) and (2 of ($userassist, $recentdocs, $runmru, $typedurls, $shellbags))
}

rule AntiForensics_USN_Journal_Delete {
    meta:
        description = "USN Journal manipulation"
        severity = "high"
    strings:
        $fsutil = "fsutil" ascii nocase
        $usn = "usn" ascii nocase
        $deletejournal = "deletejournal" ascii nocase
        $journal = "$UsnJrnl" ascii
        $j = "$J" ascii
    condition:
        ($fsutil and $usn and $deletejournal) or ($journal and any of ($j))
}

rule AntiForensics_Prefetch_Delete {
    meta:
        description = "Prefetch file deletion"
        severity = "medium"
    strings:
        $prefetch = "Prefetch" ascii nocase
        $pf = ".pf" ascii nocase
        $delete = "Delete" ascii
        $remove = "Remove" ascii
        $windows = "\\Windows\\" ascii
    condition:
        uint16(0) == 0x5A4D and $prefetch and ($pf or $windows) and any of ($delete, $remove)
}

rule AntiForensics_Browser_History_Clean {
    meta:
        description = "Browser history cleaning"
        severity = "medium"
    strings:
        $chrome = "Chrome" ascii nocase
        $firefox = "Firefox" ascii nocase
        $edge = "Edge" ascii nocase
        $history = "History" ascii nocase
        $cookies = "Cookies" ascii nocase
        $cache = "Cache" ascii nocase
        $delete = "delete" ascii nocase
        $clear = "clear" ascii nocase
        $sqlite = "sqlite" ascii nocase
    condition:
        (any of ($chrome, $firefox, $edge)) and (any of ($history, $cookies, $cache)) and (any of ($delete, $clear, $sqlite))
}

rule AntiForensics_Memory_Artifact_Clean {
    meta:
        description = "Memory artifact cleaning"
        severity = "high"
    strings:
        $api1 = "VirtualFree" ascii
        $api2 = "ZeroMemory" ascii
        $api3 = "SecureZeroMemory" ascii
        $api4 = "RtlZeroMemory" ascii
        $clean = "clean" ascii nocase
        $wipe = "wipe" ascii nocase
        $memory = "memory" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (2 of ($api*)) and any of ($clean, $wipe, $memory)
}

rule AntiForensics_Slack_Space_Hiding {
    meta:
        description = "Slack space data hiding"
        severity = "high"
    strings:
        $slack = "slack" ascii nocase
        $space = "space" ascii nocase
        $hide = "hide" ascii nocase
        $cluster = "cluster" ascii nocase
        // UNUSED: $ntfs = "NTFS" ascii
        $raw = "raw" ascii nocase
    condition:
        ($slack and $space and $hide) or ($cluster and any of ($hide, $raw))
}

rule AntiForensics_ADS_Hiding {
    meta:
        description = "Alternate Data Stream hiding"
        severity = "high"
    strings:
        $ads = "Alternate Data Stream" ascii nocase
        $colon = ":" ascii
        $zone = "Zone.Identifier" ascii
        $hide = "hide" ascii nocase
        $stream = "stream" ascii nocase
        $ntfs = "NTFS" ascii
    condition:
        $ads or ($zone and $hide) or (($colon and $stream) and any of ($hide, $ntfs))
}

rule AntiForensics_Process_Hollowing_Clean {
    meta:
        description = "Process hollowing cleanup"
        severity = "critical"
    strings:
        $hollow = "hollow" ascii nocase
        $unmap = "NtUnmapViewOfSection" ascii
        $write = "WriteProcessMemory" ascii
        $resume = "ResumeThread" ascii
        $clean = "clean" ascii nocase
        $remove = "remove" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($unmap and $write and $resume) and any of ($clean, $remove, $hollow)
}

rule AntiForensics_Artifact_Wiper {
    meta:
        description = "Forensic artifact wiper tool"
        severity = "critical"
    strings:
        $ccleaner = "CCleaner" ascii nocase
        $bleachbit = "BleachBit" ascii nocase
        $privazer = "PrivaZer" ascii nocase
        $evidence = "evidence" ascii nocase
        $artifact = "artifact" ascii nocase
        $forensic = "forensic" ascii nocase
        $wipe = "wipe" ascii nocase
        $clean = "clean" ascii nocase
    condition:
        (any of ($ccleaner, $bleachbit, $privazer)) or (any of ($evidence, $artifact, $forensic) and any of ($wipe, $clean))
}

rule AntiForensics_Encrypted_Container {
    meta:
        description = "Encrypted container usage"
        severity = "medium"
    strings:
        $veracrypt = "VeraCrypt" ascii nocase
        $truecrypt = "TrueCrypt" ascii nocase
        $bitlocker = "BitLocker" ascii nocase
        $luks = "LUKS" ascii
        $hidden = "hidden" ascii nocase
        $volume = "volume" ascii nocase
        $container = "container" ascii nocase
    condition:
        (any of ($veracrypt, $truecrypt, $bitlocker, $luks)) and any of ($hidden, $volume, $container)
}

rule AntiForensics_VM_Detection_Evasion {
    meta:
        description = "VM detection for forensic evasion"
        severity = "high"
    strings:
        $vm1 = "VMware" ascii nocase
        $vm2 = "VirtualBox" ascii nocase
        $vm3 = "QEMU" ascii nocase
        $vm4 = "Hyper-V" ascii nocase
        $sandbox = "sandbox" ascii nocase
        $analysis = "analysis" ascii nocase
        $exit = "ExitProcess" ascii
        $terminate = "TerminateProcess" ascii
    condition:
        uint16(0) == 0x5A4D and (2 of ($vm*) or $sandbox or $analysis) and any of ($exit, $terminate)
}

rule AntiForensics_Disk_Wiping {
    meta:
        description = "Full disk wiping capability"
        severity = "critical"
    strings:
        $disk1 = "PhysicalDrive" ascii
        $disk2 = "\\\\.\\C:" ascii
        $disk3 = "\\Device\\Harddisk" ascii
        $wipe = "wipe" ascii nocase
        $erase = "erase" ascii nocase
        $zero = "zero" ascii nocase
        $pattern = "pattern" ascii nocase
        $dod = "DoD" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($disk*)) and (2 of ($wipe, $erase, $zero, $pattern, $dod))
}

rule AntiForensics_Network_Evidence_Clean {
    meta:
        description = "Network evidence cleaning"
        severity = "high"
    strings:
        $netsh = "netsh" ascii nocase
        $arp = "arp" ascii nocase
        $dns = "dns" ascii nocase
        $cache = "cache" ascii nocase
        $flush = "flush" ascii nocase
        $clear = "clear" ascii nocase
        $ipconfig = "ipconfig" ascii nocase
        $flushdns = "flushdns" ascii nocase
    condition:
        (($netsh or $arp or $ipconfig) and any of ($cache, $flush, $clear, $flushdns)) or ($dns and $flush)
}

rule AntiForensics_Self_Destruction {
    meta:
        description = "Self-destruction mechanism"
        severity = "critical"
    strings:
        $self = "self" ascii nocase
        $destruct = "destruct" ascii nocase
        // UNUSED: $delete = "delete" ascii nocase
        $remove = "remove" ascii nocase
        $cmd = "cmd.exe" ascii nocase
        $del = "/c del" ascii nocase
        $bat = ".bat" ascii nocase
        $timeout = "timeout" ascii nocase
    condition:
        (($self and $destruct) or ($cmd and $del)) and any of ($remove, $bat, $timeout)
}

rule AntiForensics_Metadata_Removal {
    meta:
        description = "File metadata removal"
        severity = "medium"
    strings:
        $exiftool = "exiftool" ascii nocase
        $metadata = "metadata" ascii nocase
        $exif = "EXIF" ascii
        $xmp = "XMP" ascii
        $iptc = "IPTC" ascii
        $remove = "remove" ascii nocase
        $strip = "strip" ascii nocase
        $clean = "clean" ascii nocase
    condition:
        ($exiftool or $metadata) and (any of ($exif, $xmp, $iptc)) and any of ($remove, $strip, $clean)
}

