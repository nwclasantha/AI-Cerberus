/*
    Iranian APT Detection Rules
    APT33, APT34, APT35, APT39, MuddyWater, and other Iranian threat actors
*/

rule Iranian_APT33_Elfin {
    meta:
        description = "APT33/Elfin indicators"
        severity = "critical"
    strings:
        $s1 = "STONEDRILL" ascii nocase
        $s2 = "TURNEDUP" ascii nocase
        $s3 = "DROPSHOT" ascii nocase
        $s4 = "SHAPESHIFT" ascii nocase
        $s5 = "Elfin" ascii nocase
        $aerospace = "aerospace" ascii nocase
        $energy = "energy" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($s*))
}

rule Iranian_APT34_OilRig {
    meta:
        description = "APT34/OilRig indicators"
        severity = "critical"
    strings:
        $s1 = "POWRUNER" ascii nocase
        $s2 = "BONDUPDATER" ascii nocase
        $s3 = "QUADAGENT" ascii nocase
        $s4 = "VALUEVAULT" ascii nocase
        $s5 = "OilRig" ascii nocase
        $s6 = "LONGWATCH" ascii nocase
        $dns = "DNS" ascii
        $c2 = "c2" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($s*))
}

rule Iranian_APT35_Charming_Kitten {
    meta:
        description = "APT35/Charming Kitten indicators"
        severity = "critical"
    strings:
        $s1 = "CharmingKitten" ascii nocase
        $s2 = "Newscaster" ascii nocase
        $s3 = "Phosphorus" ascii nocase
        $s4 = "POWERSTAR" ascii nocase
        $s5 = "HYPERSCRAPE" ascii nocase
        $phish = "phishing" ascii nocase
        $google = "google" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($s*))
}

rule Iranian_APT39_Chafer {
    meta:
        description = "APT39/Chafer indicators"
        severity = "critical"
    strings:
        $s1 = "Chafer" ascii nocase
        $s2 = "REMIX" ascii nocase
        $s3 = "SEAWEED" ascii nocase
        $s4 = "CACHEMONEY" ascii nocase
        $s5 = "POWBAT" ascii nocase
        $telecom = "telecom" ascii nocase
        $travel = "travel" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($s*))
}

rule Iranian_MuddyWater {
    meta:
        description = "MuddyWater APT indicators"
        severity = "critical"
    strings:
        $s1 = "MuddyWater" ascii nocase
        $s2 = "POWERSTATS" ascii nocase
        $s3 = "SHARPSTATS" ascii nocase
        $s4 = "LOLBINS" ascii nocase
        $ps = "powershell" ascii nocase
        $macro = "macro" ascii nocase
        $obfusc = "obfuscation" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($s*) or ($ps and $obfusc))
}

rule Iranian_Shamoon {
    meta:
        description = "Shamoon wiper"
        severity = "critical"
    strings:
        $shamoon = "Shamoon" ascii nocase
        $disttrack = "DistTrack" ascii nocase
        $wiper = "wiper" ascii nocase
        $mbr = "\\\\.\\\\" ascii
        $rawdisk = "RawDisk" ascii
        $eldos = "ElDos" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($shamoon, $disttrack) or ($wiper and any of ($mbr, $rawdisk, $eldos)))
}

rule Iranian_ZeroCleare {
    meta:
        description = "ZeroCleare wiper"
        severity = "critical"
    strings:
        $zero = "ZeroCleare" ascii nocase
        $dustman = "Dustman" ascii nocase
        $wipe = "wipe" ascii nocase
        $disk = "disk" ascii nocase
        $rawdisk = "RawDisk" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($zero, $dustman) or ($wipe and $disk and $rawdisk))
}

rule Iranian_CopyKittens {
    meta:
        description = "CopyKittens APT"
        severity = "critical"
    strings:
        $s1 = "CopyKittens" ascii nocase
        $s2 = "MATRYOSHKA" ascii nocase
        $s3 = "Venom" ascii nocase
        $s4 = "COOKIEJAR" ascii nocase
        $israel = "israel" ascii nocase
        $gov = "gov" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($s*))
}

rule Iranian_Rocket_Kitten {
    meta:
        description = "Rocket Kitten APT"
        severity = "critical"
    strings:
        $s1 = "RocketKitten" ascii nocase
        $s2 = "Flying Kitten" ascii nocase
        $s3 = "GHOLE" ascii nocase
        $s4 = "WOOLGER" ascii nocase
        $s5 = "FireMalv" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of them)
}

rule Iranian_MagicHound {
    meta:
        description = "Magic Hound APT"
        severity = "critical"
    strings:
        $s1 = "MagicHound" ascii nocase
        $s2 = "Cobalt Gypsy" ascii nocase
        $s3 = "PupyRAT" ascii nocase
        $s4 = "Meterpreter" ascii nocase
        $iran = "iran" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($s*))
}

rule Iranian_Crambus_Leafminer {
    meta:
        description = "Crambus/Leafminer APT"
        severity = "critical"
    strings:
        $s1 = "Crambus" ascii nocase
        $s2 = "Leafminer" ascii nocase
        $s3 = "Raspite" ascii nocase
        $s4 = "SORGU" ascii nocase
        $s5 = "SOLEBOT" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of them)
}

rule Iranian_Lyceum {
    meta:
        description = "Lyceum/Hexane APT"
        severity = "critical"
    strings:
        $s1 = "Lyceum" ascii nocase
        $s2 = "Hexane" ascii nocase
        $s3 = "DanBot" ascii nocase
        $s4 = "SPIRLIX" ascii nocase
        $dns_tunnel = "DNS" ascii
        $c2 = "http" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($s*))
}

rule Iranian_Agrius {
    meta:
        description = "Agrius APT"
        severity = "critical"
    strings:
        $s1 = "Agrius" ascii nocase
        $s2 = "Apostle" ascii nocase
        $s3 = "IPsec Helper" ascii
        $s4 = "DEADWOOD" ascii nocase
        $wiper = "wipe" ascii nocase
        $ransom = "ransom" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($s*) or ($wiper and $ransom))
}

rule Iranian_Domestic_Kitten {
    meta:
        description = "Domestic Kitten APT"
        severity = "critical"
    strings:
        $s1 = "DomesticKitten" ascii nocase
        $s2 = "APT-C-50" ascii
        $s3 = "FurBall" ascii nocase
        $android = "android" ascii nocase
        $mobile = "mobile" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($s*))
}

rule Iranian_Infy {
    meta:
        description = "Infy/Prince of Persia"
        severity = "critical"
    strings:
        $s1 = "Infy" ascii nocase
        $s2 = "PrinceOfPersia" ascii nocase
        $s3 = "Foudre" ascii nocase
        $s4 = "Tonnerre" ascii nocase
        $keylog = "keylog" ascii nocase
        $screen = "screen" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($s*) or ($keylog and $screen))
}

rule Iranian_Nemesis_Kitten {
    meta:
        description = "Nemesis Kitten (DEV-0270)"
        severity = "critical"
    strings:
        $s1 = "NemesisKitten" ascii nocase
        $s2 = "DEV-0270" ascii
        $s3 = "BitLocker" ascii
        $s4 = "DiskCryptor" ascii
        $ransom = "ransom" ascii nocase
        $encrypt = "encrypt" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($s*))
}

rule Iranian_Tortoiseshell {
    meta:
        description = "Tortoiseshell APT"
        severity = "critical"
    strings:
        $s1 = "Tortoiseshell" ascii nocase
        $s2 = "IAmTheKing" ascii nocase
        $s3 = "SYSKIT" ascii nocase
        $s4 = "LIDERC" ascii nocase
        $supply = "supply chain" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($s*))
}

rule Iranian_SectorA01 {
    meta:
        description = "Iranian SectorA01 tools"
        severity = "critical"
    strings:
        $remexi = "Remexi" ascii nocase
        $mechaflounder = "MechaFlounder" ascii nocase
        $meterpreter = "Meterpreter" ascii nocase
        $cobaltstrike = "CobaltStrike" ascii nocase
        $ps = "powershell" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($remexi, $mechaflounder) or ($meterpreter and $ps))
}

rule Iranian_POWERSOURCE {
    meta:
        description = "Iranian POWERSOURCE backdoor"
        severity = "critical"
    strings:
        $power = "POWERSOURCE" ascii nocase
        $dns_txt = "TXT" ascii
        $dns_query = "DNS" ascii
        $base64 = "base64" ascii nocase
        $ps = "-enc" ascii
        $hidden = "-w hidden" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($power or ($dns_txt and $dns_query and any of ($base64, $ps, $hidden)))
}

rule Iranian_KEYPUNCH {
    meta:
        description = "Iranian KEYPUNCH keylogger"
        severity = "critical"
    strings:
        $keypunch = "KEYPUNCH" ascii nocase
        $keylog = "GetAsyncKeyState" ascii
        $hook = "SetWindowsHookEx" ascii
        $log = "log" ascii
        $file = "CreateFile" ascii
    condition:
        uint16(0) == 0x5A4D and ($keypunch or ($keylog and $hook and ($log or $file)))
}

rule Iranian_LONGWATCH {
    meta:
        description = "Iranian LONGWATCH keylogger"
        severity = "critical"
    strings:
        $longwatch = "LONGWATCH" ascii nocase
        $keylog1 = "keyboard" ascii nocase
        $keylog2 = "keylogger" ascii nocase
        $screenshot = "screenshot" ascii nocase
        $clipboard = "clipboard" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($longwatch or (2 of ($keylog1, $keylog2, $screenshot, $clipboard)))
}

