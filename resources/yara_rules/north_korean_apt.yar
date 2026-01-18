/*
    North Korean APT Detection Rules
    Lazarus, Kimsuky, APT37, APT38, and other DPRK threat actors
*/

rule NK_Lazarus_Group {
    meta:
        description = "Lazarus Group indicators"
        severity = "critical"
    strings:
        $s1 = "Lazarus" ascii nocase
        $s2 = "HIDDEN COBRA" ascii nocase
        $s3 = "HOPLIGHT" ascii nocase
        $s4 = "ELECTRICFISH" ascii nocase
        $s5 = "CROWDEDFLOUNDER" ascii nocase
        $s6 = "HARDRAIN" ascii nocase
        $s7 = "BANKSHOT" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of them)
}

rule NK_Kimsuky {
    meta:
        description = "Kimsuky APT indicators"
        severity = "critical"
    strings:
        $s1 = "Kimsuky" ascii nocase
        $s2 = "STOLEN PENCIL" ascii nocase
        $s3 = "BabyShark" ascii nocase
        $s4 = "AppleSeed" ascii nocase
        $s5 = "FlowerPower" ascii nocase
        $s6 = "GOLDDRAGON" ascii nocase
        // UNUSED: $korea = "korea" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($s*))
}

rule NK_APT37_Reaper {
    meta:
        description = "APT37/Reaper indicators"
        severity = "critical"
    strings:
        $s1 = "Reaper" ascii nocase
        $s2 = "DOGCALL" ascii nocase
        $s3 = "ROKRAT" ascii nocase
        $s4 = "POORWEB" ascii nocase
        $s5 = "SHUTTERSPEED" ascii nocase
        $s6 = "SLOWDRIFT" ascii nocase
        $s7 = "ScarCruft" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of them)
}

rule NK_APT38 {
    meta:
        description = "APT38 financial theft"
        severity = "critical"
    strings:
        $s1 = "FASTCash" ascii nocase
        $s2 = "DYEPACK" ascii nocase
        $s3 = "CROWDEDFLOUNDER" ascii nocase
        $swift = "SWIFT" ascii
        $bank = "bank" ascii nocase
        // UNUSED: $atm = "ATM" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($s*) or ($swift and $bank))
}

rule NK_Andariel {
    meta:
        description = "Andariel sub-group"
        severity = "critical"
    strings:
        $s1 = "Andariel" ascii nocase
        $s2 = "Maui" ascii nocase
        $s3 = "TigerRAT" ascii nocase
        $s4 = "MagicRAT" ascii nocase
        // UNUSED: $ransom = "ransom" ascii nocase
        // UNUSED: $healthcare = "health" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($s*))
}

rule NK_Bluenoroff {
    meta:
        description = "Bluenoroff sub-group"
        severity = "critical"
    strings:
        $s1 = "Bluenoroff" ascii nocase
        $s2 = "SNATCH" ascii nocase
        $s3 = "CryptoCore" ascii nocase
        $crypto = "crypto" ascii nocase
        $exchange = "exchange" ascii nocase
        $wallet = "wallet" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($s*) or (2 of ($crypto, $exchange, $wallet)))
}

rule NK_WannaCry {
    meta:
        description = "WannaCry ransomware"
        severity = "critical"
    strings:
        $wannacry = "WannaCry" ascii nocase
        $wcry = "WNCRY" ascii
        $ransom = "@WanaDecryptor" ascii
        $msf = "MS17-010" ascii
        $eternal = "EternalBlue" ascii nocase
        $ext = ".WNCRY" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($wannacry, $wcry, $ransom, $ext) or ($msf and $eternal))
}

rule NK_FALLCHILL {
    meta:
        description = "FALLCHILL RAT"
        severity = "critical"
    strings:
        $s1 = "FALLCHILL" ascii nocase
        $s2 = "Volgmer" ascii nocase
        $mutex = "Global\\" ascii
        $rc4 = { 00 01 02 03 04 05 06 07 }
        $c2 = "POST" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($s*) or ($mutex and $rc4 and $c2))
}

rule NK_BADCALL {
    meta:
        description = "BADCALL backdoor"
        severity = "critical"
    strings:
        $s1 = "BADCALL" ascii nocase
        $s2 = "HARDRAIN" ascii nocase
        // UNUSED: $proxy = "proxy" ascii nocase
        $ssl = "SSL" ascii
        // UNUSED: $fake_tls = { 16 03 01 }  // TLS header
    condition:
        uint16(0) == 0x5A4D and (any of ($s*))
}

rule NK_TYPEFRAME {
    meta:
        description = "TYPEFRAME backdoor"
        severity = "critical"
    strings:
        $s1 = "TYPEFRAME" ascii nocase
        $cmd1 = "upload" ascii
        $cmd2 = "download" ascii
        $cmd3 = "exec" ascii
        $cmd4 = "shell" ascii
        $http = "HTTP" ascii
    condition:
        uint16(0) == 0x5A4D and ($s1 or ((3 of ($cmd*)) and $http))
}

rule NK_SHARPKNOT {
    meta:
        description = "SHARPKNOT wiper"
        severity = "critical"
    strings:
        $s1 = "SHARPKNOT" ascii nocase
        $mbr = "\\\\.\\\\" ascii
        $physdisk = "PhysicalDrive" ascii
        $wipe = { 00 00 00 00 00 00 00 00 }
        // UNUSED: $service = "Service" ascii
    condition:
        uint16(0) == 0x5A4D and ($s1 or ($mbr and $physdisk and $wipe))
}

rule NK_JOANAP {
    meta:
        description = "JOANAP botnet"
        severity = "critical"
    strings:
        $s1 = "JOANAP" ascii nocase
        $s2 = "SMB" ascii
        $s3 = "worm" ascii nocase
        $share = "ADMIN$" ascii
        $spread = "spread" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($s*))
}

rule NK_BRAMBUL {
    meta:
        description = "BRAMBUL worm"
        severity = "critical"
    strings:
        $s1 = "BRAMBUL" ascii nocase
        $smb = "SMB" ascii
        // UNUSED: $worm = "worm" ascii nocase
        $admin = "ADMIN$" ascii
        $ipc = "IPC$" ascii
        $brute = "brute" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($s1 or ($smb and any of ($admin, $ipc) and $brute))
}

rule NK_AppleJeus {
    meta:
        description = "AppleJeus crypto theft"
        severity = "critical"
    strings:
        $s1 = "AppleJeus" ascii nocase
        $s2 = "CelasTradePro" ascii
        $s3 = "JMTTrading" ascii
        $s4 = "UnionCrypto" ascii
        $crypto = "crypto" ascii nocase
        $trade = "trade" ascii nocase
        $update = "update" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($s*) or ($crypto and $trade and $update))
}

rule NK_Gopuram {
    meta:
        description = "Gopuram backdoor (3CX attack)"
        severity = "critical"
    strings:
        $s1 = "Gopuram" ascii nocase
        $s2 = "3CX" ascii nocase
        $s3 = "DesktopApp" ascii
        $supply = "supply" ascii nocase
        // UNUSED: $chain = "chain" ascii nocase
        // UNUSED: $update = "update" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($s*))
}

rule NK_ELECTRICFISH {
    meta:
        description = "ELECTRICFISH tunneling"
        severity = "critical"
    strings:
        $s1 = "ELECTRICFISH" ascii nocase
        $tunnel = "tunnel" ascii nocase
        $proxy = "proxy" ascii nocase
        // UNUSED: $socks = "SOCKS" ascii
        // UNUSED: $connect = "CONNECT" ascii
    condition:
        uint16(0) == 0x5A4D and ($s1 or ($tunnel and $proxy))
}

rule NK_HOTCROISSANT {
    meta:
        description = "HOTCROISSANT backdoor"
        severity = "critical"
    strings:
        $s1 = "HOTCROISSANT" ascii nocase
        $s2 = "RIFDOOR" ascii nocase
        // UNUSED: $beacon = "beacon" ascii nocase
        // UNUSED: $c2 = "c2" ascii nocase
        // UNUSED: $http = "HTTP" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($s*))
}

rule NK_DTrack {
    meta:
        description = "DTrack/ATMDTrack"
        severity = "critical"
    strings:
        $s1 = "DTrack" ascii nocase
        $s2 = "ATMDTrack" ascii nocase
        $keylog = "keylog" ascii nocase
        $screen = "screen" ascii nocase
        $browser = "browser" ascii nocase
        $history = "history" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($s*) or (2 of ($keylog, $screen, $browser, $history)))
}

rule NK_BLINDINGCAN {
    meta:
        description = "BLINDINGCAN RAT"
        severity = "critical"
    strings:
        $s1 = "BLINDINGCAN" ascii nocase
        $cmd = "cmd.exe" ascii
        $ps = "powershell" ascii nocase
        $rat = "RAT" ascii
        // UNUSED: $remote = "remote" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($s1 or ($cmd and $ps and $rat))
}

rule NK_PEBBLEDASH {
    meta:
        description = "PEBBLEDASH implant"
        severity = "critical"
    strings:
        $s1 = "PEBBLEDASH" ascii nocase
        $implant = "implant" ascii nocase
        $c2 = "http" ascii nocase
        // UNUSED: $rc4 = "RC4" ascii
        // UNUSED: $xor = "xor" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($s1 or ($implant and $c2))
}

rule NK_H0lyGh0st {
    meta:
        description = "H0lyGh0st ransomware"
        severity = "critical"
    strings:
        $s1 = "H0lyGh0st" ascii nocase
        $s2 = "HolyGhost" ascii nocase
        $s3 = "SiennaPurple" ascii
        $s4 = "SiennaBlue" ascii
        // UNUSED: $ransom = "ransom" ascii nocase
        // UNUSED: $encrypt = "encrypt" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($s*))
}

