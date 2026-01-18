/*
    Chinese APT Detection Rules
    APT1, APT3, APT10, APT40, APT41, and other Chinese threat actors
*/

rule Chinese_APT1_Comment_Crew {
    meta:
        description = "APT1/Comment Crew indicators"
        severity = "critical"
    strings:
        $s1 = "WEBC2" ascii nocase
        $s2 = "BISCUIT" ascii nocase
        $s3 = "AURIGA" ascii
        $s4 = "BANGAT" ascii
        $s5 = "COOKIEBAG" ascii
        $c2 = "comment" ascii nocase
        $http = "HTTP" ascii
        // UNUSED: $beacon = "beacon" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($s*) or ($c2 and $http))
}

rule Chinese_APT3_Gothic_Panda {
    meta:
        description = "APT3/Gothic Panda indicators"
        severity = "critical"
    strings:
        $s1 = "Pirpi" ascii nocase
        $s2 = "PlugX" ascii nocase
        $s3 = "SHOTPUT" ascii
        $s4 = "DoublePulsar" ascii nocase
        // UNUSED: $mutex = "Global\\" ascii
        $c2_pattern = /[a-z]{5,10}\.[a-z]{2,3}\.cn/ ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($s*) or $c2_pattern)
}

rule Chinese_APT10_Stone_Panda {
    meta:
        description = "APT10/Stone Panda indicators"
        severity = "critical"
    strings:
        $s1 = "menuPass" ascii nocase
        $s2 = "ChChes" ascii nocase
        $s3 = "RedLeaves" ascii nocase
        $s4 = "UPPERCUT" ascii nocase
        $s5 = "ANEL" ascii nocase
        $config = "config" ascii
        $msp = "MSP" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($s*) or ($config and $msp))
}

rule Chinese_APT17_Deputy_Dog {
    meta:
        description = "APT17/Deputy Dog indicators"
        severity = "critical"
    strings:
        $s1 = "BLACKCOFFEE" ascii nocase
        $s2 = "DeputyDog" ascii nocase
        $s3 = "Hikit" ascii nocase
        $mshtml = "mshtml" ascii nocase
        $ie_exploit = "CVE-2013" ascii
        // UNUSED: $dll = ".dll" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($s*) or ($mshtml and $ie_exploit))
}

rule Chinese_APT18_Wekby {
    meta:
        description = "APT18/Wekby indicators"
        severity = "critical"
    strings:
        $s1 = "Wekby" ascii nocase
        $s2 = "hcdLoader" ascii
        $s3 = "HTTPBrowser" ascii
        $gh0st = "Gh0st" ascii nocase
        // UNUSED: $pisloader = "pisloader" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($s*) or $gh0st)
}

rule Chinese_APT19_Deep_Panda {
    meta:
        description = "APT19/Deep Panda indicators"
        severity = "critical"
    strings:
        $s1 = "DERUSBI" ascii nocase
        $s2 = "Sakula" ascii nocase
        $s3 = "Codoso" ascii nocase
        $s4 = "FireEye" ascii  // often referenced
        // UNUSED: $dll_side = "DLL" ascii
        // UNUSED: $persist = "HKCU" ascii
    condition:
        uint16(0) == 0x5A4D and (2 of ($s*))
}

rule Chinese_APT27_Emissary_Panda {
    meta:
        description = "APT27/Emissary Panda indicators"
        severity = "critical"
    strings:
        $s1 = "LuckyMouse" ascii nocase
        $s2 = "EmissaryPanda" ascii nocase
        $s3 = "IronTiger" ascii nocase
        $s4 = "HyperBro" ascii nocase
        $s5 = "PlugX" ascii nocase
        $s6 = "SysUpdate" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of them)
}

rule Chinese_APT30 {
    meta:
        description = "APT30 indicators"
        severity = "critical"
    strings:
        $s1 = "NETEAGLE" ascii nocase
        $s2 = "BACKSPACE" ascii nocase
        $s3 = "FLASHFLOOD" ascii
        $s4 = "SPACESHIP" ascii
        // UNUSED: $gov = "government" ascii nocase
        // UNUSED: $asean = "ASEAN" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($s*))
}

rule Chinese_APT40_Leviathan {
    meta:
        description = "APT40/Leviathan indicators"
        severity = "critical"
    strings:
        $s1 = "AIRBREAK" ascii nocase
        $s2 = "FRESHAIR" ascii nocase
        $s3 = "Leviathan" ascii nocase
        $s4 = "MURKYTOP" ascii nocase
        $s5 = "PHOTO" ascii
        $maritime = "maritime" ascii nocase
        $naval = "naval" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($s*) or any of ($maritime, $naval))
}

rule Chinese_APT41_Winnti {
    meta:
        description = "APT41/Winnti indicators"
        severity = "critical"
    strings:
        $s1 = "POISONPLUG" ascii nocase
        $s2 = "ShadowPad" ascii nocase
        $s3 = "Winnti" ascii nocase
        $s4 = "CROSSWALK" ascii nocase
        $s5 = "LOWKEY" ascii nocase
        // UNUSED: $game = "game" ascii nocase
        $supply = "update" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (2 of ($s*))
}

rule Chinese_Winnti_Backdoor {
    meta:
        description = "Winnti backdoor"
        severity = "critical"
    strings:
        $winnti = "winnti" ascii nocase
        $driver = "driver" ascii nocase
        $inject = "inject" ascii nocase
        $xor = { 35 ?? ?? ?? ?? }
        // UNUSED: $config_marker = { 78 9C }  // zlib
        // UNUSED: $persist = "ServiceDll" ascii
    condition:
        uint16(0) == 0x5A4D and ($winnti or ($driver and $inject and $xor))
}

rule Chinese_PlugX {
    meta:
        description = "PlugX/SOGU backdoor"
        severity = "critical"
    strings:
        $s1 = "PlugX" ascii nocase
        $s2 = "SOGU" ascii nocase
        $s3 = "Destroy" ascii
        $s4 = "gulpf" ascii
        $config = { 45 4E 43 52 }  // ENCR
        $xor_key = { 41 41 41 41 }
        // UNUSED: $http_header = "X-Session" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($s*) or ($config and $xor_key))
}

rule Chinese_ShadowPad {
    meta:
        description = "ShadowPad backdoor"
        severity = "critical"
    strings:
        $s1 = "ShadowPad" ascii nocase
        $s2 = "SHADOWPAD" ascii
        $module1 = "Plugins" ascii
        $module2 = "Config" ascii
        $module3 = "Online" ascii
        // UNUSED: $dns = "DNS" ascii
        // UNUSED: $tcp = "TCP" ascii
        // UNUSED: $http = "HTTP" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($s*) or (all of ($module*)))
}

rule Chinese_Gh0st_RAT {
    meta:
        description = "Gh0st RAT"
        severity = "critical"
    strings:
        $gh0st = "Gh0st" ascii nocase
        $pcshare = "PcShare" ascii nocase
        $marker = { 47 68 30 73 74 }  // Gh0st
        $zlib = { 78 9C }
        $screen = "Screen" ascii
        $keylog = "Keylog" ascii
        $file = "FileManager" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($gh0st, $pcshare, $marker) or ($zlib and 2 of ($screen, $keylog, $file)))
}

rule Chinese_Poison_Ivy {
    meta:
        description = "Poison Ivy RAT"
        severity = "critical"
    strings:
        $pi1 = "PIVY" ascii nocase
        $pi2 = "Poison Ivy" ascii nocase
        $stub = "stub" ascii
        $admin = "admin" ascii
        $password = "password" ascii
        // UNUSED: $active = "Active Setup" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($pi*) or ($stub and $admin and $password))
}

rule Chinese_Taidoor {
    meta:
        description = "Taidoor RAT"
        severity = "critical"
    strings:
        $taidoor = "Taidoor" ascii nocase
        $config1 = "svchost.dll" ascii
        $config2 = "rasauto.dll" ascii
        $mutex = "YOURKEY" ascii
        // UNUSED: $http = "POST" ascii
    condition:
        uint16(0) == 0x5A4D and ($taidoor or (any of ($config*) and $mutex))
}

rule Chinese_TSCookie {
    meta:
        description = "TSCookie backdoor"
        severity = "critical"
    strings:
        $ts = "TSCookie" ascii nocase
        $plead = "PLEAD" ascii nocase
        $cookie = "Cookie:" ascii
        $ua = "User-Agent:" ascii
        $rc4 = { 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F }
    condition:
        uint16(0) == 0x5A4D and (any of ($ts, $plead) or ($cookie and $ua and $rc4))
}

rule Chinese_IceFog {
    meta:
        description = "Icefog APT tools"
        severity = "critical"
    strings:
        $icefog = "Icefog" ascii nocase
        $fucksun = "fucksun" ascii nocase
        $dagger = "Dagger" ascii
        $javafog = "Javafog" ascii
        // UNUSED: $upload = "upload" ascii
        // UNUSED: $download = "download" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($icefog, $fucksun, $dagger, $javafog))
}

rule Chinese_Naikon_APT {
    meta:
        description = "Naikon APT backdoor"
        severity = "critical"
    strings:
        $naikon = "Naikon" ascii nocase
        $admin = "admin@338" ascii
        $rarstone = "RARSTONE" ascii
        $xsplus = "XSPlus" ascii
        $sys10 = "SYS10" ascii
    condition:
        uint16(0) == 0x5A4D and (any of them)
}

rule Chinese_Hellsing_APT {
    meta:
        description = "Hellsing APT"
        severity = "critical"
    strings:
        $hellsing = "Hellsing" ascii nocase
        $goblin = "Goblin" ascii nocase
        // UNUSED: $panda = "Panda" ascii nocase
        $xrat = "xRAT" ascii
        // UNUSED: $config = "config" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($hellsing, $goblin) or $xrat)
}

rule Chinese_Lotus_Blossom {
    meta:
        description = "Lotus Blossom APT"
        severity = "critical"
    strings:
        $lotus = "Lotus" ascii nocase
        $blossom = "Blossom" ascii nocase
        $elise = "Elise" ascii nocase
        $spring = "Spring" ascii nocase
        $dragon = "Dragon" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (($lotus and $blossom) or any of ($elise, $spring, $dragon))
}

rule Chinese_Operation_Soft_Cell {
    meta:
        description = "Operation Soft Cell"
        severity = "critical"
    strings:
        $softcell = "SoftCell" ascii nocase
        // UNUSED: $telecom = "telecom" ascii nocase
        // UNUSED: $cdr = "CDR" ascii
        $modified = "modified_mimikatz" ascii
        $china_chopper = "chopper" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($softcell, $modified, $china_chopper))
}

rule Chinese_Hafnium_ProxyLogon {
    meta:
        description = "HAFNIUM/ProxyLogon indicators"
        severity = "critical"
    strings:
        $s1 = "ProxyLogon" ascii nocase
        $s2 = "HAFNIUM" ascii nocase
        $s3 = "China Chopper" ascii nocase
        // UNUSED: $exchange = "Exchange" ascii
        // UNUSED: $owa = "OWA" ascii
        // UNUSED: $webshell = "webshell" ascii nocase
        $cve1 = "CVE-2021-26855" ascii
        $cve2 = "CVE-2021-27065" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($s*) or any of ($cve*))
}

rule Chinese_Bronze_Butler {
    meta:
        description = "Bronze Butler/Tick"
        severity = "critical"
    strings:
        $bronze = "BronzeButler" ascii nocase
        $tick = "Tick" ascii nocase
        $daserf = "Daserf" ascii nocase
        $datper = "Datper" ascii nocase
        $xxmm = "xxmm" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of them)
}

