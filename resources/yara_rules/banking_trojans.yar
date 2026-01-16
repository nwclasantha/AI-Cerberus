/*
    Banking Trojan Detection Rules
    Covers: Zeus, Emotet, TrickBot, Dridex, QakBot, etc.
*/

rule Zeus_GameOver {
    meta:
        description = "Zeus GameOver banking trojan"
        severity = "critical"
    strings:
        $s1 = "ZEUS" ascii
        $s2 = "GameOver" ascii
        $s3 = "bot_version" ascii
        $s4 = "inject_vnc" ascii
        $cfg = {C7 45 ?? ?? ?? ?? ?? 89 45 ??}
    condition:
        2 of ($s*) or ($cfg and any of ($s*))
}

rule Emotet_Loader {
    meta:
        description = "Emotet banking trojan/loader"
        severity = "critical"
    strings:
        $s1 = "EMOTET" nocase
        $s2 = {8B 45 ?? 83 C0 ?? 50 8B 4D ?? 51 E8}
        $s3 = {C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? EB}
        $str1 = "Content-Type: multipart" ascii
        $str2 = "%s%s.exe" ascii
    condition:
        2 of them
}

rule TrickBot_Main {
    meta:
        description = "TrickBot banking trojan"
        severity = "critical"
    strings:
        $s1 = "TrickBot" nocase
        $s2 = "mcconf" ascii
        $s3 = "dpost" ascii
        $s4 = "dinj" ascii
        $s5 = "sinj" ascii
        $mod1 = "systeminfo" ascii
        $mod2 = "injectDll" ascii
    condition:
        any of ($s*) or 2 of ($mod*)
}

rule TrickBot_Module {
    meta:
        description = "TrickBot module"
        severity = "critical"
    strings:
        $s1 = "<moduleconfig>" ascii
        $s2 = "tabDll32" ascii
        $s3 = "tabDll64" ascii
        $s4 = "pwgrab" ascii
        $s5 = "networkDll" ascii
    condition:
        2 of them
}

rule Dridex_Main {
    meta:
        description = "Dridex banking trojan"
        severity = "critical"
    strings:
        $s1 = "dridex" nocase
        $s2 = "Bugat" nocase
        $s3 = "Cridex" nocase
        $cfg1 = {8B ?? ?? ?? ?? ?? 33 C0 89}
        $cfg2 = {C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ??}
    condition:
        any of ($s*) or all of ($cfg*)
}

rule QakBot_Main {
    meta:
        description = "QakBot/Qbot banking trojan"
        severity = "critical"
    strings:
        $s1 = "qakbot" nocase
        $s2 = "qbot" nocase
        $s3 = "stager_1" ascii
        $s4 = "spx102" ascii
        $str1 = "ProgramData" ascii
        $str2 = "%s\\%s.dll" ascii
    condition:
        any of ($s*) or 2 of ($str*)
}

rule IcedID_Main {
    meta:
        description = "IcedID/BokBot banking trojan"
        severity = "critical"
    strings:
        $s1 = "IcedID" nocase
        $s2 = "BokBot" nocase
        $s3 = {8B 45 ?? 89 45 ?? 8B 4D ?? 03 C8}
        $cfg = "Cookie: __gads=" ascii
    condition:
        any of ($s*) or $cfg
}

rule Ursnif_Gozi {
    meta:
        description = "Ursnif/Gozi banking trojan"
        severity = "critical"
    strings:
        $s1 = "ursnif" nocase
        $s2 = "gozi" nocase
        $s3 = "ISFB" ascii
        $s4 = "JJ-STRUCTURE" ascii
        $cfg = {C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ??}
    condition:
        any of ($s*) or $cfg
}

rule Hancitor_Loader {
    meta:
        description = "Hancitor/Chanitor loader"
        severity = "critical"
    strings:
        $s1 = "hancitor" nocase
        $s2 = "chanitor" nocase
        $s3 = "GUID=%I64u&" ascii
        $s4 = "&WIN=%s(%s)" ascii
    condition:
        any of them
}

rule Zloader_Main {
    meta:
        description = "Zloader banking trojan"
        severity = "critical"
    strings:
        $s1 = "zloader" nocase
        $s2 = "SILENT_ZLOADER" ascii
        $s3 = "botnet_id" ascii
        $s4 = "rc4_key" ascii
    condition:
        any of them
}

rule Ramnit_Main {
    meta:
        description = "Ramnit banking trojan"
        severity = "critical"
    strings:
        $s1 = "ramnit" nocase
        $s2 = {72 61 6D 6E 69 74}
        $s3 = "demetra" ascii
        $cfg = {8B 45 ?? 33 D2 F7 75 ?? 8B C2}
    condition:
        any of ($s*) or $cfg
}

rule Vawtrak_Main {
    meta:
        description = "Vawtrak/Neverquest banking trojan"
        severity = "critical"
    strings:
        $s1 = "vawtrak" nocase
        $s2 = "neverquest" nocase
        $s3 = "Snifula" nocase
        $cfg = {C7 45 ?? ?? ?? ?? ?? 8B 55}
    condition:
        any of ($s*) or $cfg
}

rule Tinba_Main {
    meta:
        description = "Tinba/TinyBanker"
        severity = "critical"
    strings:
        $s1 = "tinba" nocase
        $s2 = "tinybanker" nocase
        $s3 = {8D 85 ?? ?? FF FF 50 8D 85 ?? ?? FF FF 50}
    condition:
        any of them
}

rule Carbanak_Main {
    meta:
        description = "Carbanak banking malware"
        severity = "critical"
    strings:
        $s1 = "carbanak" nocase
        $s2 = "cobalt_gang" nocase
        $s3 = "anunak" nocase
        $s4 = "klgconfig.plug" ascii
        $s5 = "vnc.plug" ascii
    condition:
        any of them
}

rule BankBot_Android {
    meta:
        description = "BankBot Android banking trojan indicators"
        severity = "critical"
    strings:
        $s1 = "bankbot" nocase
        $s2 = "accessibility" ascii
        $s3 = "inject_html" ascii
        $s4 = "sms_intercept" ascii
    condition:
        2 of them
}

rule Anubis_Banking {
    meta:
        description = "Anubis Android banking trojan"
        severity = "critical"
    strings:
        $s1 = "anubis" nocase
        $s2 = "BankBot" ascii
        $s3 = "sms_listener" ascii
        $s4 = "keylogger_start" ascii
    condition:
        2 of them
}

rule Cerberus_Banking {
    meta:
        description = "Cerberus Android banking trojan"
        severity = "critical"
    strings:
        $s1 = "cerberus" nocase
        $s2 = "rat_connect" ascii
        $s3 = "overlay_inject" ascii
    condition:
        2 of them
}

rule Ginp_Banking {
    meta:
        description = "Ginp Android banking trojan"
        severity = "critical"
    strings:
        $s1 = "ginp" nocase
        $s2 = "flash_overlay" ascii
        $s3 = "grab_sms" ascii
    condition:
        2 of them
}

rule Grandoreiro_Main {
    meta:
        description = "Grandoreiro Latin American banking trojan"
        severity = "critical"
    strings:
        $s1 = "grandoreiro" nocase
        $delphi = {55 8B EC 83 C4 ?? 53 56 57}
        $s2 = "overlay_phishing" ascii
    condition:
        any of ($s*) or $delphi
}

rule Mekotio_Main {
    meta:
        description = "Mekotio Latin American banking trojan"
        severity = "critical"
    strings:
        $s1 = "mekotio" nocase
        $s2 = "bancos_latinos" ascii
        $autoit = "AutoIt" ascii
    condition:
        any of them
}
