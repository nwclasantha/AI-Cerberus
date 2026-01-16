/*
    Loader and Dropper Detection Rules
    Covers: BazarLoader, IcedID loader, Bumblebee, etc.
*/

rule BazarLoader {
    meta:
        description = "BazarLoader/BazarBackdoor"
        severity = "critical"
    strings:
        $s1 = "BazarLoader" ascii
        $s2 = "Bazar" ascii
        $s3 = {8B 45 ?? 89 45 ?? 8B 4D ?? 03 4D ??}
        $dns = "bazar" ascii
    condition:
        any of ($s*) or $dns
}

rule Bumblebee_Loader {
    meta:
        description = "Bumblebee loader"
        severity = "critical"
    strings:
        $s1 = "bumblebee" nocase
        $s2 = "wab.exe" ascii
        $s3 = "PowerShell" ascii
        $dll = "gzip" ascii
    condition:
        any of ($s*) or $dll
}

rule IcedID_Loader {
    meta:
        description = "IcedID/BokBot loader"
        severity = "critical"
    strings:
        $s1 = "IcedID" nocase
        $s2 = "__gads=" ascii
        $s3 = {C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ??}
    condition:
        any of them
}

rule QakBot_Loader {
    meta:
        description = "QakBot loader DLL"
        severity = "critical"
    strings:
        $s1 = "qakbot" nocase
        $s2 = "regsvr32" ascii
        $s3 = "rundll32" ascii
        $dll = "DllRegisterServer" ascii
    condition:
        any of ($s*) or $dll
}

rule Emotet_Loader_Module {
    meta:
        description = "Emotet loader module"
        severity = "critical"
    strings:
        $s1 = "emotet" nocase
        $s2 = {8B 45 ?? 83 C0 ?? 50 8B 4D ?? 51}
        $http = "Content-Type:" ascii
    condition:
        any of ($s*) or $http
}

rule SmokeLoader {
    meta:
        description = "SmokeLoader"
        severity = "critical"
    strings:
        $s1 = "smokeloader" nocase
        $s2 = "smoke" nocase
        $s3 = {33 C0 8A 04 01 32 04 02 88 04 01}
    condition:
        any of them
}

rule Guloader {
    meta:
        description = "GuLoader/CloudEyE"
        severity = "critical"
    strings:
        $s1 = "guloader" nocase
        $s2 = "cloudeye" nocase
        $vbs = "VirtualAlloc" ascii
        $shell = "shellcode" ascii
    condition:
        any of ($s*) or ($vbs and $shell)
}

rule Amadey_Loader {
    meta:
        description = "Amadey bot loader"
        severity = "critical"
    strings:
        $s1 = "amadey" nocase
        $s2 = "/Plugins/" ascii
        $s3 = "cred.dll" ascii
        $bot = "botid" ascii
    condition:
        any of ($s*) or $bot
}

rule SystemBC_Proxy {
    meta:
        description = "SystemBC proxy loader"
        severity = "critical"
    strings:
        $s1 = "systembc" nocase
        $s2 = "socks5" ascii
        $s3 = "tor_proxy" ascii
    condition:
        any of them
}

rule Vidar_Loader {
    meta:
        description = "Vidar stealer loader"
        severity = "critical"
    strings:
        $s1 = "vidar" nocase
        $s2 = "arkei" nocase
        $s3 = {C7 45 ?? ?? ?? ?? ?? 89 45 ??}
    condition:
        any of them
}

rule RedLine_Loader {
    meta:
        description = "RedLine stealer loader"
        severity = "critical"
    strings:
        $s1 = "RedLine" ascii
        $s2 = "redline" ascii
        $s3 = "ScanDetails" ascii
        $net = "Yandex" ascii
    condition:
        any of ($s*) or $net
}

rule Raccoon_Loader {
    meta:
        description = "Raccoon stealer loader"
        severity = "critical"
    strings:
        $s1 = "Raccoon" ascii
        $s2 = "raccoon" ascii
        $s3 = "machineId" ascii
    condition:
        any of them
}

rule Danabot_Loader {
    meta:
        description = "DanaBot loader"
        severity = "critical"
    strings:
        $s1 = "danabot" nocase
        $s2 = "dana" nocase
        $s3 = {8D 85 ?? ?? FF FF 50}
    condition:
        any of them
}

rule SocGholish_FakeUpdate {
    meta:
        description = "SocGholish fake update loader"
        severity = "critical"
    strings:
        $s1 = "socgholish" nocase
        $s2 = "update" ascii
        $js = "javascript" nocase
        $zip = ".zip" ascii
    condition:
        any of ($s*) or ($js and $zip)
}

rule Gootloader {
    meta:
        description = "GootLoader JavaScript loader"
        severity = "critical"
    strings:
        $s1 = "gootloader" nocase
        $s2 = "gootkit" nocase
        $js = "eval(" ascii
        $obf = "String.fromCharCode" ascii
    condition:
        any of ($s*) or ($js and $obf)
}

rule Hancitor_Loader {
    meta:
        description = "Hancitor/Chanitor loader"
        severity = "critical"
    strings:
        $s1 = "hancitor" nocase
        $s2 = "chanitor" nocase
        $s3 = "GUID=" ascii
        $s4 = "WIN=" ascii
    condition:
        any of them
}

rule Zloader_Loader {
    meta:
        description = "Zloader loader component"
        severity = "critical"
    strings:
        $s1 = "zloader" nocase
        $s2 = "botnet" ascii
        $s3 = "silent" ascii
    condition:
        2 of them
}

rule PrivateLoader {
    meta:
        description = "PrivateLoader PPI service"
        severity = "critical"
    strings:
        $s1 = "privateloader" nocase
        $s2 = "PPI" ascii
        $s3 = "install" ascii
    condition:
        2 of them
}

rule NullMixer_Dropper {
    meta:
        description = "NullMixer dropper"
        severity = "critical"
    strings:
        $s1 = "nullmixer" nocase
        $s2 = "software crack" ascii
        $s3 = "keygen" nocase
    condition:
        any of them
}

rule CryptBot_Loader {
    meta:
        description = "CryptBot loader"
        severity = "critical"
    strings:
        $s1 = "cryptbot" nocase
        $s2 = "cryptonightv7" ascii
        $s3 = "clipper" ascii
    condition:
        any of them
}

rule Mars_Stealer_Loader {
    meta:
        description = "Mars Stealer loader"
        severity = "critical"
    strings:
        $s1 = "MarsTeam" ascii
        $s2 = "mars" nocase
        $s3 = "grabber" ascii
    condition:
        2 of them
}

rule Pikabot_Loader {
    meta:
        description = "Pikabot loader"
        severity = "critical"
    strings:
        $s1 = "pikabot" nocase
        $s2 = "pika" ascii
        $net = "POST" ascii
    condition:
        any of ($s*) or $net
}

rule DarkGate_Loader {
    meta:
        description = "DarkGate loader"
        severity = "critical"
    strings:
        $s1 = "darkgate" nocase
        $s2 = "autoit" nocase
        $s3 = "crypto" ascii
    condition:
        any of them
}

rule Generic_JS_Dropper {
    meta:
        description = "Generic JavaScript dropper"
        severity = "high"
    strings:
        $s1 = "WScript.Shell" ascii
        $s2 = "ActiveXObject" ascii
        $s3 = "Scripting.FileSystemObject" ascii
        $s4 = "powershell" nocase
        $s5 = "cmd /c" nocase
    condition:
        2 of them
}

rule Generic_VBS_Dropper {
    meta:
        description = "Generic VBS dropper"
        severity = "high"
    strings:
        $s1 = "CreateObject" ascii
        $s2 = "WScript" ascii
        $s3 = "Shell" ascii
        $s4 = "Run" ascii
        $exec = "cmd.exe" nocase
    condition:
        3 of ($s*) or $exec
}

rule Generic_HTA_Dropper {
    meta:
        description = "Generic HTA dropper"
        severity = "high"
    strings:
        $hta1 = "<HTA:APPLICATION" nocase
        $hta2 = "<script" nocase
        $exec1 = "WScript.Shell" ascii
        $exec2 = "powershell" nocase
    condition:
        any of ($hta*) and any of ($exec*)
}

rule Generic_PowerShell_Dropper {
    meta:
        description = "Generic PowerShell dropper"
        severity = "high"
    strings:
        $s1 = "IEX" ascii
        $s2 = "Invoke-Expression" ascii
        $s3 = "DownloadString" ascii
        $s4 = "DownloadFile" ascii
        $s5 = "WebClient" ascii
        $b64 = "FromBase64String" ascii
    condition:
        2 of them
}
