/*
    Advanced APT Detection Rules - Extended Coverage
    Covers major APT groups with byte-level signatures
*/

rule APT_Cozy_Bear_SUNBURST {
    meta:
        description = "SolarWinds SUNBURST backdoor (APT29)"
        severity = "critical"
        author = "AI-Cerberus"
        reference = "CVE-2020-10148"
        mitre_attack = "T1195.002"
    strings:
        $a1 = "OrionImprovementBusinessLayer" ascii
        $a2 = "SolarWinds.Orion.Core.BusinessLayer" ascii
        $b1 = {C6 45 ?? 68 C6 45 ?? 74 C6 45 ?? 74 C6 45 ?? 70}
        $b2 = "avsvmcloud.com" ascii
        $b3 = "appsync-api" ascii
        $enc = {33 C0 8B ?? 33 ?? 89}
        $c1 = "RefreshInternal" ascii
        $c2 = "ExecuteEngine" ascii
    condition:
        uint16(0) == 0x5A4D and
        (any of ($a*) or (all of ($b*)) or ($enc and any of ($c*)))
}

rule APT_Hafnium_ProxyLogon {
    meta:
        description = "HAFNIUM ProxyLogon Exchange exploit"
        severity = "critical"
        mitre_attack = "T1190"
    strings:
        $s1 = "/ecp/DDI/DDIService.svc/SetObject" ascii
        $s2 = "/owa/auth/Current/themes/resources" ascii
        $s3 = "X-BEResource" ascii
        $s4 = "msExchCanary" ascii
        $sh1 = "Set-OabVirtualDirectory" ascii
        $sh2 = "ExternalUrl" ascii
        $webshell = "<%@ Page Language" ascii
    condition:
        3 of ($s*) or (2 of ($sh*) and $webshell)
}

rule APT_Fancy_Bear_Zebrocy {
    meta:
        description = "APT28 Zebrocy downloader (Go/Delphi variants)"
        severity = "critical"
    strings:
        $go1 = "main.downloadFile" ascii
        $go2 = "main.postData" ascii
        $go3 = "main.screenshot" ascii
        $d1 = "TFileStream" ascii
        $d2 = "TIdHTTP" ascii
        $d3 = "GetScreenShot" ascii
        $mutex = "Global\\{" ascii
        $cfg = {68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ??}
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($go*) or 2 of ($d*) or ($mutex and $cfg))
}

rule APT_Lazarus_MATA {
    meta:
        description = "Lazarus MATA framework"
        severity = "critical"
    strings:
        $s1 = "MATAv2" ascii
        $s2 = "mata.dll" ascii
        $s3 = "/c start /b" ascii
        $enc1 = {8B 45 ?? 33 45 ?? 89 45}
        $enc2 = {C1 E0 ?? 33 C1 89}
        $api1 = "VirtualAllocEx" ascii
        $api2 = "WriteProcessMemory" ascii
        $api3 = "CreateRemoteThread" ascii
    condition:
        uint16(0) == 0x5A4D and
        (any of ($s*) or (all of ($enc*)) or all of ($api*))
}

rule APT_DarkSide_Ransomware {
    meta:
        description = "DarkSide ransomware (Colonial Pipeline attack)"
        severity = "critical"
    strings:
        $s1 = "darkside" nocase
        $s2 = "Your network has been penetrated" ascii
        $s3 = ".onion" ascii
        $key = {48 8D 0D ?? ?? ?? ?? 48 89 ?? 24}
        $ext = ".darkside" ascii
        $ransom = "README" ascii
        $api1 = "CryptGenRandom" ascii
        $api2 = "CryptAcquireContext" ascii
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($s*) or ($key and $ext) or (all of ($api*) and $ransom))
}

rule APT_REvil_Sodinokibi {
    meta:
        description = "REvil/Sodinokibi ransomware"
        severity = "critical"
    strings:
        $cfg1 = "pk" ascii
        $cfg2 = "pid" ascii
        $cfg3 = "sub" ascii
        $cfg4 = "dbg" ascii
        $json = "{\"ver\":" ascii
        $ext = {2E ?? ?? ?? ?? ?? 00}
        $mutex = "Global\\206D87E0-0E60-DF25-DD8F-8E4E7D1E3BF0"
        $ransom = "-readme.txt" ascii
    condition:
        uint16(0) == 0x5A4D and
        (3 of ($cfg*) or ($json and $ext) or $mutex)
}

rule APT_Conti_Ransomware {
    meta:
        description = "Conti ransomware"
        severity = "critical"
    strings:
        $s1 = "CONTI" ascii
        $s2 = "All of your files are currently encrypted" ascii
        $api1 = "RtlGetVersion" ascii
        $api2 = "IoCompletionPort" ascii
        $mutex = "hsfjuukjzloqu28oajh727190" ascii
        $thread = {6A 00 6A 00 6A 00 68 ?? ?? ?? ?? 6A 00 6A 00}
    condition:
        uint16(0) == 0x5A4D and
        (any of ($s*) or $mutex or ($api1 and $api2 and $thread))
}

rule APT_Emotet_Loader {
    meta:
        description = "Emotet banking trojan/loader"
        severity = "critical"
    strings:
        $enc1 = {8B 45 ?? 8B 4D ?? 33 C1 89 45}
        $enc2 = {C1 E8 ?? 33 C0 8B}
        $api1 = "HttpOpenRequestA" ascii
        $api2 = "InternetConnectA" ascii
        $api3 = "HttpSendRequestA" ascii
        $str1 = "Content-Type: multipart/form-data" ascii
        $pdb = /[A-Z]:\\[^\\]+\\[^\\]+\.(pdb|PDB)/ ascii
    condition:
        uint16(0) == 0x5A4D and
        (all of ($enc*) or all of ($api*) or ($str1 and any of ($enc*)))
}

rule APT_Qakbot_Banking {
    meta:
        description = "Qakbot/QBot banking trojan"
        severity = "critical"
    strings:
        $str1 = "spx=" ascii
        $str2 = "stx=" ascii
        $str3 = "C:\\INTERNAL" ascii
        $cfg = {C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 8D}
        $rc4 = {33 C0 88 04 30 40 3D 00 01 00 00}
        $mutex = /[a-z]{5,10}\d{3,5}/ ascii
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($str*) or ($cfg and $rc4) or $mutex)
}

rule APT_TrickBot_Modules {
    meta:
        description = "TrickBot modular banker"
        severity = "critical"
    strings:
        $mod1 = "pwgrab" ascii
        $mod2 = "injectDll" ascii
        $mod3 = "systeminfo" ascii
        $mod4 = "networkDll" ascii
        $cfg = "<mcconf>" ascii
        $srv = "<srv>" ascii
        $enc = {8A 04 01 32 04 02 88 04 01 41}
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($mod*) or ($cfg and $srv) or $enc)
}

rule APT_BazarLoader {
    meta:
        description = "BazarLoader/BazarBackdoor"
        severity = "critical"
    strings:
        $s1 = "bazar" nocase
        $s2 = ".bazar" ascii
        $dns = "dns.google" ascii
        $api1 = "DnsQuery_A" ascii
        $api2 = "GetAdaptersInfo" ascii
        $enc = {48 8B ?? 48 33 ?? 48 89}
    condition:
        uint16(0) == 0x5A4D and
        (any of ($s*) or ($dns and any of ($api*)) or $enc)
}

rule APT_IcedID_Bokbot {
    meta:
        description = "IcedID/BokBot banking trojan"
        severity = "critical"
    strings:
        $s1 = "License.dat" ascii
        $s2 = "photo.png" ascii
        $s3 = "ieaborgnvnr" ascii
        $cfg = {C6 05 ?? ?? ?? ?? ?? C6 05 ?? ?? ?? ?? ??}
        $hook = "Hook" ascii
        $inject = "inject" ascii
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($s*) or ($cfg and ($hook or $inject)))
}

rule APT_Dridex_Evil_Corp {
    meta:
        description = "Dridex/Cridex banking trojan (Evil Corp)"
        severity = "critical"
    strings:
        $s1 = "botid=" ascii
        $s2 = "ver=" ascii
        $s3 = "modules" ascii
        $xml = "<root>" ascii
        $enc1 = {8B 45 ?? 33 45 ?? C1 C0}
        $enc2 = {32 04 08 88 04 0F 41}
        $api = "ZwQuerySystemInformation" ascii
    condition:
        uint16(0) == 0x5A4D and
        (all of ($s*) or ($xml and any of ($enc*)) or ($api and $enc1))
}

rule APT_Cobalt_Strike_Beacon_Config {
    meta:
        description = "Cobalt Strike beacon configuration"
        severity = "critical"
    strings:
        $cfg1 = {00 01 00 01 00 02}
        $cfg2 = {00 02 00 01 00 02}
        $str1 = "%02d/%02d/%02d %02d:%02d:%02d" ascii
        $str2 = "Started service" ascii
        $str3 = "beacon.dll" ascii
        $pipe = "\\\\.\\pipe\\" ascii
        $http = "Accept: */*" ascii
    condition:
        (any of ($cfg*) and $str1) or
        (any of ($str*) and ($pipe or $http))
}

rule APT_Metasploit_Meterpreter {
    meta:
        description = "Metasploit Meterpreter payload"
        severity = "critical"
    strings:
        $s1 = "metsrv.dll" ascii
        $s2 = "ReflectiveLoader" ascii
        $s3 = "stdapi_" ascii
        $s4 = "priv_" ascii
        $shell = {FC E8 ?? 00 00 00}
        $api1 = "ws2_32" ascii
        $api2 = "kernel32" ascii
    condition:
        (2 of ($s*)) or ($shell and all of ($api*))
}

rule APT_PowerShell_Empire {
    meta:
        description = "PowerShell Empire stager"
        severity = "critical"
    strings:
        $s1 = "FromBase64String" ascii
        $s2 = "Invoke-Empire" ascii
        $s3 = "-enc" ascii
        $s4 = "IEX" ascii
        $s5 = "DownloadString" ascii
        $s6 = "Net.WebClient" ascii
        $obf = /\$[a-zA-Z]{1,3}\s*=\s*\[char\]/ ascii
    condition:
        3 of ($s*) or (2 of ($s*) and $obf)
}

rule APT_Silver_C2 {
    meta:
        description = "Sliver C2 implant"
        severity = "critical"
    strings:
        $go1 = "sliverpb" ascii
        $go2 = "main.init" ascii
        $mtls = "h2" ascii
        $dns = "dns://" ascii
        $http = "https://" ascii
        $wg = "wg://" ascii
        $cfg = {48 8D 05 ?? ?? ?? ?? 48 89 ?? 24}
    condition:
        uint16(0) == 0x5A4D and
        ($go1 or ($go2 and (any of ($mtls, $dns, $http, $wg))))
}

rule APT_Brute_Ratel_C4 {
    meta:
        description = "Brute Ratel C4 red team tool"
        severity = "critical"
    strings:
        $s1 = "badger" ascii
        $s2 = "brc4" nocase
        $cfg = {41 B8 ?? ?? ?? ?? 48 8D}
        $xor = {44 30 04 01 48 FF C1}
        $api1 = "NtQueueApcThread" ascii
        $api2 = "NtAlertResumeThread" ascii
    condition:
        uint16(0) == 0x5A4D and
        (any of ($s*) or ($cfg and $xor) or all of ($api*))
}

rule APT_Mythic_Agent {
    meta:
        description = "Mythic C2 framework agents"
        severity = "critical"
    strings:
        $s1 = "mythic" nocase
        $s2 = "Apollo" ascii
        $s3 = "Medusa" ascii
        $go1 = "pkg/profiles" ascii
        $go2 = "pkg/utils" ascii
        $cfg = "callback_host" ascii
    condition:
        any of ($s*) or (any of ($go*) and $cfg)
}

rule APT_Chinese_APT_PlugX_Config {
    meta:
        description = "PlugX RAT configuration block"
        severity = "critical"
    strings:
        $cfg1 = {50 4C 55 47 58 21 21 21}
        $cfg2 = {58 47 55 4C 50 21 21 21}
        $str1 = "boot.ldr" ascii
        $str2 = "https://" ascii
        $dec = {8A 04 08 32 04 10 88 04 08}
    condition:
        uint16(0) == 0x5A4D and
        (any of ($cfg*) or (any of ($str*) and $dec))
}

rule APT_Iranian_Shamoon {
    meta:
        description = "Shamoon/DistTrack wiper"
        severity = "critical"
    strings:
        $s1 = "RawDisk" ascii
        $s2 = "\\??\\ElRawDisk" ascii
        $s3 = "\\Device\\Harddisk" ascii
        $wipe = {C7 00 00 00 00 00 C7 40 04 00 00 00 00}
        $mbr = {33 C0 8E D0 BC 00 7C}
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($s*) or $wipe or $mbr)
}

rule APT_Russian_NotPetya {
    meta:
        description = "NotPetya/ExPetr wiper"
        severity = "critical"
    strings:
        $s1 = "perfc.dat" ascii
        $s2 = "dllhost.dat" ascii
        $psexec = "psexec" ascii
        $wmi = "wmic" ascii
        $enc = {0F B6 04 01 32 04 0A 88 04 01}
        $mbr = "MBR" ascii
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($s*) or ($psexec and $wmi) or ($enc and $mbr))
}

rule APT_North_Korean_HOPLIGHT {
    meta:
        description = "HOPLIGHT backdoor (Hidden Cobra)"
        severity = "critical"
    strings:
        $s1 = "wtsapi32.dll" ascii
        $s2 = "netapi32.dll" ascii
        $s3 = "SYSTEM\\CurrentControlSet\\Services" ascii
        $enc = {33 C0 8A 04 08 32 04 10 88 04 08 40}
        $cert = "fake certificate" ascii
        $ssl = "SSL" ascii
    condition:
        uint16(0) == 0x5A4D and
        (all of ($s*) or ($enc and ($cert or $ssl)))
}

rule APT_Vietnamese_OceanLotus_MacOS {
    meta:
        description = "OceanLotus macOS backdoor"
        severity = "critical"
    strings:
        $s1 = "libobjc.A.dylib" ascii
        $s2 = "/tmp/.lock" ascii
        $s3 = "com.apple." ascii
        $plist = "CFBundleIdentifier" ascii
        $launch = "LaunchAgents" ascii
    condition:
        (uint32(0) == 0xFEEDFACE or uint32(0) == 0xFEEDFACF) and
        (2 of ($s*) or ($plist and $launch))
}
