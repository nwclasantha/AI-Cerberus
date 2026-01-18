/*
    Backdoor and RAT Detection Rules
    Covers: Cobalt Strike, Meterpreter, njRAT, DarkComet, etc.
*/

rule CobaltStrike_Beacon {
    meta:
        description = "Cobalt Strike Beacon"
        severity = "critical"
    strings:
        $s1 = "beacon.dll" ascii
        $s2 = "%02d/%02d/%02d %02d:%02d:%02d" ascii
        $s3 = "ReflectiveLoader" ascii
        $s4 = "%s as %s\\%s: %d" ascii
        $s5 = "Started service %s on %s" ascii
        $s6 = "beacon.x64.dll" ascii
    condition:
        2 of them
}

rule CobaltStrike_Malleable {
    meta:
        description = "Cobalt Strike malleable profile indicators"
        severity = "critical"
    strings:
        $s1 = "sleeptime" ascii
        $s2 = "jitter" ascii
        $s3 = "useragent" ascii
        $s4 = "http-get" ascii
        $s5 = "http-post" ascii
    condition:
        3 of them
}

rule Meterpreter_Stager {
    meta:
        description = "Metasploit Meterpreter stager"
        severity = "critical"
    strings:
        $s1 = "metsrv" ascii
        $s2 = "meterpreter" nocase
        $s3 = "stdapi" ascii
        $s4 = "reverse_tcp" ascii
        $s5 = "bind_tcp" ascii
        $shellcode = {FC E8 82 00 00 00}
    condition:
        any of ($s*) or $shellcode
}

rule Meterpreter_Reverse_Shell {
    meta:
        description = "Meterpreter reverse shell"
        severity = "critical"
    strings:
        $s1 = {FC E8 ?? 00 00 00}
        $s2 = "ws2_32" ascii
        // UNUSED: $s3 = "kernel32" ascii
        $api1 = "VirtualAlloc" ascii
        $api2 = "CreateThread" ascii
    condition:
        ($s1 and $s2) or all of ($api*)
}

rule njRAT_Main {
    meta:
        description = "njRAT remote access trojan"
        severity = "critical"
    strings:
        $s1 = "njRAT" ascii
        $s2 = "njq8" ascii
        $s3 = "Bladabindi" nocase
        $s4 = "|'|'|" ascii
        $s5 = "netsh firewall add" ascii
        $vbs = "im523" ascii
    condition:
        any of them
}

rule DarkComet_RAT {
    meta:
        description = "DarkComet RAT"
        severity = "critical"
    strings:
        $s1 = "DarkComet" ascii
        $s2 = "DCRAT" ascii
        $s3 = "#BOT#" ascii
        $s4 = "EditServer" ascii
        $mutex = "DC_MUTEX" ascii
    condition:
        any of them
}

rule QuasarRAT_Main {
    meta:
        description = "Quasar RAT"
        severity = "critical"
    strings:
        $s1 = "QuasarRAT" ascii
        $s2 = "Quasar.Client" ascii
        $s3 = "xRAT" ascii
        $s4 = "QuasarClient" ascii
        $net = "set_IsProxy" ascii
    condition:
        any of them
}

rule AsyncRAT_Main {
    meta:
        description = "AsyncRAT"
        severity = "critical"
    strings:
        $s1 = "AsyncRAT" ascii
        $s2 = "AsyncClient" ascii
        $s3 = "Async_Client" ascii
        $s4 = "ServerIP" ascii
        $s5 = "Pastebin" ascii
    condition:
        2 of them
}

rule RemcosRAT_Main {
    meta:
        description = "Remcos RAT"
        severity = "critical"
    strings:
        $s1 = "Remcos" ascii
        $s2 = "Breaking-Security" ascii
        $s3 = "remcos.exe" ascii
        $s4 = "licence" ascii
        $settings = {C6 45 ?? ?? C6 45 ?? ?? C6 45 ?? ??}
    condition:
        any of ($s*) or $settings
}

rule NanoCore_RAT {
    meta:
        description = "NanoCore RAT"
        severity = "critical"
    strings:
        $s1 = "NanoCore" ascii
        $s2 = "ClientPlugin" ascii
        $s3 = "NanoCoreBase" ascii
        $s4 = "PluginCommand" ascii
        $guid = "{GUID}" ascii
    condition:
        2 of ($s*) or $guid
}

rule Poison_Ivy_RAT {
    meta:
        description = "Poison Ivy RAT"
        severity = "critical"
    strings:
        $s1 = "Poison Ivy" ascii
        $s2 = "PIVY" ascii
        $s3 = {8D 85 ?? ?? FF FF 50 FF 15}
        $stub = "admin" ascii
        $init = {E8 ?? ?? ?? ?? 83 C4 0C 68}
    condition:
        any of ($s*) or ($stub and $init)
}

rule Gh0st_RAT {
    meta:
        description = "Gh0st RAT"
        severity = "critical"
    strings:
        $s1 = "Gh0st" ascii
        $s2 = "gh0st" ascii
        $s3 = {67 68 30 73 74}
        $magic = "Gh0st" ascii
        $screen = "ScreenManager" ascii
    condition:
        any of them
}

rule PlugX_RAT {
    meta:
        description = "PlugX/Korplug RAT"
        severity = "critical"
    strings:
        $s1 = "PLUG" ascii
        $s2 = "boot.ldr" ascii
        $s3 = "http://%s:%d/%s/%s" ascii
        $cfg = {50 4C 55 47}
    condition:
        2 of ($s*) or $cfg
}

rule NetWire_RAT {
    meta:
        description = "NetWire RAT"
        severity = "critical"
    strings:
        $s1 = "NetWire" ascii
        $s2 = "netwire" ascii
        $s3 = "%08lX%04lX%lu" ascii
        $mutex = "NetWire" ascii
        $host = "HostId" ascii
    condition:
        2 of them
}

rule Warzone_RAT {
    meta:
        description = "Warzone/AveMaria RAT"
        severity = "critical"
    strings:
        $s1 = "Warzone" ascii
        $s2 = "AveMaria" ascii
        $s3 = "AVE_MARIA" ascii
        $s4 = "warzone" nocase
    condition:
        any of them
}

rule Agent_Tesla {
    meta:
        description = "Agent Tesla keylogger/RAT"
        severity = "critical"
    strings:
        $s1 = "AgentTesla" ascii
        $s2 = "AgenTesla" ascii
        $s3 = "smtp.yandex.com" ascii
        $s4 = "WebPanel" ascii
        $net = "System.Net.Mail" ascii
    condition:
        any of ($s*) or $net
}

rule FormBook_Stealer {
    meta:
        description = "FormBook form grabber"
        severity = "critical"
    strings:
        $s1 = "FormBook" ascii
        $s2 = "xloader" ascii
        $s3 = {8B 45 ?? 89 45 ?? 8B 4D ?? 89 4D ??}
        $sha1 = "sha1" ascii
    condition:
        any of ($s*) or $sha1
}

rule LokiBot_Stealer {
    meta:
        description = "LokiBot password stealer"
        severity = "critical"
    strings:
        $s1 = "LokiBot" ascii
        $s2 = "loki" ascii
        $s3 = {8D 85 ?? ?? FF FF 50 8D 85 ?? ?? FF FF}
        $ftp = "ftp://" ascii
    condition:
        any of ($s*) or $ftp
}

rule Predator_Pain_RAT {
    meta:
        description = "Predator Pain RAT"
        severity = "critical"
    strings:
        $s1 = "Predator" ascii
        $s2 = "Pain" ascii
        $s3 = "HawkEye" ascii
        $key = "keylog" ascii
    condition:
        2 of ($s*) or $key
}

rule HawkEye_Keylogger {
    meta:
        description = "HawkEye keylogger"
        severity = "critical"
    strings:
        $s1 = "HawkEye" ascii
        $s2 = "Reborn" ascii
        $s3 = "smtp" ascii
        $s4 = "ftp" ascii
        $key = "keystrokes" ascii
    condition:
        2 of ($s*) or $key
}

rule Orcus_RAT {
    meta:
        description = "Orcus RAT"
        severity = "critical"
    strings:
        $s1 = "Orcus" ascii
        $s2 = "OrcusRAT" ascii
        $s3 = "OrcusAdministration" ascii
        $net = "get_Plugins" ascii
    condition:
        any of them
}

rule Imminent_Monitor {
    meta:
        description = "Imminent Monitor RAT"
        severity = "critical"
    strings:
        $s1 = "Imminent" ascii
        $s2 = "Monitor" ascii
        $s3 = "ImminentMonitor" ascii
        $s4 = "IRatClient" ascii
    condition:
        2 of them
}

rule RevengeRAT {
    meta:
        description = "RevengeRAT"
        severity = "critical"
    strings:
        $s1 = "RevengeRAT" ascii
        $s2 = "Revenge-RAT" ascii
        $s3 = "nuclear" ascii
        $socket = "Socket" ascii
    condition:
        any of ($s*) or $socket
}

rule VenomRAT {
    meta:
        description = "VenomRAT"
        severity = "critical"
    strings:
        $s1 = "VenomRAT" ascii
        $s2 = "Venom" ascii
        $s3 = "QuasarClone" ascii
        $net = "ClientSocket" ascii
    condition:
        any of ($s*) or $net
}

rule DcRAT {
    meta:
        description = "DcRAT"
        severity = "critical"
    strings:
        $s1 = "DcRAT" ascii
        $s2 = "DarkCrystal" ascii
        $s3 = "dcrat" ascii
        $cfg = "config.json" ascii
    condition:
        any of them
}

rule BitRAT {
    meta:
        description = "BitRAT"
        severity = "critical"
    strings:
        $s1 = "BitRAT" ascii
        $s2 = "bitrat" ascii
        $s3 = "hvnc" ascii
        $tor = ".onion" ascii
    condition:
        any of ($s*) or $tor
}
