/*
    Command and Control Frameworks Detection
    Commercial and open-source C2 frameworks
*/

rule C2_Cobalt_Strike_Beacon {
    meta:
        description = "Cobalt Strike Beacon"
        severity = "critical"
    strings:
        $s1 = "beacon.dll" ascii
        $s2 = "beacon.x64.dll" ascii
        $s3 = "%s as %s\\%s: %d" ascii
        $s4 = "powershell -nop -exec bypass" ascii
        $s5 = "IEX (New-Object Net.Webclient).DownloadString" ascii
        $cfg1 = { 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 ?? ?? }
        $cfg2 = { 69 68 69 68 69 6B ?? ?? }
    condition:
        uint16(0) == 0x5A4D and (2 of ($s*) or any of ($cfg*))
}

rule C2_Cobalt_Strike_Stager {
    meta:
        description = "Cobalt Strike Stager"
        severity = "critical"
    strings:
        $mz = { 4D 5A }
        $str1 = "%d.%d.%d.%d" ascii
        $str2 = "%02d/%02d/%02d %02d:%02d:%02d" ascii
        $api1 = "VirtualAlloc" ascii
        $api2 = "InternetOpenA" ascii
        $api3 = "InternetConnectA" ascii
        $api4 = "HttpOpenRequestA" ascii
    condition:
        $mz at 0 and all of ($api*) and any of ($str*)
}

rule C2_Metasploit_Meterpreter {
    meta:
        description = "Metasploit Meterpreter payload"
        severity = "critical"
    strings:
        $s1 = "metsrv" ascii
        $s2 = "stdapi" ascii
        $s3 = "priv" ascii
        $s4 = "extapi" ascii
        $api1 = "ReflectiveLoader" ascii
        $api2 = "MZ" ascii
        $rev = "reverse_" ascii
        $shell = "_meterpreter" ascii
    condition:
        uint16(0) == 0x5A4D and ((2 of ($s*)) or $api1 or ($rev and $shell))
}

rule C2_Empire_PowerShell {
    meta:
        description = "PowerShell Empire agent"
        severity = "critical"
    strings:
        $s1 = "Invoke-Empire" ascii nocase
        $s2 = "Get-Keystrokes" ascii nocase
        $s3 = "Invoke-Mimikatz" ascii nocase
        $s4 = "New-GPOImmediateTask" ascii nocase
        $enc1 = "-enc" ascii nocase
        $enc2 = "FromBase64String" ascii nocase
        $iex = "IEX" ascii
    condition:
        (2 of ($s*)) or (($enc1 or $enc2) and $iex)
}

rule C2_Covenant_Grunt {
    meta:
        description = "Covenant C2 Grunt implant"
        severity = "critical"
    strings:
        $s1 = "GruntHTTP" ascii
        $s2 = "GruntSMB" ascii
        $s3 = "Covenant" ascii
        $s4 = "ExecuteStager" ascii
        $s5 = "GetMessageFormat" ascii
        $api = "AssemblyLoadContext" ascii
    condition:
        uint16(0) == 0x5A4D and (2 of ($s*) or ($api and any of ($s*)))
}

rule C2_Sliver_Implant {
    meta:
        description = "Sliver C2 implant"
        severity = "critical"
    strings:
        $go = "Go build" ascii
        $s1 = "sliver" ascii nocase
        $s2 = "bishopfox" ascii nocase
        $s3 = "sliverpb" ascii
        $s4 = "implant/sliver" ascii
        $pivot = "pivot" ascii nocase
        $mtls = "mtls" ascii nocase
    condition:
        uint32(0) == 0x464C457F and $go and (2 of ($s*) or ($pivot and $mtls))
}

rule C2_Brute_Ratel {
    meta:
        description = "Brute Ratel C4 framework"
        severity = "critical"
    strings:
        $s1 = "BruteRatel" ascii nocase
        $s2 = "badger" ascii nocase
        $s3 = "BRc4" ascii
        $s4 = "DarkVortex" ascii nocase
        $cfg = "config.json" ascii
        $smb = "smb_pipe" ascii
    condition:
        uint16(0) == 0x5A4D and (2 of ($s*) or ($cfg and any of ($smb)))
}

rule C2_Havoc_Framework {
    meta:
        description = "Havoc C2 framework"
        severity = "critical"
    strings:
        $s1 = "Havoc" ascii nocase
        $s2 = "Demon" ascii nocase
        $s3 = "HavocClient" ascii
        $s4 = "teamserver" ascii nocase
        $api1 = "NtQueueApcThread" ascii
        $api2 = "NtAllocateVirtualMemory" ascii
    condition:
        uint16(0) == 0x5A4D and (2 of ($s*) or (all of ($api*) and any of ($s*)))
}

rule C2_PoshC2 {
    meta:
        description = "PoshC2 framework"
        severity = "critical"
    strings:
        $s1 = "PoshC2" ascii nocase
        $s2 = "nishang" ascii nocase
        $s3 = "dropper" ascii nocase
        $ps1 = "Invoke-Shellcode" ascii
        $ps2 = "Get-GPPPassword" ascii
        $ps3 = "Invoke-TokenManipulation" ascii
    condition:
        (2 of ($s*)) or (2 of ($ps*))
}

rule C2_Mythic_Agent {
    meta:
        description = "Mythic C2 agent"
        severity = "critical"
    strings:
        $s1 = "Mythic" ascii nocase
        $s2 = "Apollo" ascii nocase
        $s3 = "Apfell" ascii nocase
        $s4 = "Poseidon" ascii nocase
        $s5 = "Athena" ascii nocase
        $cfg = "mythic_config" ascii
    condition:
        (2 of ($s*)) or $cfg
}

rule C2_SilentTrinity {
    meta:
        description = "SilentTrinity BOOLANG"
        severity = "critical"
    strings:
        $s1 = "SILENTTRINITY" ascii nocase
        $s2 = "boolang" ascii nocase
        $s3 = "st_client" ascii
        $ironpython = "IronPython" ascii
        $boo = ".boo" ascii
    condition:
        uint16(0) == 0x5A4D and (2 of ($s*) or ($ironpython and $boo))
}

rule C2_Merlin_Agent {
    meta:
        description = "Merlin C2 agent"
        severity = "critical"
    strings:
        $go = "Go build" ascii
        $s1 = "merlin" ascii nocase
        $s2 = "ne0nd0g" ascii nocase
        $s3 = "http2" ascii nocase
        $s4 = "h2c" ascii
        $agent = "agent/agent" ascii
    condition:
        $go and (2 of ($s*) or $agent)
}

rule C2_Koadic_COM {
    meta:
        description = "Koadic COM-based C2"
        severity = "critical"
    strings:
        $s1 = "koadic" ascii nocase
        $s2 = "zerosum0x0" ascii nocase
        $js = "WScript.Shell" ascii
        $com1 = "ActiveXObject" ascii
        $com2 = "Scripting.FileSystemObject" ascii
        $wmi = "winmgmts" ascii nocase
    condition:
        (any of ($s*)) or (($js or $wmi) and (any of ($com*)))
}

rule C2_SILENTTRINITY_Stager {
    meta:
        description = "SILENTTRINITY stager"
        severity = "critical"
    strings:
        $s1 = "SILENTTRINITY" ascii nocase
        $s2 = "naga" ascii
        $python = "IronPython" ascii
        $stage = "stager" ascii nocase
        $boo = "Boo.Lang" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($s*) or ($python and any of ($stage, $boo)))
}

rule C2_Faction_Framework {
    meta:
        description = "Faction C2 framework"
        severity = "critical"
    strings:
        $s1 = "FactionC2" ascii nocase
        $s2 = "Faction" ascii nocase
        $s3 = "Marauder" ascii
        $agent = "FactionAgent" ascii
        $api = "ApiController" ascii
    condition:
        uint16(0) == 0x5A4D and (2 of ($s*) or ($agent and $api))
}

rule C2_Nuages_Framework {
    meta:
        description = "Nuages C2 framework"
        severity = "critical"
    strings:
        $s1 = "Nuages" ascii nocase
        $s2 = "p3nt4" ascii
        $implant = "NuagesImplant" ascii
        $api = "implant_api" ascii
        $handler = "handler" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($s*) or ($implant and any of ($api, $handler)))
}

rule C2_Pupy_RAT {
    meta:
        description = "Pupy RAT framework"
        severity = "critical"
    strings:
        $s1 = "pupy" ascii nocase
        $s2 = "rpyc" ascii
        $s3 = "n1nj4sec" ascii
        $python = "Python" ascii
        $payload = "pupyimporter" ascii
    condition:
        (2 of ($s*)) or ($python and $payload)
}

rule C2_Villain {
    meta:
        description = "Villain C2 framework"
        severity = "critical"
    strings:
        $s1 = "Villain" ascii nocase
        $s2 = "t3l3machus" ascii
        $hoax = "Hoaxshell" ascii nocase
        $shell = "reverse" ascii nocase
        $ps = "PowerShell" ascii nocase
    condition:
        (any of ($s*)) or ($hoax and any of ($shell, $ps))
}

rule C2_DeimosC2 {
    meta:
        description = "DeimosC2 framework"
        severity = "critical"
    strings:
        $go = "Go build" ascii
        $s1 = "DeimosC2" ascii nocase
        $s2 = "Deimos" ascii nocase
        $agent = "agent/agent" ascii
        $c2 = "c2/c2" ascii
    condition:
        $go and (any of ($s*) or ($agent and $c2))
}

rule C2_Generic_Indicators {
    meta:
        description = "Generic C2 framework indicators"
        severity = "high"
    strings:
        $beacon = "beacon" ascii nocase
        $implant = "implant" ascii nocase
        $stager = "stager" ascii nocase
        $agent = "agent" ascii nocase
        $handler = "handler" ascii nocase
        $listener = "listener" ascii nocase
        $shellcode = "shellcode" ascii nocase
        $callback = "callback" ascii nocase
        $checkin = "checkin" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (4 of them)
}

