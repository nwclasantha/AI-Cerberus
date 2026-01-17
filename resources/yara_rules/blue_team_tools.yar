/*
    Blue Team Tools Detection
    Legitimate security tools that may be abused
*/

rule BlueTool_Mimikatz {
    meta:
        description = "Mimikatz credential dumper"
        severity = "critical"
    strings:
        $s1 = "mimikatz" ascii nocase
        $s2 = "gentilkiwi" ascii nocase
        $s3 = "sekurlsa" ascii nocase
        $s4 = "kiwi" ascii nocase
        $cmd1 = "sekurlsa::logonpasswords" ascii
        $cmd2 = "lsadump::sam" ascii
        $cmd3 = "privilege::debug" ascii
    condition:
        uint16(0) == 0x5A4D and ((any of ($s*)) or (any of ($cmd*)))
}

rule BlueTool_BloodHound {
    meta:
        description = "BloodHound AD analysis"
        severity = "high"
    strings:
        $s1 = "BloodHound" ascii nocase
        $s2 = "SharpHound" ascii nocase
        $ad = "Active Directory" ascii nocase
        $neo4j = "neo4j" ascii nocase
        $path = "path" ascii nocase
    condition:
        (any of ($s*)) and any of ($ad, $neo4j, $path)
}

rule BlueTool_Rubeus {
    meta:
        description = "Rubeus Kerberos tool"
        severity = "critical"
    strings:
        $s1 = "Rubeus" ascii nocase
        $kerberos = "Kerberos" ascii nocase
        $tgt = "TGT" ascii
        $tgs = "TGS" ascii
        $asrep = "asreproast" ascii nocase
        $kerb = "kerberoast" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($s1 or ($kerberos and any of ($tgt, $tgs, $asrep, $kerb)))
}

rule BlueTool_Impacket {
    meta:
        description = "Impacket toolkit"
        severity = "high"
    strings:
        $s1 = "impacket" ascii nocase
        $s2 = "SecureAuth" ascii nocase
        $psexec = "psexec" ascii nocase
        $wmiexec = "wmiexec" ascii nocase
        $smbexec = "smbexec" ascii nocase
        $secretsdump = "secretsdump" ascii nocase
    condition:
        (any of ($s*)) or (2 of ($psexec, $wmiexec, $smbexec, $secretsdump))
}

rule BlueTool_CrackMapExec {
    meta:
        description = "CrackMapExec network tool"
        severity = "high"
    strings:
        $s1 = "CrackMapExec" ascii nocase
        $s2 = "CME" ascii
        $s3 = "crackmapexec" ascii nocase
        $smb = "smb" ascii nocase
        $spray = "spray" ascii nocase
    condition:
        (any of ($s*)) and any of ($smb, $spray)
}

rule BlueTool_PowerSploit {
    meta:
        description = "PowerSploit framework"
        severity = "critical"
    strings:
        $s1 = "PowerSploit" ascii nocase
        $invoke1 = "Invoke-Mimikatz" ascii
        $invoke2 = "Invoke-TokenManipulation" ascii
        $invoke3 = "Invoke-Shellcode" ascii
        $invoke4 = "Get-GPPPassword" ascii
    condition:
        $s1 or (2 of ($invoke*))
}

rule BlueTool_Nmap {
    meta:
        description = "Nmap network scanner"
        severity = "medium"
    strings:
        $s1 = "nmap" ascii nocase
        $s2 = "Nmap" ascii
        $scan = "scan" ascii nocase
        $port = "port" ascii nocase
        $script = "script" ascii nocase
        $output = "-oX" ascii
    condition:
        (any of ($s*)) and any of ($scan, $port, $script, $output)
}

rule BlueTool_Netcat {
    meta:
        description = "Netcat network utility"
        severity = "high"
    strings:
        $s1 = "netcat" ascii nocase
        $s2 = "nc.exe" ascii nocase
        $s3 = "ncat" ascii nocase
        $listen = "-l" ascii
        $execute = "-e" ascii
        $verbose = "-v" ascii
    condition:
        (any of ($s*)) and (any of ($listen, $execute) or $verbose)
}

rule BlueTool_PsExec {
    meta:
        description = "PsExec remote execution"
        severity = "high"
    strings:
        $s1 = "PsExec" ascii nocase
        $s2 = "psexec.exe" ascii nocase
        $s3 = "Sysinternals" ascii nocase
        $service = "PSEXESVC" ascii
        $remote = "remote" ascii nocase
    condition:
        (any of ($s*)) and any of ($service, $remote)
}

rule BlueTool_WinRM {
    meta:
        description = "Windows Remote Management abuse"
        severity = "high"
    strings:
        $winrm = "WinRM" ascii nocase
        $wsman = "WSMan" ascii nocase
        $invoke = "Invoke-Command" ascii
        $session = "New-PSSession" ascii
        $remote = "remote" ascii nocase
    condition:
        (any of ($winrm, $wsman)) and any of ($invoke, $session, $remote)
}

rule BlueTool_LaZagne {
    meta:
        description = "LaZagne password recovery"
        severity = "critical"
    strings:
        $s1 = "LaZagne" ascii nocase
        $s2 = "lazagne" ascii nocase
        $password = "password" ascii nocase
        $browser = "browser" ascii nocase
        $wifi = "wifi" ascii nocase
    condition:
        (any of ($s*)) and any of ($password, $browser, $wifi)
}

rule BlueTool_Responder {
    meta:
        description = "Responder LLMNR poisoner"
        severity = "critical"
    strings:
        $s1 = "Responder" ascii nocase
        $s2 = "responder" ascii nocase
        $llmnr = "LLMNR" ascii
        $nbt = "NBT-NS" ascii
        $wpad = "WPAD" ascii
        $hash = "hash" ascii nocase
    condition:
        (any of ($s*)) and any of ($llmnr, $nbt, $wpad, $hash)
}

rule BlueTool_Burp_Suite {
    meta:
        description = "Burp Suite proxy"
        severity = "medium"
    strings:
        $s1 = "Burp Suite" ascii nocase
        $s2 = "BurpSuite" ascii nocase
        $s3 = "PortSwigger" ascii nocase
        $proxy = "proxy" ascii nocase
        $intercept = "intercept" ascii nocase
    condition:
        (any of ($s*)) and any of ($proxy, $intercept)
}

rule BlueTool_SQLMap {
    meta:
        description = "SQLMap injection tool"
        severity = "high"
    strings:
        $s1 = "sqlmap" ascii nocase
        $s2 = "SQLMap" ascii nocase
        $sql = "SQL" ascii
        $inject = "injection" ascii nocase
        $dump = "dump" ascii nocase
    condition:
        (any of ($s*)) and any of ($sql, $inject, $dump)
}

rule BlueTool_Hashcat {
    meta:
        description = "Hashcat password cracker"
        severity = "high"
    strings:
        $s1 = "hashcat" ascii nocase
        $s2 = "Hashcat" ascii
        $hash = "hash" ascii nocase
        $crack = "crack" ascii nocase
        $mode = "-m" ascii
    condition:
        (any of ($s*)) and any of ($hash, $crack, $mode)
}

rule BlueTool_Covenant {
    meta:
        description = "Covenant C2 framework"
        severity = "critical"
    strings:
        $s1 = "Covenant" ascii nocase
        $grunt = "Grunt" ascii nocase
        $c2 = "C2" ascii
        $implant = "implant" ascii nocase
        $listener = "listener" ascii nocase
    condition:
        $s1 and any of ($grunt, $c2, $implant, $listener)
}

rule BlueTool_SharpCollection {
    meta:
        description = "Sharp offensive tools"
        severity = "critical"
    strings:
        $sharp1 = "SharpHound" ascii
        $sharp2 = "SharpDump" ascii
        $sharp3 = "SharpRoast" ascii
        $sharp4 = "SharpWMI" ascii
        $sharp5 = "SharpDPAPI" ascii
        $sharp6 = "SharpChrome" ascii
    condition:
        uint16(0) == 0x5A4D and (2 of ($sharp*))
}

rule BlueTool_Seatbelt {
    meta:
        description = "Seatbelt enumeration"
        severity = "high"
    strings:
        $s1 = "Seatbelt" ascii nocase
        $s2 = "GhostPack" ascii nocase
        $enum = "enum" ascii nocase
        $system = "system" ascii nocase
        $all = "-group=all" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ((any of ($s*)) and any of ($enum, $system, $all))
}

rule BlueTool_WinPEAS {
    meta:
        description = "WinPEAS privilege escalation"
        severity = "high"
    strings:
        $s1 = "winPEAS" ascii nocase
        $s2 = "WinPEAS" ascii
        $priv = "privilege" ascii nocase
        $escalate = "escalat" ascii nocase
        $enum = "enum" ascii nocase
    condition:
        (any of ($s*)) and any of ($priv, $escalate, $enum)
}

rule BlueTool_Certify {
    meta:
        description = "Certify AD CS tool"
        severity = "critical"
    strings:
        $s1 = "Certify" ascii nocase
        $adcs = "AD CS" ascii nocase
        $cert = "certificate" ascii nocase
        $template = "template" ascii nocase
        $vuln = "vulnerable" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($s1 and any of ($adcs, $cert, $template, $vuln))
}

