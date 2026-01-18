/*
    Lateral Movement Technique Detection
    SMB, WMI, PsExec, remote services, and network propagation
*/

rule Lateral_PsExec {
    meta:
        description = "PsExec-style remote execution"
        severity = "high"
    strings:
        $svc1 = "OpenSCManager" ascii
        $svc2 = "CreateService" ascii
        $svc3 = "StartService" ascii
        $smb1 = "IPC$" ascii
        $smb2 = "ADMIN$" ascii
        $pipe = "\\\\.\\pipe\\" ascii
    condition:
        uint16(0) == 0x5A4D and (all of ($svc*) or (any of ($svc*) and any of ($smb*, $pipe)))
}

rule Lateral_WMI_Remote {
    meta:
        description = "WMI remote execution"
        severity = "high"
    strings:
        $wmi1 = "Win32_Process" ascii
        $wmi2 = "Win32_Service" ascii
        $wmi3 = "IWbemServices" ascii
        $wmi4 = "ExecMethod" ascii
        $create = "Create" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of ($wmi*) and $create
}

rule Lateral_SMB_Propagation {
    meta:
        description = "SMB network propagation"
        severity = "high"
    strings:
        $smb1 = "NetShareEnum" ascii
        $smb2 = "NetServerEnum" ascii
        $smb3 = "WNetAddConnection" ascii
        $smb4 = "WNetOpenEnum" ascii
        $share1 = "C$" ascii
        $share2 = "ADMIN$" ascii
    condition:
        uint16(0) == 0x5A4D and (2 of ($smb*) or (any of ($smb*) and any of ($share*)))
}

rule Lateral_Remote_Registry {
    meta:
        description = "Remote registry manipulation"
        severity = "high"
    strings:
        $reg1 = "RegConnectRegistry" ascii
        $reg2 = "RemoteRegistry" ascii
        $key1 = "CurrentVersion\\Run" ascii
        $key2 = "Services" ascii
    condition:
        uint16(0) == 0x5A4D and ($reg1 or $reg2) and any of ($key*)
}

rule Lateral_Pass_The_Hash {
    meta:
        description = "Pass-the-hash technique indicators"
        severity = "critical"
    strings:
        $lsa1 = "LsaLogonUser" ascii
        $lsa2 = "NtlmSsp" ascii
        $sam1 = "SAM" ascii
        $cred1 = "sekurlsa" ascii nocase
        $cred2 = "mimikatz" ascii nocase
        $ntlm = { 4E 54 4C 4D 53 53 50 }
    condition:
        uint16(0) == 0x5A4D and (2 of ($lsa*, $sam1) or any of ($cred*) or $ntlm)
}

rule Lateral_Remote_Desktop {
    meta:
        description = "RDP abuse for lateral movement"
        severity = "medium"
    strings:
        $rdp1 = "mstsc" ascii nocase
        $rdp2 = "termsrv.dll" ascii nocase
        $rdp3 = "Terminal Services" ascii
        $port = "3389" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}
