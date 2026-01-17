/*
    Lateral Movement Technique Detection
    SMB, WMI, PsExec, remote services, and network propagation
*/

rule LateralMovement_PsExec {
    meta:
        description = "PsExec or similar remote execution"
        severity = "critical"
    strings:
        $s1 = "PSEXESVC" ascii
        $s2 = "psexec" ascii nocase
        $s3 = "paexec" ascii nocase
        $s4 = "remcom" ascii nocase
        $pipe = "\\pipe\\" ascii
        $admin = "ADMIN$" ascii
        $ipc = "IPC$" ascii
        $scm = "OpenSCManager" ascii
    condition:
        uint16(0) == 0x5A4D and
        (any of ($s*) or (($admin or $ipc) and ($pipe or $scm)))
}

rule LateralMovement_WMI {
    meta:
        description = "WMI-based remote execution"
        severity = "high"
    strings:
        $wmi1 = "Win32_Process" ascii
        $wmi2 = "Win32_ProcessStartup" ascii
        $wmi3 = "Win32_ScheduledJob" ascii
        $create = "Create" ascii
        $method = "ExecMethod" ascii
        $connect = "ConnectServer" ascii
        $root = "root\\cimv2" ascii nocase
        $cred = "Credentials" ascii
    condition:
        uint16(0) == 0x5A4D and
        (any of ($wmi*) and ($create or $method)) or ($connect and $root and $cred)
}

rule LateralMovement_DCOM {
    meta:
        description = "DCOM-based remote execution"
        severity = "high"
    strings:
        $dcom1 = "MMC20.Application" ascii
        $dcom2 = "ShellBrowserWindow" ascii
        $dcom3 = "ShellWindows" ascii
        $dcom4 = "Excel.Application" ascii
        $dcom5 = "Outlook.Application" ascii
        $create = "CreateObject" ascii
        $execute = "ExecuteShellCommand" ascii
        $shell = "DDEInitiate" ascii
    condition:
        uint16(0) == 0x5A4D and
        (any of ($dcom*) and ($create or $execute or $shell))
}

rule LateralMovement_WinRM {
    meta:
        description = "WinRM remote execution"
        severity = "high"
    strings:
        $winrm = "winrm" ascii nocase
        $wsman = "WSMan" ascii
        $ps1 = "Invoke-Command" ascii
        $ps2 = "Enter-PSSession" ascii
        $ps3 = "New-PSSession" ascii
        $http = "5985" ascii
        $https = "5986" ascii
        $cred = "Credential" ascii
    condition:
        uint16(0) == 0x5A4D and
        (($winrm or $wsman) and ($cred or any of ($http, $https))) or
        (any of ($ps*) and $cred)
}

rule LateralMovement_RDP {
    meta:
        description = "RDP hijacking or tunneling"
        severity = "high"
    strings:
        $mstsc = "mstsc.exe" ascii nocase
        $rdp1 = "3389" ascii
        $rdp2 = "termsrv.dll" ascii
        $tscon = "tscon" ascii nocase
        $shadow = "/shadow:" ascii
        $takeover = "takeover" ascii nocase
        $tunnel = "tunnel" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        ($mstsc and any of ($shadow, $takeover)) or
        ($rdp1 and $tunnel) or $tscon
}

rule LateralMovement_SMB_Share {
    meta:
        description = "SMB share access for lateral movement"
        severity = "high"
    strings:
        $admin = "\\\\*\\ADMIN$" ascii
        $c = "\\\\*\\C$" ascii
        $ipc = "\\\\*\\IPC$" ascii
        $net = "net use" ascii nocase
        $wnet1 = "WNetAddConnection" ascii
        $wnet2 = "WNetAddConnection2" ascii
        $wnet3 = "WNetAddConnection3" ascii
        $copy = "copy" ascii nocase
        $xcopy = "xcopy" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        ((any of ($admin, $c, $ipc)) and (any of ($net, $wnet*) or any of ($copy, $xcopy)))
}

rule LateralMovement_Remote_Service {
    meta:
        description = "Remote service creation"
        severity = "critical"
    strings:
        $sc1 = "sc \\\\*" ascii nocase
        $sc2 = "create" ascii nocase
        $sc3 = "binPath=" ascii nocase
        $api1 = "OpenSCManagerA" ascii
        $api2 = "OpenSCManagerW" ascii
        $api3 = "CreateServiceA" ascii
        $api4 = "CreateServiceW" ascii
        $remote = "\\\\" ascii
    condition:
        uint16(0) == 0x5A4D and
        (($sc1 and $sc2 and $sc3) or ((any of ($api1, $api2)) and (any of ($api3, $api4)) and $remote))
}

rule LateralMovement_Scheduled_Task_Remote {
    meta:
        description = "Remote scheduled task creation"
        severity = "critical"
    strings:
        $at1 = "at \\\\*" ascii nocase
        $schtasks1 = "schtasks /create /s" ascii nocase
        $schtasks2 = "/s " ascii
        $tn = "/tn" ascii nocase
        $tr = "/tr" ascii nocase
        $api1 = "ITaskService" ascii
        $connect = "Connect" ascii
        $remote = "\\\\" ascii
    condition:
        uint16(0) == 0x5A4D and
        ($at1 or ($schtasks1 and $tn and $tr) or ($api1 and $connect and $remote))
}

rule LateralMovement_SSH {
    meta:
        description = "SSH-based lateral movement"
        severity = "medium"
    strings:
        $ssh = "ssh" ascii nocase
        $scp = "scp" ascii nocase
        $sftp = "sftp" ascii nocase
        $key = ".ssh" ascii
        $rsa = "id_rsa" ascii
        $known = "known_hosts" ascii
        $port = "22" ascii
    condition:
        uint16(0) == 0x5A4D and
        (any of ($ssh, $scp, $sftp) and any of ($key, $rsa, $known, $port))
}

rule LateralMovement_Pass_The_Hash {
    meta:
        description = "Pass-the-hash lateral movement"
        severity = "critical"
    strings:
        $pth1 = "pth-" ascii nocase
        $pth2 = "pass-the-hash" ascii nocase
        $pth3 = "PassTheHash" ascii
        $sekurlsa = "sekurlsa" ascii
        $mimikatz = "mimikatz" ascii nocase
        $lsadump = "lsadump" ascii
        $hash = /[a-f0-9]{32}:[a-f0-9]{32}/ ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        (any of ($pth*) or ($sekurlsa and $lsadump) or $mimikatz or $hash)
}

rule LateralMovement_Pass_The_Ticket {
    meta:
        description = "Pass-the-ticket Kerberos attack"
        severity = "critical"
    strings:
        $ptt1 = "pass-the-ticket" ascii nocase
        $ptt2 = "PassTheTicket" ascii
        $ptt3 = "ptt" ascii nocase
        $kirbi = ".kirbi" ascii
        $kerberos = "kerberos" ascii nocase
        $ticket = "ticket" ascii nocase
        $tgt = "TGT" ascii
        $tgs = "TGS" ascii
    condition:
        uint16(0) == 0x5A4D and
        (any of ($ptt*) or $kirbi or (($kerberos or $ticket) and any of ($tgt, $tgs)))
}

rule LateralMovement_Golden_Ticket {
    meta:
        description = "Golden ticket attack"
        severity = "critical"
    strings:
        $golden = "golden" ascii nocase
        $krbtgt = "krbtgt" ascii nocase
        $ticket = "ticket" ascii nocase
        $domain = "domain" ascii nocase
        $sid = "S-1-5-21-" ascii
        $aes = "aes256" ascii nocase
        $mimikatz = "mimikatz" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        (($golden and $ticket) or ($krbtgt and any of ($domain, $sid, $aes)) or $mimikatz)
}

rule LateralMovement_OverPass_The_Hash {
    meta:
        description = "Overpass-the-hash attack"
        severity = "critical"
    strings:
        $over = "overpass" ascii nocase
        $pth = "pass-the-hash" ascii nocase
        $asktgt = "asktgt" ascii nocase
        $rubeus = "Rubeus" ascii
        $sekurlsa = "sekurlsa::pth" ascii
        $ekeys = "ekeys" ascii
    condition:
        uint16(0) == 0x5A4D and
        (($over and $pth) or $asktgt or ($rubeus and $ekeys) or $sekurlsa)
}

rule LateralMovement_DCSync {
    meta:
        description = "DCSync attack for credential theft"
        severity = "critical"
    strings:
        $dcsync = "dcsync" ascii nocase
        $drsuapi = "DRSUAPI" ascii
        $getncchanges = "GetNCChanges" ascii
        $replication = "replication" ascii nocase
        $lsadump = "lsadump::dcsync" ascii
        $mimikatz = "mimikatz" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        ($dcsync or $drsuapi or $getncchanges or ($replication and $mimikatz) or $lsadump)
}

rule LateralMovement_EternalBlue {
    meta:
        description = "EternalBlue exploit"
        severity = "critical"
    strings:
        $eb1 = "EternalBlue" ascii nocase
        $eb2 = "MS17-010" ascii
        $eb3 = "SMBv1" ascii nocase
        $smb = "445" ascii
        $trans2 = "Trans2" ascii
        $exploit = "exploit" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        (any of ($eb*) or ($smb and $trans2 and $exploit))
}

rule LateralMovement_BlueKeep {
    meta:
        description = "BlueKeep RDP exploit"
        severity = "critical"
    strings:
        $bk1 = "BlueKeep" ascii nocase
        $bk2 = "CVE-2019-0708" ascii
        $rdp = "3389" ascii
        $channel = "MS_T120" ascii
        $exploit = "exploit" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        (any of ($bk*) or ($rdp and $channel and $exploit))
}
