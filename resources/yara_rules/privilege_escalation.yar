/*
    Privilege Escalation Technique Detection
    UAC bypass, token manipulation, exploit techniques
*/

rule PrivEsc_UAC_Bypass_Fodhelper {
    meta:
        description = "UAC bypass via fodhelper.exe"
        severity = "critical"
    strings:
        $fodhelper = "fodhelper.exe" ascii nocase
        $reg1 = "Software\\Classes\\ms-settings\\shell\\open\\command" ascii nocase
        $reg2 = "DelegateExecute" ascii
        $api = "ShellExecute" ascii
    condition:
        uint16(0) == 0x5A4D and $fodhelper and any of ($reg*)
}

rule PrivEsc_UAC_Bypass_Eventvwr {
    meta:
        description = "UAC bypass via eventvwr.exe"
        severity = "critical"
    strings:
        $eventvwr = "eventvwr.exe" ascii nocase
        $reg1 = "Software\\Classes\\mscfile\\shell\\open\\command" ascii nocase
        $msc = ".msc" ascii
        $api = "ShellExecute" ascii
    condition:
        uint16(0) == 0x5A4D and $eventvwr and ($reg1 or $msc)
}

rule PrivEsc_UAC_Bypass_CMSTP {
    meta:
        description = "UAC bypass via cmstp.exe"
        severity = "critical"
    strings:
        $cmstp = "cmstp.exe" ascii nocase
        $inf = ".inf" ascii
        $au = "/au" ascii
        $s = "/s" ascii
        $run = "RunPreSetupCommands" ascii
    condition:
        uint16(0) == 0x5A4D and $cmstp and ($inf and (any of ($au, $s, $run)))
}

rule PrivEsc_UAC_Bypass_ComputerDefaults {
    meta:
        description = "UAC bypass via computerdefaults.exe"
        severity = "critical"
    strings:
        $comp = "computerdefaults.exe" ascii nocase
        $reg = "Software\\Classes\\ms-settings\\shell\\open\\command" ascii nocase
        $delegate = "DelegateExecute" ascii
    condition:
        uint16(0) == 0x5A4D and $comp and $reg
}

rule PrivEsc_UAC_Bypass_SilentCleanup {
    meta:
        description = "UAC bypass via SilentCleanup"
        severity = "critical"
    strings:
        $clean = "SilentCleanup" ascii
        $env = "windir" ascii
        $task = "\\Microsoft\\Windows\\DiskCleanup" ascii
        $api = "schtasks" ascii nocase
    condition:
        uint16(0) == 0x5A4D and $clean and any of ($env, $task, $api)
}

rule PrivEsc_Token_Manipulation {
    meta:
        description = "Token manipulation for privilege escalation"
        severity = "critical"
    strings:
        $api1 = "OpenProcessToken" ascii
        $api2 = "DuplicateTokenEx" ascii
        $api3 = "ImpersonateLoggedOnUser" ascii
        $api4 = "SetThreadToken" ascii
        $api5 = "AdjustTokenPrivileges" ascii
        $api6 = "CreateProcessAsUserA" ascii
        $api7 = "CreateProcessAsUserW" ascii
        $api8 = "CreateProcessWithTokenW" ascii
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule PrivEsc_Named_Pipe_Impersonation {
    meta:
        description = "Named pipe impersonation"
        severity = "critical"
    strings:
        $api1 = "CreateNamedPipeA" ascii
        $api2 = "CreateNamedPipeW" ascii
        $api3 = "ConnectNamedPipe" ascii
        $api4 = "ImpersonateNamedPipeClient" ascii
        $pipe = "\\\\.\\pipe\\" ascii
        $spoof = "spoofpipe" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        ((any of ($api1, $api2)) and $api3 and $api4)
}

rule PrivEsc_Service_Permissions {
    meta:
        description = "Weak service permissions exploitation"
        severity = "high"
    strings:
        $api1 = "QueryServiceConfig" ascii
        $api2 = "ChangeServiceConfig" ascii
        $api3 = "OpenServiceA" ascii
        $api4 = "OpenServiceW" ascii
        $write = "SERVICE_CHANGE_CONFIG" ascii
        $path = "binPath" ascii nocase
        $auto = "auto" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        ((any of ($api1, $api2)) and (any of ($api3, $api4))) or ($write and $path)
}

rule PrivEsc_Unquoted_Service_Path {
    meta:
        description = "Unquoted service path exploitation"
        severity = "high"
    strings:
        $reg = "SYSTEM\\CurrentControlSet\\Services" ascii nocase
        $image = "ImagePath" ascii
        $program = "Program Files" ascii
        $space = " " ascii
        $api = "RegQueryValue" ascii
    condition:
        uint16(0) == 0x5A4D and $reg and $image and $program and $space
}

rule PrivEsc_DLL_Hijack_System {
    meta:
        description = "System DLL hijacking for privilege escalation"
        severity = "critical"
    strings:
        $sys1 = "\\System32\\" ascii
        $sys2 = "\\SysWOW64\\" ascii
        $copy1 = "CopyFileA" ascii
        $copy2 = "CopyFileW" ascii
        $dll = ".dll" ascii nocase
        $known = /version\.dll|userenv\.dll|dwmapi\.dll/ ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        (any of ($sys*)) and (any of ($copy*)) and $dll
}

rule PrivEsc_SeDebugPrivilege {
    meta:
        description = "SeDebugPrivilege exploitation"
        severity = "critical"
    strings:
        $priv = "SeDebugPrivilege" ascii
        $api1 = "LookupPrivilegeValueA" ascii
        $api2 = "AdjustTokenPrivileges" ascii
        $api3 = "OpenProcessToken" ascii
        $lsass = "lsass.exe" ascii nocase
        $debug = "debug" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        $priv and (all of ($api*) or $lsass)
}

rule PrivEsc_SeImpersonatePrivilege {
    meta:
        description = "SeImpersonatePrivilege exploitation (Potato)"
        severity = "critical"
    strings:
        $potato1 = "JuicyPotato" ascii
        $potato2 = "RottenPotato" ascii
        $potato3 = "SweetPotato" ascii
        $potato4 = "PrintSpoofer" ascii
        $priv = "SeImpersonatePrivilege" ascii
        $pipe = "\\pipe\\" ascii
        $api = "ImpersonateNamedPipeClient" ascii
    condition:
        uint16(0) == 0x5A4D and
        (any of ($potato*) or ($priv and $pipe and $api))
}

rule PrivEsc_ALPC_BITS {
    meta:
        description = "ALPC/BITS privilege escalation"
        severity = "critical"
    strings:
        $alpc1 = "NtAlpcConnectPort" ascii
        $alpc2 = "AlpcMaxAllowedMessageLength" ascii
        $bits = "BITS" ascii
        $com = "Background Intelligent Transfer" ascii
        $api = "CoCreateInstance" ascii
    condition:
        uint16(0) == 0x5A4D and
        ((any of ($alpc*)) or ($bits and $api))
}

rule PrivEsc_PrintNightmare {
    meta:
        description = "PrintNightmare exploitation"
        severity = "critical"
    strings:
        $print1 = "AddPrinterDriverExA" ascii
        $print2 = "AddPrinterDriverExW" ascii
        $spooler = "spoolsv.exe" ascii nocase
        $driver = "pDriverPath" ascii
        $remote = "\\\\" ascii
        $dll = ".dll" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        ((any of ($print*)) or ($spooler and $driver and $dll))
}

rule PrivEsc_Kernel_Exploit {
    meta:
        description = "Kernel exploit for privilege escalation"
        severity = "critical"
    strings:
        $token = "SYSTEM" ascii
        $api1 = "NtQuerySystemInformation" ascii
        $api2 = "DeviceIoControl" ascii
        $driver = "\\\\.\\{" ascii
        $shellcode = { 65 48 8B 04 25 88 01 00 00 }  // PEB access
        $token_steal = { 48 8B 80 B8 00 00 00 }      // Token offset
    condition:
        uint16(0) == 0x5A4D and
        ($token and $api2 and $driver) or (any of ($shellcode, $token_steal))
}

rule PrivEsc_CVE_Generic {
    meta:
        description = "Generic CVE exploit indicators"
        severity = "high"
    strings:
        $cve = /CVE-20[1-2][0-9]-\d{4,5}/ ascii
        $exploit = "exploit" ascii nocase
        $poc = "proof of concept" ascii nocase
        $priv = "privilege" ascii nocase
        $escalation = "escalation" ascii nocase
    condition:
        uint16(0) == 0x5A4D and $cve and (any of ($exploit, $poc) or ($priv and $escalation))
}

rule PrivEsc_AlwaysInstallElevated {
    meta:
        description = "AlwaysInstallElevated exploitation"
        severity = "high"
    strings:
        $reg1 = "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer" ascii nocase
        $reg2 = "AlwaysInstallElevated" ascii
        $msi = ".msi" ascii nocase
        $msiexec = "msiexec" ascii nocase
        $api = "MsiInstallProduct" ascii
    condition:
        uint16(0) == 0x5A4D and $reg1 and $reg2 and (any of ($msi, $msiexec, $api))
}

rule PrivEsc_GPP_Password {
    meta:
        description = "Group Policy Preferences password extraction"
        severity = "critical"
    strings:
        $gpp1 = "Groups.xml" ascii
        $gpp2 = "ScheduledTasks.xml" ascii
        $gpp3 = "Services.xml" ascii
        $gpp4 = "Drives.xml" ascii
        $cpassword = "cpassword" ascii nocase
        $sysvol = "SYSVOL" ascii
        $decrypt = "decrypt" ascii nocase
    condition:
        (any of ($gpp*) and ($cpassword or $sysvol)) or ($cpassword and $decrypt)
}

rule PrivEsc_SAM_SYSTEM {
    meta:
        description = "SAM/SYSTEM registry extraction"
        severity = "critical"
    strings:
        $sam = "\\SAM" ascii
        $system = "\\SYSTEM" ascii
        $security = "\\SECURITY" ascii
        $reg_save = "reg save" ascii nocase
        $copy = "copy" ascii nocase
        $api1 = "RegSaveKeyA" ascii
        $api2 = "RegSaveKeyW" ascii
        $shadow = "shadow" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        ((any of ($sam, $system, $security)) and (any of ($reg_save, $copy, $api1, $api2, $shadow)))
}
