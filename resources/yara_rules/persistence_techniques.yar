/*
    Persistence Mechanism Detection
    Registry, scheduled tasks, services, startup folders, and other persistence
*/

rule Persistence_Registry_Run {
    meta:
        description = "Registry Run key persistence"
        severity = "high"
    strings:
        $run1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii nocase
        $run2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii nocase
        $run3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices" ascii nocase
        $run4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce" ascii nocase
        $run5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" ascii nocase
        $run6 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii nocase
        $api1 = "RegSetValueEx" ascii
        $api2 = "RegCreateKeyEx" ascii
    condition:
        uint16(0) == 0x5A4D and any of ($run*) and any of ($api*)
}

rule Persistence_Startup_Folder {
    meta:
        description = "Startup folder persistence"
        severity = "high"
    strings:
        $path1 = "\\Start Menu\\Programs\\Startup" ascii
        $path2 = "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" ascii
        $shell = "shell:startup" ascii nocase
        $api1 = "CopyFileA" ascii
        $api2 = "CopyFileW" ascii
        $api3 = "CreateFileA" ascii
        $lnk = ".lnk" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($path*) or $shell) and (any of ($api*) or $lnk)
}

rule Persistence_Scheduled_Task {
    meta:
        description = "Scheduled task persistence"
        severity = "high"
    strings:
        $schtasks = "schtasks" ascii nocase
        $create = "/create" ascii nocase
        $xml1 = "<Task " ascii
        $xml2 = "<Exec>" ascii
        $xml3 = "<Command>" ascii
        $api1 = "ITaskService" ascii
        $api2 = "RegisterTaskDefinition" ascii
        // UNUSED: $tr = "/tr" ascii nocase
        // UNUSED: $sc = "/sc" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        (($schtasks and $create) or (2 of ($xml*)) or all of ($api*))
}

rule Persistence_Service_Creation {
    meta:
        description = "Service creation for persistence"
        severity = "high"
    strings:
        $api1 = "CreateServiceA" ascii
        $api2 = "CreateServiceW" ascii
        $api3 = "OpenSCManagerA" ascii
        $api4 = "OpenSCManagerW" ascii
        // UNUSED: $api5 = "StartServiceA" ascii
        // UNUSED: $api6 = "StartServiceW" ascii
        $sc = "sc create" ascii nocase
        $binpath = "binPath=" ascii nocase
        // UNUSED: $auto = "auto" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        ((any of ($api1, $api2) and any of ($api3, $api4)) or ($sc and $binpath))
}

rule Persistence_WMI_Subscription {
    meta:
        description = "WMI event subscription persistence"
        severity = "critical"
    strings:
        $sub1 = "__EventFilter" ascii
        $sub2 = "__EventConsumer" ascii
        $sub3 = "__FilterToConsumerBinding" ascii
        $sub4 = "CommandLineEventConsumer" ascii
        $sub5 = "ActiveScriptEventConsumer" ascii
        $wmi = "winmgmts:" ascii nocase
        $create = "Create" ascii
    condition:
        uint16(0) == 0x5A4D and (2 of ($sub*) and ($wmi or $create))
}

rule Persistence_COM_Hijack {
    meta:
        description = "COM object hijacking"
        severity = "high"
    strings:
        $clsid = "CLSID\\" ascii
        $inproc = "InprocServer32" ascii
        $local = "LocalServer32" ascii
        $treat = "TreatAs" ascii
        $dll = ".dll" ascii nocase
        $api = "RegSetValue" ascii
    condition:
        uint16(0) == 0x5A4D and $clsid and (any of ($inproc, $local, $treat)) and ($dll or $api)
}

rule Persistence_DLL_Search_Hijack {
    meta:
        description = "DLL search order hijacking"
        severity = "high"
    strings:
        $api1 = "SetDllDirectoryA" ascii
        $api2 = "SetDllDirectoryW" ascii
        $api3 = "AddDllDirectory" ascii
        $copy1 = "CopyFileA" ascii
        $copy2 = "CopyFileW" ascii
        $path1 = "\\System32\\" ascii
        $path2 = "\\SysWOW64\\" ascii
        $dll = ".dll" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        (any of ($api*) or (any of ($copy*) and any of ($path*) and $dll))
}

rule Persistence_Image_File_Exec {
    meta:
        description = "Image File Execution Options persistence"
        severity = "critical"
    strings:
        $ifeo = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options" ascii nocase
        $debug = "Debugger" ascii
        $gflags = "GlobalFlag" ascii
        $silent = "SilentProcessExit" ascii
        // UNUSED: $api = "RegSetValue" ascii
    condition:
        uint16(0) == 0x5A4D and $ifeo and (any of ($debug, $gflags, $silent))
}

rule Persistence_AppInit_DLLs {
    meta:
        description = "AppInit_DLLs injection"
        severity = "critical"
    strings:
        $reg = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows" ascii nocase
        $appinit = "AppInit_DLLs" ascii
        $loadappinit = "LoadAppInit_DLLs" ascii
        $api = "RegSetValue" ascii
        $dll = ".dll" ascii nocase
    condition:
        uint16(0) == 0x5A4D and $reg and ($appinit or $loadappinit) and ($api or $dll)
}

rule Persistence_Netsh_Helper {
    meta:
        description = "Netsh helper DLL persistence"
        severity = "high"
    strings:
        $netsh = "netsh" ascii nocase
        $add = "add helper" ascii nocase
        $reg = "SOFTWARE\\Microsoft\\NetSh" ascii nocase
        $dll = ".dll" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (($netsh and $add) or ($reg and $dll))
}

rule Persistence_Security_Support_Provider {
    meta:
        description = "Security Support Provider (SSP) persistence"
        severity = "critical"
    strings:
        $reg = "SYSTEM\\CurrentControlSet\\Control\\Lsa" ascii nocase
        $ssp1 = "Security Packages" ascii
        $ssp2 = "Authentication Packages" ascii
        $api1 = "AddSecurityPackage" ascii
        $dll = ".dll" ascii nocase
    condition:
        uint16(0) == 0x5A4D and $reg and (any of ($ssp*) or $api1) and $dll
}

rule Persistence_Print_Monitor {
    meta:
        description = "Print monitor persistence"
        severity = "high"
    strings:
        $reg = "SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors" ascii nocase
        $api1 = "AddMonitor" ascii
        $driver = "Driver" ascii
        $dll = ".dll" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($reg or $api1) and ($driver or $dll)
}

rule Persistence_Winlogon {
    meta:
        description = "Winlogon persistence mechanisms"
        severity = "critical"
    strings:
        $reg = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii nocase
        $shell = "Shell" ascii
        $userinit = "Userinit" ascii
        $notify = "Notify" ascii
        $api = "RegSetValue" ascii
    condition:
        uint16(0) == 0x5A4D and $reg and (any of ($shell, $userinit, $notify)) and $api
}

rule Persistence_Boot_Execute {
    meta:
        description = "BootExecute persistence"
        severity = "critical"
    strings:
        $reg = "SYSTEM\\CurrentControlSet\\Control\\Session Manager" ascii nocase
        $boot = "BootExecute" ascii
        $setup = "SetupExecute" ascii
        $api = "RegSetValue" ascii
    condition:
        uint16(0) == 0x5A4D and $reg and (any of ($boot, $setup)) and $api
}

rule Persistence_Browser_Extension {
    meta:
        description = "Malicious browser extension installation"
        severity = "high"
    strings:
        $chrome = "\\Google\\Chrome\\User Data\\Default\\Extensions" ascii
        $firefox = "\\Mozilla\\Firefox\\Profiles" ascii
        $edge = "\\Microsoft\\Edge\\User Data\\Default\\Extensions" ascii
        $manifest = "manifest.json" ascii
        $crx = ".crx" ascii
        $xpi = ".xpi" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($chrome, $firefox, $edge)) and (any of ($manifest, $crx, $xpi))
}

rule Persistence_Office_Startup {
    meta:
        description = "Office startup persistence"
        severity = "high"
    strings:
        $xlstart = "\\Microsoft\\Excel\\XLSTART" ascii
        $wordstart = "\\Microsoft\\Word\\STARTUP" ascii
        $template = "Normal.dotm" ascii
        $personal = "PERSONAL.XLSB" ascii
        $vba = "VBAProject" ascii
    condition:
        uint16(0) == 0x5A4D and ((any of ($xlstart, $wordstart)) or (any of ($template, $personal) and $vba))
}

rule Persistence_Accessibility_Features {
    meta:
        description = "Accessibility feature hijacking"
        severity = "critical"
    strings:
        $sethc = "sethc.exe" ascii nocase
        $utilman = "utilman.exe" ascii nocase
        $osk = "osk.exe" ascii nocase
        $magnify = "magnify.exe" ascii nocase
        $narrator = "narrator.exe" ascii nocase
        $cmd = "cmd.exe" ascii nocase
        $copy = "CopyFile" ascii
        $rename = "MoveFile" ascii
    condition:
        uint16(0) == 0x5A4D and
        (any of ($sethc, $utilman, $osk, $magnify, $narrator)) and
        ($cmd and any of ($copy, $rename))
}

rule Persistence_Logon_Script {
    meta:
        description = "Logon script persistence"
        severity = "high"
    strings:
        $reg1 = "Environment" ascii
        $reg2 = "UserInitMprLogonScript" ascii
        $gpo1 = "Scripts\\Logon" ascii
        $gpo2 = "Scripts\\Startup" ascii
        $api = "RegSetValue" ascii
    condition:
        uint16(0) == 0x5A4D and ((any of ($reg*) and $api) or any of ($gpo*))
}

rule Persistence_Time_Provider {
    meta:
        description = "Time provider DLL persistence"
        severity = "high"
    strings:
        $reg = "SYSTEM\\CurrentControlSet\\Services\\W32Time\\TimeProviders" ascii nocase
        $dll = "DllName" ascii
        $enabled = "Enabled" ascii
        $api = "RegSetValue" ascii
    condition:
        uint16(0) == 0x5A4D and $reg and ($dll or $enabled) and $api
}
