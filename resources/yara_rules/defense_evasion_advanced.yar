/*
    Advanced Defense Evasion Detection
    AV bypass, logging evasion, and security tool disabling
*/

rule Evasion_AV_Process_Kill {
    meta:
        description = "AV/security process termination"
        severity = "critical"
    strings:
        $av1 = "avast" ascii nocase
        $av2 = "kaspersky" ascii nocase
        $av3 = "norton" ascii nocase
        $av4 = "mcafee" ascii nocase
        $av5 = "defender" ascii nocase
        $av6 = "malwarebytes" ascii nocase
        $kill1 = "taskkill" ascii nocase
        $kill2 = "TerminateProcess" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($av*) and any of ($kill*))
}

rule Evasion_AMSI_Bypass {
    meta:
        description = "AMSI bypass technique"
        severity = "high"
    strings:
        $amsi1 = "AmsiScanBuffer" ascii
        $amsi2 = "AmsiInitialize" ascii
        $amsi3 = "amsi.dll" ascii nocase
        $patch = { B8 57 00 07 80 }
    condition:
        uint16(0) == 0x5A4D and (2 of ($amsi*) or $patch)
}

rule Evasion_ETW_Disable {
    meta:
        description = "ETW (Event Tracing) bypass"
        severity = "high"
    strings:
        $etw1 = "EtwEventWrite" ascii
        $etw2 = "EtwNotificationRegister" ascii
        $etw3 = "NtTraceEvent" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of ($etw*)
}

rule Evasion_Windows_Defender_Disable {
    meta:
        description = "Windows Defender evasion"
        severity = "critical"
    strings:
        $reg1 = "DisableAntiSpyware" ascii
        $reg2 = "DisableRealtimeMonitoring" ascii
        $reg3 = "SOFTWARE\\Policies\\Microsoft\\Windows Defender" ascii
        $ps = "Set-MpPreference" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Evasion_UAC_Bypass {
    meta:
        description = "UAC bypass technique"
        severity = "high"
    strings:
        $uac1 = "fodhelper" ascii nocase
        $uac2 = "eventvwr" ascii nocase
        $uac3 = "computerdefaults" ascii nocase
        $uac4 = "sdclt" ascii nocase
        $reg = "Software\\Classes\\ms-settings\\Shell\\Open\\command" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($uac*) or $reg)
}

rule Evasion_Logging_Disable {
    meta:
        description = "Security logging evasion"
        severity = "high"
    strings:
        $log1 = "wevtutil cl" ascii nocase
        $log2 = "Clear-EventLog" ascii nocase
        $log3 = "auditpol /set" ascii nocase
    condition:
        any of them
}
