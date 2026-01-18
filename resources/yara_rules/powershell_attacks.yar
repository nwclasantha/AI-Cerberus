/*
    PowerShell Attack Detection
    Malicious PowerShell scripts and techniques
*/

rule PowerShell_Encoded_Command {
    meta:
        description = "Encoded PowerShell command"
        severity = "high"
    strings:
        $ps1 = "powershell" ascii nocase
        $ps2 = "pwsh" ascii nocase
        $enc1 = "-enc" ascii nocase
        $enc2 = "-EncodedCommand" ascii nocase
        $enc3 = "-ec" ascii nocase
        $b64 = /[A-Za-z0-9+\/=]{50,}/ ascii
    condition:
        (any of ($ps*)) and (any of ($enc*)) and $b64
}

rule PowerShell_Bypass_Execution {
    meta:
        description = "PowerShell execution policy bypass"
        severity = "high"
    strings:
        $ps = "powershell" ascii nocase
        $bypass1 = "-ExecutionPolicy Bypass" ascii nocase
        $bypass2 = "-ep bypass" ascii nocase
        $bypass3 = "-exec bypass" ascii nocase
        $bypass4 = "Set-ExecutionPolicy Unrestricted" ascii nocase
        $bypass5 = "Bypass" ascii nocase
    condition:
        $ps and (any of ($bypass*))
}

rule PowerShell_Hidden_Window {
    meta:
        description = "Hidden PowerShell window"
        severity = "high"
    strings:
        $ps = "powershell" ascii nocase
        $hidden1 = "-WindowStyle Hidden" ascii nocase
        $hidden2 = "-w hidden" ascii nocase
        $hidden3 = "-win hidden" ascii nocase
        $noprofile = "-NoProfile" ascii nocase
        $noninteractive = "-NonInteractive" ascii nocase
    condition:
        $ps and (any of ($hidden*)) and (any of ($noprofile, $noninteractive))
}

rule PowerShell_Download_Execute {
    meta:
        description = "PowerShell download and execute"
        severity = "critical"
    strings:
        $iex1 = "IEX" ascii
        $iex2 = "Invoke-Expression" ascii nocase
        $dl1 = "DownloadString" ascii
        $dl2 = "DownloadFile" ascii
        $dl3 = "DownloadData" ascii
        $dl4 = "Net.WebClient" ascii
        $dl5 = "Invoke-WebRequest" ascii
        $dl6 = "wget" ascii
        $dl7 = "curl" ascii
    condition:
        (any of ($iex*)) and (any of ($dl*))
}

rule PowerShell_Reflective_Injection {
    meta:
        description = "PowerShell reflective PE injection"
        severity = "critical"
    strings:
        $reflect1 = "Invoke-ReflectivePEInjection" ascii nocase
        $reflect2 = "ReflectivePEInjection" ascii nocase
        $pe = "PE" ascii
        $inject = "inject" ascii nocase
        $virtualalloc = "VirtualAlloc" ascii
        $loadlibrary = "LoadLibrary" ascii
    condition:
        (any of ($reflect*)) or ($pe and $inject and any of ($virtualalloc, $loadlibrary))
}

rule PowerShell_Mimikatz {
    meta:
        description = "PowerShell Mimikatz"
        severity = "critical"
    strings:
        $mimi1 = "Invoke-Mimikatz" ascii nocase
        $mimi2 = "mimikatz" ascii nocase
        $sekurlsa = "sekurlsa" ascii
        $lsadump = "lsadump" ascii
        $kerberos = "kerberos" ascii nocase
        $wdigest = "wdigest" ascii
    condition:
        (any of ($mimi*)) or (2 of ($sekurlsa, $lsadump, $kerberos, $wdigest))
}

rule PowerShell_Empire {
    meta:
        description = "PowerShell Empire framework"
        severity = "critical"
    strings:
        $empire1 = "Empire" ascii nocase
        $empire2 = "PowerShellEmpire" ascii nocase
        $stager = "stager" ascii nocase
        $agent = "agent" ascii nocase
        $listener = "listener" ascii nocase
        $module = "module" ascii nocase
    condition:
        (any of ($empire*)) and (2 of ($stager, $agent, $listener, $module))
}

rule PowerShell_PowerSploit {
    meta:
        description = "PowerSploit toolkit"
        severity = "critical"
    strings:
        $ps1 = "PowerSploit" ascii nocase
        $inv1 = "Invoke-Shellcode" ascii
        $inv2 = "Invoke-DllInjection" ascii
        $inv3 = "Invoke-TokenManipulation" ascii
        $inv4 = "Get-Keystrokes" ascii
        $inv5 = "Get-GPPPassword" ascii
        $inv6 = "Invoke-Kerberoast" ascii
    condition:
        $ps1 or (2 of ($inv*))
}

rule PowerShell_AMSI_Bypass {
    meta:
        description = "AMSI bypass attempt"
        severity = "critical"
    strings:
        $amsi1 = "AmsiScanBuffer" ascii
        $amsi2 = "amsi.dll" ascii nocase
        $amsi3 = "AmsiInitFailed" ascii
        $amsi4 = "AmsiContext" ascii
        $bypass = "bypass" ascii nocase
        $patch = { B8 57 00 07 80 }  // mov eax, 0x80070057
        $disable = "disable" ascii nocase
    condition:
        (any of ($amsi*)) and (any of ($bypass, $patch, $disable))
}

rule PowerShell_Credential_Theft {
    meta:
        description = "PowerShell credential theft"
        severity = "critical"
    strings:
        $cred1 = "Get-Credential" ascii
        $cred2 = "ConvertTo-SecureString" ascii
        $cred3 = "Export-Clixml" ascii
        $mimikatz = "mimikatz" ascii nocase
        $lsass = "lsass" ascii nocase
        $sam = "SAM" ascii
        $ntds = "NTDS" ascii
    condition:
        (2 of ($cred*)) or (any of ($mimikatz, $lsass, $sam, $ntds))
}

rule PowerShell_Obfuscation {
    meta:
        description = "Obfuscated PowerShell"
        severity = "high"
    strings:
        $tick = "`" ascii  // Backtick obfuscation
        $concat = "+" ascii
        $format = "-f" ascii
        $join = "-join" ascii nocase
        $replace = "-replace" ascii nocase
        $reverse = "[char[]]" ascii
        $split = "-split" ascii nocase
        $frombase64 = "FromBase64String" ascii
    condition:
        (4 of them)
}

rule PowerShell_Shellcode_Loader {
    meta:
        description = "PowerShell shellcode loader"
        severity = "critical"
    strings:
        $shellcode = "shellcode" ascii nocase
        $virtualalloc = "VirtualAlloc" ascii
        $virtualprotect = "VirtualProtect" ascii
        $createthread = "CreateThread" ascii
        $marshal = "[System.Runtime.InteropServices.Marshal]" ascii
        $copy = "Copy" ascii
        $delegate = "DelegateType" ascii
    condition:
        $shellcode or (2 of ($virtualalloc, $virtualprotect, $createthread, $marshal, $copy, $delegate))
}

rule PowerShell_Token_Manipulation {
    meta:
        description = "PowerShell token manipulation"
        severity = "critical"
    strings:
        $token1 = "Invoke-TokenManipulation" ascii
        $token2 = "TOKEN" ascii
        $impersonate = "Impersonate" ascii nocase
        $duplicate = "DuplicateToken" ascii
        $adjust = "AdjustTokenPrivileges" ascii
        $privilege = "SeDebugPrivilege" ascii
    condition:
        $token1 or (2 of ($token2, $impersonate, $duplicate, $adjust, $privilege))
}

rule PowerShell_WMI_Lateral {
    meta:
        description = "PowerShell WMI lateral movement"
        severity = "critical"
    strings:
        $wmi1 = "Invoke-WmiMethod" ascii
        $wmi2 = "Get-WmiObject" ascii
        $wmi3 = "Win32_Process" ascii
        $create = "Create" ascii
        $remote = "-ComputerName" ascii
        $cred = "-Credential" ascii
    condition:
        (any of ($wmi*)) and $create and (any of ($remote, $cred))
}

rule PowerShell_PSRemoting {
    meta:
        description = "PowerShell remoting abuse"
        severity = "high"
    strings:
        $invoke = "Invoke-Command" ascii
        $session = "New-PSSession" ascii
        $enter = "Enter-PSSession" ascii
        $computer = "-ComputerName" ascii
        $cred = "-Credential" ascii
        $script = "-ScriptBlock" ascii
    condition:
        (any of ($invoke, $session, $enter)) and (any of ($computer, $cred, $script))
}

rule PowerShell_Persistence {
    meta:
        description = "PowerShell persistence mechanism"
        severity = "critical"
    strings:
        $reg = "Set-ItemProperty" ascii
        $reg2 = "New-ItemProperty" ascii
        $run = "\\CurrentVersion\\Run" ascii
        $schtasks = "Register-ScheduledTask" ascii
        $schtasks2 = "New-ScheduledTaskAction" ascii
        $wmi_persist = "__EventFilter" ascii
        // UNUSED: $startup = "Startup" ascii nocase
    condition:
        (any of ($reg, $reg2) and $run) or (any of ($schtasks, $schtasks2)) or $wmi_persist
}

rule PowerShell_Keylogger {
    meta:
        description = "PowerShell keylogger"
        severity = "critical"
    strings:
        $api1 = "GetAsyncKeyState" ascii
        $api2 = "GetKeyState" ascii
        $api3 = "SetWindowsHookEx" ascii
        $hook = "Keyboard" ascii nocase
        $log = "log" ascii nocase
        $capture = "capture" ascii nocase
    condition:
        (any of ($api*)) and (any of ($hook, $log, $capture))
}

rule PowerShell_Screenshot {
    meta:
        description = "PowerShell screenshot capture"
        severity = "medium"
    strings:
        $screen1 = "Screen" ascii
        $screen2 = "Screenshot" ascii nocase
        $bitmap = "Bitmap" ascii
        $graphics = "Graphics" ascii
        $copyfromscreen = "CopyFromScreen" ascii
        $save = "Save" ascii
    condition:
        (any of ($screen*)) and ($bitmap or $graphics) and (any of ($copyfromscreen, $save))
}

rule PowerShell_Exfiltration {
    meta:
        description = "PowerShell data exfiltration"
        severity = "critical"
    strings:
        $http = "Invoke-WebRequest" ascii
        $rest = "Invoke-RestMethod" ascii
        $upload = "upload" ascii nocase
        $post = "POST" ascii
        $webhook = "webhook" ascii nocase
        $discord = "discord" ascii nocase
        $telegram = "telegram" ascii nocase
        $pastebin = "pastebin" ascii nocase
    condition:
        (any of ($http, $rest)) and ($upload or $post) and (any of ($webhook, $discord, $telegram, $pastebin))
}

rule PowerShell_Cobalt_Strike {
    meta:
        description = "PowerShell Cobalt Strike"
        severity = "critical"
    strings:
        $cs1 = "beacon" ascii nocase
        $cs2 = "payload" ascii nocase
        $cs3 = "stager" ascii nocase
        $spawn = "spawn" ascii nocase
        $inject = "inject" ascii nocase
        $shellcode = "shellcode" ascii nocase
    condition:
        (any of ($cs*)) and (any of ($spawn, $inject, $shellcode))
}

