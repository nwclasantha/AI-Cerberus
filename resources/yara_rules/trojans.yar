/*
   Trojan Detection Rules
   Patterns for detecting trojan behavior
*/

rule Trojan_Generic {
    meta:
        description = "Generic Trojan indicators"
        author = "Malware Analyzer Team"
        date = "2025-01-15"
        severity = "high"
        category = "trojan"
    strings:
        $s1 = "cmd.exe" nocase
        $s2 = "powershell" nocase
        $s3 = "wscript" nocase
        $api1 = "ShellExecute" nocase
        $api2 = "WinExec" nocase
        $hide1 = "SW_HIDE"
    condition:
        (any of ($s*) and any of ($api*)) or
        (any of ($api*) and any of ($hide*))
}

rule RAT_Indicators {
    meta:
        description = "Remote Access Trojan indicators"
        severity = "critical"
        category = "rat"
    strings:
        $screen1 = "GetDC" nocase
        $screen2 = "BitBlt" nocase
        $screen3 = "GetDesktopWindow" nocase
        $keylog1 = "GetAsyncKeyState" nocase
        $keylog2 = "GetKeyState" nocase
        $keylog3 = "SetWindowsHookEx" nocase
        $net1 = "send" nocase
        $net2 = "recv" nocase
        $shell1 = "CreateProcess" nocase
        $shell2 = "WinExec" nocase
    condition:
        (any of ($screen*) or any of ($keylog*)) and
        any of ($net*) and any of ($shell*)
}

rule Downloader_Trojan {
    meta:
        description = "Trojan downloader behavior"
        severity = "high"
        category = "downloader"
    strings:
        $url1 = "URLDownloadToFile" nocase
        $url2 = "URLOpenStream" nocase
        $inet1 = "InternetOpen" nocase
        $inet2 = "InternetReadFile" nocase
        $inet3 = "HttpOpenRequest" nocase
        $exec1 = "ShellExecute" nocase
        $exec2 = "CreateProcess" nocase
        $exec3 = "WinExec" nocase
        $temp = "GetTempPath" nocase
    condition:
        (any of ($url*) or 2 of ($inet*)) and
        any of ($exec*) and $temp
}

rule Backdoor_Indicators {
    meta:
        description = "Backdoor functionality"
        severity = "critical"
        category = "backdoor"
    strings:
        $socket1 = "socket" nocase
        $socket2 = "bind" nocase
        $socket3 = "listen" nocase
        $socket4 = "accept" nocase
        $pipe1 = "CreateNamedPipe" nocase
        $pipe2 = "ConnectNamedPipe" nocase
        $shell1 = "cmd.exe"
        $shell2 = "/bin/sh"
        $shell3 = "/bin/bash"
        $exec1 = "CreateProcess" nocase
        $exec2 = "popen"
    condition:
        (3 of ($socket*) or 2 of ($pipe*)) and
        (any of ($shell*) or any of ($exec*))
}
