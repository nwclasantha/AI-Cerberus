/*
    Detailed Keylogger Detection Rules
    Comprehensive keylogger and keyboard monitoring detection
*/

rule Keylogger_GetAsyncKeyState {
    meta:
        description = "Keylogger using GetAsyncKeyState"
        severity = "high"
    strings:
        $api = "GetAsyncKeyState" ascii
        $loop = { 8B ?? 83 ?? 01 83 ?? 00 7? }
        $vk = "VK_" ascii
        $key = "key" ascii nocase
        $log = "log" ascii nocase
    condition:
        uint16(0) == 0x5A4D and $api and any of ($loop, $vk) and any of ($key, $log)
}

rule Keylogger_SetWindowsHookEx {
    meta:
        description = "Keylogger using SetWindowsHookEx"
        severity = "critical"
    strings:
        $api1 = "SetWindowsHookExA" ascii
        $api2 = "SetWindowsHookExW" ascii
        $wh1 = "WH_KEYBOARD" ascii
        $wh2 = "WH_KEYBOARD_LL" ascii
        $unhook = "UnhookWindowsHookEx" ascii
        $callback = "CallNextHookEx" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($api*)) and (any of ($wh*)) and any of ($unhook, $callback)
}

rule Keylogger_RawInput {
    meta:
        description = "Keylogger using Raw Input API"
        severity = "high"
    strings:
        $api1 = "RegisterRawInputDevices" ascii
        $api2 = "GetRawInputData" ascii
        $rid = "RAWINPUTDEVICE" ascii
        $keyboard = "RIM_TYPEKEYBOARD" ascii
        $hid = "HID" ascii
    condition:
        uint16(0) == 0x5A4D and (all of ($api*)) and any of ($rid, $keyboard, $hid)
}

rule Keylogger_DirectInput {
    meta:
        description = "Keylogger using DirectInput"
        severity = "high"
    strings:
        $di1 = "dinput.dll" ascii nocase
        $di2 = "dinput8.dll" ascii nocase
        $api1 = "DirectInput8Create" ascii
        $api2 = "GetDeviceState" ascii
        $keyboard = "c_dfDIKeyboard" ascii
        $acquire = "Acquire" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($di*)) and (any of ($api*)) and any of ($keyboard, $acquire)
}

rule Keylogger_GetKeyboardState {
    meta:
        description = "Keylogger using GetKeyboardState"
        severity = "high"
    strings:
        $api1 = "GetKeyboardState" ascii
        $api2 = "GetKeyState" ascii
        $api3 = "ToAscii" ascii
        $api4 = "ToUnicode" ascii
        // UNUSED: $buffer = { 68 00 01 00 00 }
        // UNUSED: $loop = "while" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($api1, $api2)) and (any of ($api3, $api4))
}

rule Keylogger_Commercial_Spector {
    meta:
        description = "SpectorSoft keylogger"
        severity = "critical"
    strings:
        $s1 = "Spector" ascii nocase
        $s2 = "SpectorSoft" ascii nocase
        $s3 = "spector360" ascii nocase
        $key = "keylog" ascii nocase
        $monitor = "monitor" ascii nocase
    condition:
        (any of ($s*)) and any of ($key, $monitor)
}

rule Keylogger_Commercial_Refog {
    meta:
        description = "REFOG keylogger"
        severity = "critical"
    strings:
        $s1 = "REFOG" ascii nocase
        $s2 = "keylogger" ascii nocase
        $s3 = "Personal Monitor" ascii nocase
        $stealth = "stealth" ascii nocase
        $invisible = "invisible" ascii nocase
    condition:
        (any of ($s*)) and any of ($stealth, $invisible)
}

rule Keylogger_Commercial_AllInOne {
    meta:
        description = "All In One Keylogger"
        severity = "critical"
    strings:
        $s1 = "All In One" ascii nocase
        $s2 = "Keylogger" ascii nocase
        $s3 = "relytec" ascii nocase
        $feature1 = "screenshot" ascii nocase
        $feature2 = "password" ascii nocase
    condition:
        (2 of ($s*)) or (any of ($s*) and any of ($feature*))
}

rule Keylogger_Ardamax {
    meta:
        description = "Ardamax keylogger"
        severity = "critical"
    strings:
        $s1 = "Ardamax" ascii nocase
        $s2 = "ARDAMAX" ascii
        $s3 = "akl.exe" ascii nocase
        $log = ".alk" ascii
        $invisible = "invisible" ascii nocase
    condition:
        (any of ($s*)) or ($log and $invisible)
}

rule Keylogger_Perfect_Keylogger {
    meta:
        description = "Perfect Keylogger"
        severity = "critical"
    strings:
        $s1 = "Perfect Keylogger" ascii nocase
        $s2 = "blazingtools" ascii nocase
        $s3 = "pkr" ascii nocase
        $log = ".pkl" ascii
        $stealth = "stealth" ascii nocase
    condition:
        (any of ($s*)) or ($log and $stealth)
}

rule Keylogger_HawkEye {
    meta:
        description = "HawkEye keylogger"
        severity = "critical"
    strings:
        $s1 = "HawkEye" ascii nocase
        $s2 = "Hawk Eye" ascii nocase
        $s3 = "hwk" ascii nocase
        $smtp = "smtp" ascii nocase
        $ftp = "ftp" ascii nocase
        $steal = "steal" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($s*)) and (any of ($smtp, $ftp, $steal))
}

rule Keylogger_AgentTesla {
    meta:
        description = "Agent Tesla keylogger"
        severity = "critical"
    strings:
        $s1 = "AgentTesla" ascii nocase
        $s2 = "Agent Tesla" ascii nocase
        $net = ".NET" ascii
        $key1 = "keylog" ascii nocase
        $key2 = "keystroke" ascii nocase
        $smtp = "SmtpClient" ascii
        $cred = "NetworkCredential" ascii
    condition:
        uint16(0) == 0x5A4D and ((any of ($s*)) or ($net and any of ($key*) and any of ($smtp, $cred)))
}

rule Keylogger_FormGrabber {
    meta:
        description = "Form grabber functionality"
        severity = "critical"
    strings:
        $form = "form" ascii nocase
        $grab = "grab" ascii nocase
        $post = "POST" ascii
        $hook1 = "HttpSendRequest" ascii
        $hook2 = "InternetWriteFile" ascii
        $hook3 = "PR_Write" ascii
        $browser = "browser" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($form and $grab) and (any of ($hook*) or ($post and $browser))
}

rule Keylogger_Clipboard_Monitor {
    meta:
        description = "Clipboard keylogger"
        severity = "high"
    strings:
        $api1 = "GetClipboardData" ascii
        $api2 = "SetClipboardViewer" ascii
        $api3 = "AddClipboardFormatListener" ascii
        $text = "CF_TEXT" ascii
        $unicode = "CF_UNICODETEXT" ascii
        $log = "log" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (2 of ($api*)) and any of ($text, $unicode, $log)
}

rule Keylogger_Window_Title_Capture {
    meta:
        description = "Window title capture keylogger"
        severity = "high"
    strings:
        $api1 = "GetForegroundWindow" ascii
        $api2 = "GetWindowText" ascii
        $api3 = "GetWindowTextA" ascii
        $api4 = "GetWindowTextW" ascii
        $log = "log" ascii nocase
        $title = "title" ascii nocase
        $active = "active" ascii nocase
    condition:
        uint16(0) == 0x5A4D and $api1 and (any of ($api2, $api3, $api4)) and any of ($log, $title, $active)
}

rule Keylogger_Screen_Capture_Combo {
    meta:
        description = "Keylogger with screenshot capability"
        severity = "critical"
    strings:
        $key1 = "GetAsyncKeyState" ascii
        $key2 = "SetWindowsHookEx" ascii
        $screen1 = "BitBlt" ascii
        $screen2 = "GetDesktopWindow" ascii
        $screen3 = "CreateCompatibleBitmap" ascii
        $save = "SaveBitmap" ascii
        $jpg = ".jpg" ascii nocase
        $png = ".png" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($key*)) and (2 of ($screen*)) and any of ($save, $jpg, $png)
}

rule Keylogger_Data_Exfiltration {
    meta:
        description = "Keylogger with data exfiltration"
        severity = "critical"
    strings:
        $key1 = "GetAsyncKeyState" ascii
        $key2 = "SetWindowsHookEx" ascii
        $smtp = "smtp" ascii nocase
        $ftp = "ftp" ascii nocase
        $http = "http" ascii nocase
        $upload = "upload" ascii nocase
        $send = "send" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($key*)) and (any of ($smtp, $ftp, $http)) and any of ($upload, $send)
}

rule Keylogger_Encrypted_Log {
    meta:
        description = "Keylogger with encrypted logs"
        severity = "critical"
    strings:
        $key = "keylog" ascii nocase
        $crypt1 = "CryptEncrypt" ascii
        $crypt2 = "AES" ascii
        $crypt3 = "encrypt" ascii nocase
        $log = ".log" ascii
        $dat = ".dat" ascii
    condition:
        uint16(0) == 0x5A4D and $key and (any of ($crypt*)) and any of ($log, $dat)
}

rule Keylogger_Python_Based {
    meta:
        description = "Python-based keylogger"
        severity = "high"
    strings:
        $py1 = "pynput" ascii
        $py2 = "keyboard" ascii
        $py3 = "pyHook" ascii
        $listener = "Listener" ascii
        $on_press = "on_press" ascii
        $on_release = "on_release" ascii
    condition:
        (any of ($py*)) and (any of ($listener, $on_press, $on_release))
}

rule Keylogger_PowerShell {
    meta:
        description = "PowerShell keylogger"
        severity = "high"
    strings:
        $ps = "powershell" ascii nocase
        $key1 = "GetAsyncKeyState" ascii
        $key2 = "Add-Type" ascii
        $user32 = "user32.dll" ascii
        $loop = "while" ascii nocase
        $sleep = "Start-Sleep" ascii
    condition:
        $ps and (any of ($key*)) and $user32 and any of ($loop, $sleep)
}

