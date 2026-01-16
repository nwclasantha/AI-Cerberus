/*
   Information Stealer Detection Rules
   Patterns for detecting credential theft and data exfiltration
*/

rule Keylogger_Indicators {
    meta:
        description = "Keylogging functionality"
        author = "Malware Analyzer Team"
        date = "2025-01-15"
        severity = "high"
        category = "infostealer"
    strings:
        $key1 = "GetAsyncKeyState" nocase
        $key2 = "GetKeyState" nocase
        $key3 = "GetKeyboardState" nocase
        $hook1 = "SetWindowsHookEx" nocase
        $hook2 = "WH_KEYBOARD"
        $hook3 = "WH_KEYBOARD_LL"
        $file1 = "CreateFile" nocase
        $file2 = "WriteFile" nocase
    condition:
        (any of ($key*) or any of ($hook*)) and
        2 of ($file*)
}

rule Password_Stealer {
    meta:
        description = "Password stealing behavior"
        severity = "critical"
        category = "credential_theft"
    strings:
        $cred1 = "CredEnumerate" nocase
        $cred2 = "CredReadA" nocase
        $cred3 = "CredReadW" nocase
        $vault1 = "VaultEnumerateVaults" nocase
        $vault2 = "VaultEnumerateItems" nocase
        $browser1 = "Login Data" nocase
        $browser2 = "Cookies" nocase
        $browser3 = "logins.json"
        $browser4 = "key3.db"
        $decrypt1 = "CryptUnprotectData" nocase
        $sqlite = "sqlite3_" nocase
    condition:
        (any of ($cred*) or 2 of ($vault*)) or
        (2 of ($browser*) and ($decrypt1 or $sqlite))
}

rule Browser_Data_Theft {
    meta:
        description = "Browser data exfiltration"
        severity = "high"
        category = "infostealer"
    strings:
        $chrome1 = "\\Google\\Chrome\\User Data" nocase
        $chrome2 = "Local State"
        $firefox1 = "\\Mozilla\\Firefox\\Profiles" nocase
        $firefox2 = "key4.db"
        $edge = "\\Microsoft\\Edge\\User Data" nocase
        $opera = "\\Opera Software" nocase
        $login = "Login Data" nocase
        $cookie = "Cookies" nocase
        $wallet = "Wallet" nocase
        $history = "History" nocase
        $decrypt = "CryptUnprotectData" nocase
    condition:
        (any of ($chrome*) or any of ($firefox*) or $edge or $opera) and
        2 of ($login, $cookie, $wallet, $history) and $decrypt
}

rule Clipboard_Stealer {
    meta:
        description = "Clipboard monitoring and theft"
        severity = "medium"
        category = "infostealer"
    strings:
        $clip1 = "GetClipboardData" nocase
        $clip2 = "OpenClipboard" nocase
        $clip3 = "SetClipboardViewer" nocase
        $clip4 = "AddClipboardFormatListener" nocase
        $crypto1 = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ // Bitcoin address
        $crypto2 = /0x[a-fA-F0-9]{40}/ // Ethereum address
    condition:
        2 of ($clip*) and (any of ($crypto*))
}

rule Form_Grabber {
    meta:
        description = "Form data interception"
        severity = "high"
        category = "infostealer"
    strings:
        $ie1 = "InternetGetCookie" nocase
        $ie2 = "InternetSetCookie" nocase
        $post1 = "POST" nocase
        $post2 = "HttpSendRequest" nocase
        $form1 = "password" nocase
        $form2 = "username" nocase
        $form3 = "login" nocase
        $hook1 = "SetWindowsHookEx" nocase
    condition:
        (any of ($ie*) or 2 of ($post*)) and
        2 of ($form*) and $hook1
}

rule Screen_Capture {
    meta:
        description = "Screenshot capability"
        severity = "medium"
        category = "surveillance"
    strings:
        $screen1 = "GetDC" nocase
        $screen2 = "GetDesktopWindow" nocase
        $screen3 = "BitBlt" nocase
        $screen4 = "StretchBlt" nocase
        $gdi1 = "CreateCompatibleDC" nocase
        $gdi2 = "CreateCompatibleBitmap" nocase
        $save1 = "GetDIBits" nocase
        $save2 = "jpeg" nocase
        $save3 = "png" nocase
    condition:
        3 of ($screen*, $gdi*) and (any of ($save*))
}
