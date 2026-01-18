/*
    Information Stealer Detection Rules
    Patterns for detecting credential theft and data exfiltration
*/

rule Stealer_Browser_Data {
    meta:
        description = "Browser credential stealing"
        severity = "high"
    strings:
        $chrome1 = "\\Chrome\\User Data\\Default\\Login Data" ascii
        $chrome2 = "\\Chrome\\User Data\\Default\\Cookies" ascii
        $firefox1 = "\\Mozilla\\Firefox\\Profiles" ascii
        $firefox2 = "logins.json" ascii
        $edge = "\\Microsoft\\Edge\\User Data" ascii
        $api1 = "CryptUnprotectData" ascii
        $api2 = "sqlite3_open" ascii
    condition:
        uint16(0) == 0x5A4D and (2 of ($chrome*, $firefox*, $edge) or any of ($api*))
}

rule Stealer_Crypto_Wallet {
    meta:
        description = "Cryptocurrency wallet stealing"
        severity = "critical"
    strings:
        $btc = "wallet.dat" ascii
        $eth1 = "Ethereum\\keystore" ascii
        $eth2 = "MetaMask" ascii
        $exodus = "exodus.wallet" ascii
        $electrum = "electrum\\wallets" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Stealer_Email_Client {
    meta:
        description = "Email client credential stealing"
        severity = "high"
    strings:
        $outlook = "\\Microsoft\\Outlook" ascii
        $thunder = "\\Thunderbird\\Profiles" ascii
        $mail1 = "SMTP Password" ascii
        $mail2 = "POP3 Password" ascii
        $mail3 = "IMAP Password" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($outlook, $thunder) or 2 of ($mail*))
}

rule Stealer_FTP_Client {
    meta:
        description = "FTP client credential stealing"
        severity = "high"
    strings:
        $filezilla = "\\FileZilla\\recentservers.xml" ascii
        $winscp = "\\WinSCP\\WinSCP.ini" ascii
        $coreftp = "\\CoreFTP\\sites.idx" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Stealer_Keylogger_API {
    meta:
        description = "Keylogging API usage"
        severity = "high"
    strings:
        $key1 = "GetAsyncKeyState" ascii
        $key2 = "GetKeyState" ascii
        $key3 = "SetWindowsHookEx" ascii
        $key4 = "GetKeyboardState" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of ($key*)
}

rule Stealer_Screenshot {
    meta:
        description = "Screen capture capability"
        severity = "medium"
    strings:
        $gdi1 = "GetDC" ascii
        $gdi2 = "BitBlt" ascii
        $gdi3 = "CreateCompatibleDC" ascii
        $gdi4 = "CreateCompatibleBitmap" ascii
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule Stealer_Clipboard {
    meta:
        description = "Clipboard monitoring/stealing"
        severity = "medium"
    strings:
        $clip1 = "GetClipboardData" ascii
        $clip2 = "OpenClipboard" ascii
        $clip3 = "SetClipboardViewer" ascii
        $clip4 = "AddClipboardFormatListener" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}
