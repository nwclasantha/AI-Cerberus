/*
    Advanced Stealer and Credential Theft Detection
    Comprehensive coverage of info-stealers, password stealers, and data exfiltration
*/

rule Stealer_RedLine {
    meta:
        description = "RedLine Stealer"
        severity = "critical"
    strings:
        $s1 = "RedLine" ascii
        $s2 = "StringDecrypt" ascii
        $s3 = "RecordHeaderField" ascii
        $s4 = "CredentialFile" ascii
        $s5 = "BrowserCredentials" ascii
        $cfg = "yandex" ascii nocase
        $net = "net.tcp://" ascii
    condition:
        uint16(0) == 0x5A4D and (2 of ($s*) or ($cfg and $net))
}

rule Stealer_Raccoon_V2 {
    meta:
        description = "Raccoon Stealer v2"
        severity = "critical"
    strings:
        $s1 = "Raccoon" ascii
        $s2 = "machineId" ascii
        $s3 = "configId" ascii
        $rc4 = {33 C0 8A 04 01 32 04 02 88 04 01}
        $ua = "User-Agent:" ascii
        $boundary = "boundary=" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($s*) or ($rc4 and $ua and $boundary))
}

rule Stealer_Vidar {
    meta:
        description = "Vidar Stealer"
        severity = "critical"
    strings:
        $s1 = "Vidar" ascii
        $s2 = "hwid" ascii
        $s3 = "builds" ascii
        $profile = "profilesini" ascii nocase
        $wallet = "wallet.dat" ascii nocase
        $chrome = "\\Google\\Chrome\\" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($s*) or 2 of ($profile, $wallet, $chrome))
}

rule Stealer_Mars {
    meta:
        description = "Mars Stealer"
        severity = "critical"
    strings:
        $s1 = "Mars" ascii
        $s2 = "grabber" ascii nocase
        $s3 = "loader" ascii
        $sql = "sqlite3" ascii
        // UNUSED: $b64 = "base64" ascii nocase
        $grab = "GrabPasswords" ascii
    condition:
        uint16(0) == 0x5A4D and (2 of ($s*) or ($sql and $grab))
}

rule Stealer_Loki {
    meta:
        description = "Loki Bot/Stealer"
        severity = "critical"
    strings:
        $s1 = "Loki" ascii
        $s2 = "fre.php" ascii
        $s3 = "gate.php" ascii
        $form = "Content-Disposition:" ascii
        $boundary = "----" ascii
        $hwid = "hwid=" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($s*) or ($form and $boundary and $hwid))
}

rule Stealer_AZORult {
    meta:
        description = "AZORult Stealer"
        severity = "critical"
    strings:
        $s1 = "AZORult" ascii nocase
        $s2 = "index.php" ascii
        $key = {C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ??}
        $rc4 = {8A 04 08 32 04 10 88 04 08}
        $ua = "Mozilla/4.0" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($s*) or ($key and $rc4) or ($rc4 and $ua))
}

rule Stealer_Formbook {
    meta:
        description = "Formbook/XLoader"
        severity = "critical"
    strings:
        $s1 = "FormBook" ascii
        $s2 = "XLoader" ascii
        $hook = "SetWindowsHookEx" ascii
        $key = "keylog" ascii nocase
        $sha1 = {8D 45 ?? 50 8D 45 ?? 50 8D 45 ?? 50}
    condition:
        uint16(0) == 0x5A4D and (any of ($s*) or ($hook and $key) or $sha1)
}

rule Stealer_Agent_Tesla {
    meta:
        description = "Agent Tesla keylogger/stealer"
        severity = "critical"
    strings:
        $s1 = "AgentTesla" ascii
        $s2 = "GetKeyboardState" ascii
        $s3 = "SetWindowsHookEx" ascii
        $smtp = "smtp" ascii nocase
        $ftp = "ftp" ascii nocase
        $clipboard = "GetClipboardData" ascii
        $net = "System.Net.Mail" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($s*) or 4 of ($smtp, $ftp, $clipboard, $s2, $s3, $net))
}

rule Stealer_Snake_Keylogger {
    meta:
        description = "Snake Keylogger"
        severity = "critical"
    strings:
        $s1 = "Snake" ascii
        $s2 = "Keylogger" ascii
        $hook = "WH_KEYBOARD_LL" ascii
        // UNUSED: $key = "VK_" ascii
        $smtp = "SmtpClient" ascii
        $tg = "api.telegram.org" ascii
    condition:
        uint16(0) == 0x5A4D and (2 of ($s*) or ($hook and any of ($smtp, $tg)))
}

rule Stealer_Pony {
    meta:
        description = "Pony Loader/Stealer"
        severity = "critical"
    strings:
        $s1 = "PONY" ascii
        $s2 = "gate.php" ascii
        $s3 = "REPORT_" ascii
        $cred1 = "FileZilla" ascii
        $cred2 = "WinSCP" ascii
        $cred3 = "CoreFTP" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($s*) or 2 of ($cred*))
}

rule Stealer_Predator {
    meta:
        description = "Predator the Thief"
        severity = "critical"
    strings:
        $s1 = "Predator" ascii
        $s2 = "Thief" ascii
        $cfg = "config.txt" ascii
        $grab = "Grabber" ascii
        $wallet = "wallet" ascii nocase
        $discord = "Discord" ascii
    condition:
        uint16(0) == 0x5A4D and (2 of ($s*) or (3 of ($cfg, $grab, $wallet, $discord)))
}

rule Stealer_Chrome_Password {
    meta:
        description = "Chrome password extraction"
        severity = "high"
    strings:
        $path1 = "\\Google\\Chrome\\User Data\\Default\\Login Data" ascii
        $path2 = "\\Google\\Chrome\\User Data\\Local State" ascii
        $sql = "SELECT origin_url, username_value, password_value FROM logins" ascii nocase
        $decrypt = "CryptUnprotectData" ascii
        $aes = "aes-256-gcm" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($path*) and ($sql or $decrypt or $aes))
}

rule Stealer_Firefox_Password {
    meta:
        description = "Firefox password extraction"
        severity = "high"
    strings:
        $path1 = "\\Mozilla\\Firefox\\Profiles\\" ascii
        $file1 = "logins.json" ascii
        $file2 = "key4.db" ascii
        $file3 = "cert9.db" ascii
        $nss = "nss3.dll" ascii
        $pk11 = "PK11_" ascii
    condition:
        uint16(0) == 0x5A4D and ($path1 and (any of ($file*) or $nss or $pk11))
}

rule Stealer_Wallet_Crypto {
    meta:
        description = "Cryptocurrency wallet stealing"
        severity = "critical"
    strings:
        $w1 = "wallet.dat" ascii
        $w2 = "Electrum" ascii
        $w3 = "Exodus" ascii
        $w4 = "Atomic" ascii
        $w5 = "Jaxx" ascii
        $w6 = "Coinomi" ascii
        $w7 = "MetaMask" ascii
        $eth = "\\Ethereum\\" ascii
        $btc = "\\Bitcoin\\" ascii
        $ext = "\\Local Extension Settings\\" ascii
    condition:
        uint16(0) == 0x5A4D and (3 of ($w*) or any of ($eth, $btc, $ext))
}

rule Stealer_Browser_Cookie {
    meta:
        description = "Browser cookie stealing"
        severity = "high"
    strings:
        $cookie1 = "Cookies" ascii
        $cookie2 = "cookies.sqlite" ascii
        $chrome = "\\Google\\Chrome\\" ascii
        $edge = "\\Microsoft\\Edge\\" ascii
        $firefox = "\\Mozilla\\Firefox\\" ascii
        $sql = "SELECT host_key, name, encrypted_value FROM cookies" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (2 of ($chrome, $edge, $firefox) and (any of ($cookie*) or $sql))
}

rule Stealer_Discord_Token {
    meta:
        description = "Discord token stealing"
        severity = "high"
    strings:
        $discord = "discord" ascii nocase
        $token = "token" ascii nocase
        $path1 = "\\discord\\Local Storage\\leveldb" ascii
        $path2 = "\\discordptb\\Local Storage\\leveldb" ascii
        $path3 = "\\discordcanary\\Local Storage\\leveldb" ascii
        $regex = /[MN][A-Za-z0-9]{23,27}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27}/ ascii
    condition:
        uint16(0) == 0x5A4D and (($discord and $token) or any of ($path*) or $regex)
}

rule Stealer_Telegram_Session {
    meta:
        description = "Telegram session stealing"
        severity = "high"
    strings:
        $tg = "Telegram" ascii
        $tdata = "tdata" ascii
        $s1 = "D877F783D5D3EF8C" ascii
        $s2 = "\\Telegram Desktop\\" ascii
        // UNUSED: $map = "map" ascii
    condition:
        uint16(0) == 0x5A4D and ($tg and ($tdata or any of ($s*)))
}

rule Stealer_Email_Client {
    meta:
        description = "Email client credential theft"
        severity = "high"
    strings:
        $outlook = "Outlook" ascii
        $thunder = "Thunderbird" ascii
        $eudora = "Eudora" ascii
        $bat = "The Bat!" ascii
        $reg = "Software\\Microsoft\\Office" ascii
        $profile = "\\Profiles\\" ascii
    condition:
        uint16(0) == 0x5A4D and (2 of ($outlook, $thunder, $eudora, $bat) or ($reg and $profile))
}

rule Stealer_System_Info {
    meta:
        description = "System information collection"
        severity = "medium"
    strings:
        $api1 = "GetComputerNameA" ascii
        $api2 = "GetUserNameA" ascii
        $api3 = "GetSystemInfo" ascii
        $api4 = "GlobalMemoryStatusEx" ascii
        $api5 = "GetVersionExA" ascii
        $api6 = "GetAdaptersInfo" ascii
        $wmi = "SELECT * FROM Win32_" ascii nocase
        $cmd = "systeminfo" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (4 of ($api*) or $wmi or $cmd)
}

rule Stealer_Screenshot {
    meta:
        description = "Screenshot capture capability"
        severity = "medium"
    strings:
        $api1 = "GetDesktopWindow" ascii
        $api2 = "GetDC" ascii
        $api3 = "BitBlt" ascii
        $api4 = "CreateCompatibleBitmap" ascii
        $api5 = "CreateCompatibleDC" ascii
        // UNUSED: $gdi = "gdi32.dll" ascii
        $format = ".png" ascii
        $format2 = ".jpg" ascii
    condition:
        uint16(0) == 0x5A4D and (3 of ($api*) and any of ($format*))
}
