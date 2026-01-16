/*
    Stealer and Spyware Detection Rules
    Covers: Password stealers, info stealers, spyware
*/

rule Stealer_Browser_Generic {
    meta:
        description = "Generic browser credential stealer"
        severity = "critical"
    strings:
        $browser1 = "chrome" nocase
        $browser2 = "firefox" nocase
        $browser3 = "edge" nocase
        $browser4 = "opera" nocase
        $browser5 = "brave" nocase
        $data1 = "Login Data" ascii
        $data2 = "cookies.sqlite" ascii
        $data3 = "logins.json" ascii
        $crypto = "CryptUnprotectData" ascii
    condition:
        2 of ($browser*) and (any of ($data*) or $crypto)
}

rule Stealer_Chrome {
    meta:
        description = "Chrome credential stealer"
        severity = "critical"
    strings:
        $path1 = "Google\\Chrome\\User Data" ascii
        $path2 = "Default\\Login Data" ascii
        $path3 = "Local State" ascii
        $db = "SELECT" ascii
        $crypto = "CryptUnprotectData" ascii
    condition:
        any of ($path*) and ($db or $crypto)
}

rule Stealer_Firefox {
    meta:
        description = "Firefox credential stealer"
        severity = "critical"
    strings:
        $path1 = "Mozilla\\Firefox\\Profiles" ascii
        $path2 = "logins.json" ascii
        $path3 = "key4.db" ascii
        $path4 = "signons.sqlite" ascii
        $nss = "nss3.dll" ascii
    condition:
        2 of ($path*) or $nss
}

rule Stealer_Email_Client {
    meta:
        description = "Email client credential stealer"
        severity = "critical"
    strings:
        $client1 = "outlook" nocase
        $client2 = "thunderbird" nocase
        $client3 = "eudora" nocase
        $client4 = "foxmail" nocase
        $reg = "Software\\Microsoft\\Office" ascii
        $pass = "password" nocase
    condition:
        any of ($client*) and ($reg or $pass)
}

rule Stealer_FTP_Client {
    meta:
        description = "FTP client credential stealer"
        severity = "critical"
    strings:
        $client1 = "FileZilla" nocase
        $client2 = "WinSCP" nocase
        $client3 = "CoreFTP" nocase
        $client4 = "CuteFTP" nocase
        $file1 = "sitemanager.xml" ascii
        $file2 = "recentservers.xml" ascii
    condition:
        any of ($client*) and any of ($file*)
}

rule Stealer_VPN_Client {
    meta:
        description = "VPN client credential stealer"
        severity = "critical"
    strings:
        $vpn1 = "NordVPN" nocase
        $vpn2 = "OpenVPN" nocase
        $vpn3 = "ProtonVPN" nocase
        $vpn4 = "ExpressVPN" nocase
        $config = ".ovpn" ascii
        $cred = "credential" nocase
    condition:
        any of ($vpn*) and ($config or $cred)
}

rule Stealer_Crypto_Wallet {
    meta:
        description = "Cryptocurrency wallet stealer"
        severity = "critical"
    strings:
        $wallet1 = "wallet.dat" ascii
        $wallet2 = "electrum" nocase
        $wallet3 = "exodus" nocase
        $wallet4 = "metamask" nocase
        $wallet5 = "coinbase" nocase
        $wallet6 = "atomic" nocase
        $path1 = "Bitcoin" nocase
        $path2 = "Ethereum" nocase
    condition:
        2 of ($wallet*) or any of ($path*)
}

rule Stealer_Discord_Token {
    meta:
        description = "Discord token stealer"
        severity = "critical"
    strings:
        $s1 = "discord" nocase
        $s2 = "token" ascii
        $path1 = "discord\\Local Storage" ascii
        $path2 = "discordcanary" ascii
        $path3 = "discordptb" ascii
        $regex = /[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}/
    condition:
        ($s1 and $s2) or any of ($path*) or $regex
}

rule Stealer_Telegram {
    meta:
        description = "Telegram data stealer"
        severity = "critical"
    strings:
        $s1 = "telegram" nocase
        $s2 = "tdata" ascii
        $path = "Telegram Desktop" ascii
        $file = "D877F783D5D3EF8C" ascii
    condition:
        ($s1 and $s2) or $path or $file
}

rule Stealer_Steam {
    meta:
        description = "Steam credential stealer"
        severity = "critical"
    strings:
        $s1 = "steam" nocase
        $s2 = "ssfn" ascii
        $path = "Steam\\config" ascii
        $file = "loginusers.vdf" ascii
    condition:
        ($s1 and $s2) or $path or $file
}

rule RedLine_Stealer {
    meta:
        description = "RedLine Stealer"
        severity = "critical"
    strings:
        $s1 = "RedLine" ascii
        $s2 = "Yandex" ascii
        $s3 = "ScanDetails" ascii
        $s4 = "GrabBrowsers" ascii
    condition:
        any of them
}

rule Raccoon_Stealer {
    meta:
        description = "Raccoon Stealer"
        severity = "critical"
    strings:
        $s1 = "Raccoon" ascii
        $s2 = "machineId" ascii
        $s3 = "configId" ascii
        $gate = "gate.php" ascii
    condition:
        any of ($s*) or $gate
}

rule Vidar_Stealer {
    meta:
        description = "Vidar Stealer"
        severity = "critical"
    strings:
        $s1 = "vidar" nocase
        $s2 = "arkei" nocase
        $ip = "ip-api.com" ascii
        $grab = "grabber" ascii
    condition:
        any of ($s*) or ($ip and $grab)
}

rule Mars_Stealer {
    meta:
        description = "Mars Stealer"
        severity = "critical"
    strings:
        $s1 = "MarsTeam" ascii
        $s2 = "mars" nocase
        $grab1 = "GrabBrowsers" ascii
        $grab2 = "GrabWallets" ascii
    condition:
        any of ($s*) or any of ($grab*)
}

rule Azorult_Stealer {
    meta:
        description = "AZORult Stealer"
        severity = "critical"
    strings:
        $s1 = "AZORult" ascii
        $s2 = "azorult" nocase
        $xor = {33 C0 8A 04 01 32 04 02}
        $cfg = "config" ascii
    condition:
        any of ($s*) or $xor
}

rule Pony_Stealer {
    meta:
        description = "Pony/Fareit Stealer"
        severity = "critical"
    strings:
        $s1 = "pony" nocase
        $s2 = "fareit" nocase
        $s3 = "gate.php" ascii
        $magic = {B6 D5 24 2C}
    condition:
        any of ($s*) or $magic
}

rule Agent_Tesla_Stealer {
    meta:
        description = "Agent Tesla"
        severity = "critical"
    strings:
        $s1 = "AgentTesla" ascii
        $smtp = "smtp." ascii
        $ftp = "ftp://" ascii
        $telegram = "api.telegram.org" ascii
    condition:
        $s1 or ($smtp and any of ($ftp, $telegram))
}

rule FormBook_Stealer {
    meta:
        description = "FormBook"
        severity = "critical"
    strings:
        $s1 = "FormBook" ascii
        $s2 = "xloader" ascii
        $anti = "SbieDll" ascii
        $sha = "sha1" ascii
    condition:
        any of ($s*) or ($anti and $sha)
}

rule LokiBot_Stealer {
    meta:
        description = "LokiBot"
        severity = "critical"
    strings:
        $s1 = "lokibot" nocase
        $s2 = "loki" nocase
        $ftp = "ftp://" ascii
        $http = "http://" ascii
    condition:
        any of ($s*) or ($ftp and $http)
}

rule Keylogger_Generic {
    meta:
        description = "Generic keylogger"
        severity = "critical"
    strings:
        $api1 = "GetAsyncKeyState" ascii
        $api2 = "GetKeyboardState" ascii
        $api3 = "SetWindowsHookExA" ascii
        $api4 = "SetWindowsHookExW" ascii
        $api5 = "GetKeyState" ascii
        $log = "keylog" nocase
    condition:
        2 of ($api*) or $log
}

rule Screen_Capture {
    meta:
        description = "Screen capture capability"
        severity = "high"
    strings:
        $api1 = "GetDC" ascii
        $api2 = "BitBlt" ascii
        $api3 = "CreateCompatibleDC" ascii
        $api4 = "GetWindowDC" ascii
        $s1 = "screenshot" nocase
        $s2 = "screen capture" nocase
    condition:
        3 of ($api*) or any of ($s*)
}

rule Clipboard_Stealer {
    meta:
        description = "Clipboard stealer"
        severity = "high"
    strings:
        $api1 = "GetClipboardData" ascii
        $api2 = "OpenClipboard" ascii
        $api3 = "CloseClipboard" ascii
        $btc = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/
    condition:
        2 of ($api*) or $btc
}

rule Webcam_Capture {
    meta:
        description = "Webcam capture capability"
        severity = "high"
    strings:
        $api1 = "capCreateCaptureWindow" ascii
        $api2 = "capDriverConnect" ascii
        $api3 = "capGrabFrame" ascii
        $s1 = "webcam" nocase
        $s2 = "camera" nocase
    condition:
        any of ($api*) or any of ($s*)
}

rule Microphone_Capture {
    meta:
        description = "Microphone capture capability"
        severity = "high"
    strings:
        $api1 = "waveInOpen" ascii
        $api2 = "waveInStart" ascii
        $api3 = "mciSendString" ascii
        $s1 = "microphone" nocase
        $s2 = "audio" nocase
        $s3 = "record" nocase
    condition:
        2 of ($api*) or 2 of ($s*)
}

rule StealC_Stealer {
    meta:
        description = "StealC Stealer"
        severity = "critical"
    strings:
        $s1 = "stealc" nocase
        $s2 = "StealC" ascii
        $grab = "grabber" ascii
    condition:
        any of ($s*) or $grab
}

rule Lumma_Stealer {
    meta:
        description = "Lumma Stealer"
        severity = "critical"
    strings:
        $s1 = "lumma" nocase
        $s2 = "LummaC2" ascii
        $cfg = "config" ascii
    condition:
        any of ($s*) or $cfg
}

rule Rhadamanthys_Stealer {
    meta:
        description = "Rhadamanthys Stealer"
        severity = "critical"
    strings:
        $s1 = "rhadamanthys" nocase
        $s2 = "Rhadamanthys" ascii
        $loader = "loader" ascii
    condition:
        any of ($s*) or $loader
}
