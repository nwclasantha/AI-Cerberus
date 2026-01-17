/*
    Data Exfiltration Technique Detection
    Data staging, compression, encoding, and exfiltration methods
*/

rule Exfil_Data_Staging {
    meta:
        description = "Data staging for exfiltration"
        severity = "high"
    strings:
        $path1 = "\\AppData\\Local\\Temp\\" ascii
        $path2 = "\\ProgramData\\" ascii
        $path3 = "\\Recycle" ascii
        $ext1 = ".zip" ascii
        $ext2 = ".rar" ascii
        $ext3 = ".7z" ascii
        $ext4 = ".tar" ascii
        $collect = "collect" ascii nocase
        $stage = "stage" ascii nocase
        $copy = "CopyFile" ascii
    condition:
        uint16(0) == 0x5A4D and
        (any of ($path*) and any of ($ext*)) or (any of ($collect, $stage) and $copy)
}

rule Exfil_Archive_Creation {
    meta:
        description = "Archive creation for exfiltration"
        severity = "high"
    strings:
        $zip1 = { 50 4B 03 04 }  // ZIP magic
        $rar1 = { 52 61 72 21 }  // RAR magic
        $7z1 = { 37 7A BC AF }  // 7z magic
        $api1 = "CreateFile" ascii
        $api2 = "WriteFile" ascii
        $compress = "compress" ascii nocase
        $password = "password" ascii nocase
        $encrypt = "encrypt" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        (any of ($zip1, $rar1, $7z1) or ($compress and any of ($api*))) and ($password or $encrypt)
}

rule Exfil_HTTP_POST {
    meta:
        description = "HTTP POST data exfiltration"
        severity = "high"
    strings:
        $http = "http" ascii nocase
        $post = "POST" ascii
        $api1 = "HttpOpenRequest" ascii
        $api2 = "HttpSendRequest" ascii
        $api3 = "InternetConnect" ascii
        $content = "Content-Type:" ascii
        $boundary = "boundary=" ascii
        $multipart = "multipart/form-data" ascii
    condition:
        uint16(0) == 0x5A4D and
        ($http and $post and any of ($api*)) or ($content and any of ($boundary, $multipart))
}

rule Exfil_FTP_Upload {
    meta:
        description = "FTP data exfiltration"
        severity = "high"
    strings:
        $ftp1 = "ftp://" ascii nocase
        $ftp2 = "FtpPutFile" ascii
        $ftp3 = "FtpOpenFile" ascii
        $api1 = "InternetConnect" ascii
        $port = "21" ascii
        $stor = "STOR" ascii
        $user = "USER" ascii
        $pass = "PASS" ascii
    condition:
        uint16(0) == 0x5A4D and
        (any of ($ftp*) or ($api1 and $port and any of ($stor, $user, $pass)))
}

rule Exfil_SFTP_SCP {
    meta:
        description = "SFTP/SCP data exfiltration"
        severity = "high"
    strings:
        $sftp = "sftp" ascii nocase
        $scp = "scp" ascii nocase
        $ssh = "ssh" ascii nocase
        $put = "put" ascii
        $key = ".pem" ascii
        $port = "22" ascii
    condition:
        uint16(0) == 0x5A4D and
        (any of ($sftp, $scp) or ($ssh and $put)) and (any of ($key, $port))
}

rule Exfil_Cloud_Storage {
    meta:
        description = "Cloud storage exfiltration"
        severity = "high"
    strings:
        $dropbox = "dropbox" ascii nocase
        $gdrive = "drive.google" ascii nocase
        $onedrive = "onedrive" ascii nocase
        $mega = "mega.nz" ascii nocase
        $aws = "s3.amazonaws" ascii nocase
        $azure = "blob.core.windows" ascii nocase
        $api = "API" ascii
        $upload = "upload" ascii nocase
        $token = "token" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        (any of ($dropbox, $gdrive, $onedrive, $mega, $aws, $azure)) and ($upload or $token)
}

rule Exfil_Email_SMTP {
    meta:
        description = "Email-based data exfiltration"
        severity = "high"
    strings:
        $smtp1 = "smtp" ascii nocase
        $smtp2 = "MAIL FROM:" ascii
        $smtp3 = "RCPT TO:" ascii
        $smtp4 = "DATA" ascii
        $api1 = "SmtpClient" ascii
        $attach = "attachment" ascii nocase
        $base64 = "Content-Transfer-Encoding: base64" ascii
        $port = "587" ascii
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($smtp*) or ($api1 and $attach)) and (any of ($base64, $port))
}

rule Exfil_DNS_Tunnel {
    meta:
        description = "DNS tunneling for exfiltration"
        severity = "critical"
    strings:
        $dns1 = "DnsQuery" ascii
        $dns2 = "getaddrinfo" ascii
        $txt = "TXT" ascii
        $cname = "CNAME" ascii
        $mx = "MX" ascii
        $encode = "base32" ascii nocase
        $encode2 = "base64" ascii nocase
        $long = /[a-z0-9]{50,}\.[a-z]{2,}/ ascii
    condition:
        uint16(0) == 0x5A4D and
        (any of ($dns*) and any of ($txt, $cname, $mx)) and (any of ($encode, $encode2) or $long)
}

rule Exfil_ICMP_Covert {
    meta:
        description = "ICMP covert channel exfiltration"
        severity = "critical"
    strings:
        $icmp = "IPPROTO_ICMP" ascii
        $raw = "SOCK_RAW" ascii
        $api1 = "IcmpSendEcho" ascii
        $api2 = "socket" ascii
        $ping = "ping" ascii nocase
        $data = "data" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        ($icmp or $api1) and ($raw or $api2) and any of ($ping, $data)
}

rule Exfil_WebDAV {
    meta:
        description = "WebDAV exfiltration"
        severity = "high"
    strings:
        $webdav = "webdav" ascii nocase
        $dav = "DAV:" ascii
        $put = "PUT" ascii
        $propfind = "PROPFIND" ascii
        $http = "http" ascii nocase
        $api = "WinHttpSendRequest" ascii
    condition:
        uint16(0) == 0x5A4D and
        (($webdav or $dav) and any of ($put, $propfind)) or ($http and $put and $api)
}

rule Exfil_Telegram_Bot {
    meta:
        description = "Telegram bot exfiltration"
        severity = "high"
    strings:
        $tg1 = "api.telegram.org" ascii
        $tg2 = "/bot" ascii
        $send = "sendDocument" ascii
        $send2 = "sendMessage" ascii
        $send3 = "sendPhoto" ascii
        $token = /\d{9,10}:[A-Za-z0-9_-]{35}/ ascii
    condition:
        uint16(0) == 0x5A4D and
        ($tg1 and any of ($send, $send2, $send3)) or $token
}

rule Exfil_Discord_Webhook {
    meta:
        description = "Discord webhook exfiltration"
        severity = "high"
    strings:
        $discord = "discord.com/api/webhooks" ascii
        $hook = "webhook" ascii nocase
        $embed = "embeds" ascii
        $file = "file" ascii
        $api = "POST" ascii
    condition:
        uint16(0) == 0x5A4D and ($discord or ($hook and $embed and $file and $api))
}

rule Exfil_Pastebin {
    meta:
        description = "Pastebin data exfiltration"
        severity = "high"
    strings:
        $paste1 = "pastebin.com" ascii
        $paste2 = "paste.ee" ascii
        $paste3 = "ghostbin" ascii
        $paste4 = "hastebin" ascii
        $api = "api_dev_key" ascii
        $post = "POST" ascii
        $raw = "/raw/" ascii
    condition:
        uint16(0) == 0x5A4D and
        (any of ($paste*) and any of ($api, $post, $raw))
}

rule Exfil_Encoded_Data {
    meta:
        description = "Encoded data for exfiltration"
        severity = "medium"
    strings:
        $b64 = "base64" ascii nocase
        $b32 = "base32" ascii nocase
        $hex = "hexencode" ascii nocase
        $xor = "xor" ascii nocase
        $api1 = "CryptBinaryToStringA" ascii
        $api2 = "CryptStringToBinaryA" ascii
        $long_b64 = /[A-Za-z0-9+\/=]{100,}/ ascii
    condition:
        uint16(0) == 0x5A4D and
        ((any of ($b64, $b32, $hex, $xor)) and any of ($api*)) or $long_b64
}

rule Exfil_Screenshot_Capture {
    meta:
        description = "Screenshot capture for exfiltration"
        severity = "medium"
    strings:
        $api1 = "GetDesktopWindow" ascii
        $api2 = "GetDC" ascii
        $api3 = "BitBlt" ascii
        $api4 = "CreateCompatibleBitmap" ascii
        $api5 = "GetDIBits" ascii
        $save = "Save" ascii
        $ext1 = ".png" ascii
        $ext2 = ".jpg" ascii
        $ext3 = ".bmp" ascii
    condition:
        uint16(0) == 0x5A4D and (3 of ($api*) and any of ($ext*))
}

rule Exfil_Clipboard_Monitor {
    meta:
        description = "Clipboard monitoring for exfiltration"
        severity = "medium"
    strings:
        $api1 = "GetClipboardData" ascii
        $api2 = "OpenClipboard" ascii
        $api3 = "SetClipboardViewer" ascii
        $api4 = "AddClipboardFormatListener" ascii
        $format = "CF_" ascii
        $timer = "SetTimer" ascii
    condition:
        uint16(0) == 0x5A4D and (2 of ($api*) and any of ($format, $timer))
}

rule Exfil_Keylogger_Output {
    meta:
        description = "Keylogger output for exfiltration"
        severity = "high"
    strings:
        $hook = "SetWindowsHookExA" ascii
        $key = "WH_KEYBOARD" ascii
        $ll = "WH_KEYBOARD_LL" ascii
        $log = "log" ascii nocase
        $file = "CreateFile" ascii
        $write = "WriteFile" ascii
        $ext = ".txt" ascii
    condition:
        uint16(0) == 0x5A4D and
        ($hook and any of ($key, $ll)) and ($file or $write or $ext)
}
