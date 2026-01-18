/*
    Credential Stealer Detection Rules
    Password dumpers, credential harvesters, and authentication theft
*/

rule Credential_Mimikatz {
    meta:
        description = "Mimikatz credential dumper"
        severity = "critical"
    strings:
        $mimi1 = "mimikatz" ascii nocase
        $mimi2 = "gentilkiwi" ascii
        $mimi3 = "sekurlsa" ascii
        $mimi4 = "kerberos" ascii
        $mimi5 = "wdigest" ascii
        $mimi6 = "dpapi" ascii
        $logon = "logonPasswords" ascii
        $lsadump = "lsadump" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($mimi*) or ($logon and $lsadump))
}

rule Credential_LaZagne {
    meta:
        description = "LaZagne credential harvester"
        severity = "critical"
    strings:
        $lazagne = "LaZagne" ascii nocase
        $softwares = "softwares" ascii
        $browsers = "browsers" ascii
        $sysadmin = "sysadmin" ascii
        $databases = "databases" ascii
        $memory = "memory" ascii
    condition:
        uint16(0) == 0x5A4D and ($lazagne or (3 of ($softwares, $browsers, $sysadmin, $databases, $memory)))
}

rule Credential_SharpHound {
    meta:
        description = "SharpHound/BloodHound collector"
        severity = "critical"
    strings:
        $sharphound = "SharpHound" ascii nocase
        $bloodhound = "BloodHound" ascii nocase
        $ldap = "LDAP" ascii
        $ad = "ActiveDirectory" ascii
        $collect = "Collect" ascii
        $session = "Session" ascii
        $group = "Group" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($sharphound, $bloodhound) or ($ldap and $ad and any of ($collect, $session, $group)))
}

rule Credential_Rubeus {
    meta:
        description = "Rubeus Kerberos toolkit"
        severity = "critical"
    strings:
        $rubeus = "Rubeus" ascii nocase
        $asktgt = "asktgt" ascii
        $asktgs = "asktgs" ascii
        $kerberoast = "kerberoast" ascii
        $renew = "renew" ascii
        $s4u = "s4u" ascii
        $ptt = "ptt" ascii
    condition:
        uint16(0) == 0x5A4D and ($rubeus or (2 of ($asktgt, $asktgs, $kerberoast, $renew, $s4u, $ptt)))
}

rule Credential_SharpDPAPI {
    meta:
        description = "SharpDPAPI credential theft"
        severity = "critical"
    strings:
        $sharpdpapi = "SharpDPAPI" ascii nocase
        $dpapi = "DPAPI" ascii
        $masterkey = "MasterKey" ascii
        $credentials = "Credentials" ascii
        $chrome = "Chrome" ascii
        $blob = "blob" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($sharpdpapi or ($dpapi and any of ($masterkey, $credentials, $chrome, $blob)))
}

rule Credential_Pypykatz {
    meta:
        description = "Pypykatz credential dumper"
        severity = "critical"
    strings:
        $pypykatz = "pypykatz" ascii nocase
        // UNUSED: $python = "python" ascii nocase
        $lsass = "lsass" ascii nocase
        $minidump = "minidump" ascii nocase
        // UNUSED: $sekurlsa = "sekurlsa" ascii
    condition:
        uint16(0) == 0x5A4D and ($pypykatz or ($lsass and $minidump))
}

rule Credential_Browser_Stealer {
    meta:
        description = "Browser credential stealer"
        severity = "critical"
    strings:
        $chrome = "Chrome" ascii
        $firefox = "Firefox" ascii
        $edge = "Edge" ascii
        $brave = "Brave" ascii
        $login = "Login Data" ascii
        $cookies = "Cookies" ascii
        $decrypt = "CryptUnprotectData" ascii
        $dpapi = "DPAPI" ascii
        $local_state = "Local State" ascii
    condition:
        uint16(0) == 0x5A4D and (2 of ($chrome, $firefox, $edge, $brave)) and (any of ($login, $cookies)) and (any of ($decrypt, $dpapi, $local_state))
}

rule Credential_LSASS_Dump {
    meta:
        description = "LSASS process dumping"
        severity = "critical"
    strings:
        $lsass = "lsass.exe" ascii nocase
        $dump1 = "MiniDump" ascii
        $dump2 = "procdump" ascii nocase
        $dump3 = "comsvcs.dll" ascii
        $dump4 = "minidump" ascii nocase
        $api1 = "MiniDumpWriteDump" ascii
        $api2 = "OpenProcess" ascii
    condition:
        uint16(0) == 0x5A4D and $lsass and (any of ($dump*) or any of ($api*))
}

rule Credential_SAM_Dump {
    meta:
        description = "SAM/SYSTEM registry dumping"
        severity = "critical"
    strings:
        $sam = "\\SAM" ascii
        $system = "\\SYSTEM" ascii
        $security = "\\SECURITY" ascii
        $save = "reg save" ascii nocase
        $export = "reg export" ascii nocase
        $copy = "copy" ascii nocase
        $shadow = "shadow" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ((any of ($sam, $system, $security)) and (any of ($save, $export, $copy, $shadow)))
}

rule Credential_NTDS_Dump {
    meta:
        description = "NTDS.dit database theft"
        severity = "critical"
    strings:
        $ntds = "ntds.dit" ascii nocase
        $dit = ".dit" ascii
        $shadow = "vssadmin" ascii nocase
        $shadow2 = "diskshadow" ascii nocase
        $copy = "copy" ascii nocase
        $esentutl = "esentutl" ascii nocase
        $secretsdump = "secretsdump" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($ntds or $dit) and (any of ($shadow, $shadow2, $copy, $esentutl, $secretsdump))
}

rule Credential_DCSync {
    meta:
        description = "DCSync attack"
        severity = "critical"
    strings:
        $dcsync = "dcsync" ascii nocase
        $drsuapi = "DRSUAPI" ascii
        $getncchanges = "GetNCChanges" ascii
        $replication = "replication" ascii nocase
        $lsadump = "lsadump::dcsync" ascii
    condition:
        uint16(0) == 0x5A4D and (any of them)
}

rule Credential_WiFi_Stealer {
    meta:
        description = "WiFi credential stealer"
        severity = "high"
    strings:
        $netsh = "netsh" ascii nocase
        $wlan = "wlan" ascii nocase
        $profile = "profile" ascii nocase
        $key = "key=clear" ascii nocase
        $export = "export" ascii nocase
        $show = "show" ascii nocase
    condition:
        uint16(0) == 0x5A4D and $netsh and $wlan and (any of ($profile, $key, $export, $show))
}

rule Credential_Email_Stealer {
    meta:
        description = "Email credential stealer"
        severity = "high"
    strings:
        $outlook = "Outlook" ascii
        $thunderbird = "Thunderbird" ascii
        $imap = "IMAP" ascii
        $smtp = "SMTP" ascii
        $pop3 = "POP3" ascii
        $password = "Password" ascii
        $account = "Account" ascii
        // UNUSED: $registry = "Software\\Microsoft\\Office" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($outlook, $thunderbird)) and (any of ($imap, $smtp, $pop3)) and any of ($password, $account)
}

rule Credential_FTP_Stealer {
    meta:
        description = "FTP credential stealer"
        severity = "high"
    strings:
        $filezilla = "FileZilla" ascii
        $winscp = "WinSCP" ascii
        $coreftp = "CoreFTP" ascii
        $flashfxp = "FlashFXP" ascii
        $recentservers = "recentservers.xml" ascii
        $sitemanager = "sitemanager.xml" ascii
        $sessions = "sessions" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($filezilla, $winscp, $coreftp, $flashfxp)) and (any of ($recentservers, $sitemanager, $sessions))
}

rule Credential_VPN_Stealer {
    meta:
        description = "VPN credential stealer"
        severity = "high"
    strings:
        $openvpn = "OpenVPN" ascii
        $nordvpn = "NordVPN" ascii
        $protonvpn = "ProtonVPN" ascii
        $expressvpn = "ExpressVPN" ascii
        $config = ".ovpn" ascii
        $auth = "auth-user-pass" ascii
        $credentials = "credentials" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($openvpn, $nordvpn, $protonvpn, $expressvpn)) and (any of ($config, $auth, $credentials))
}

rule Credential_SSH_Key_Stealer {
    meta:
        description = "SSH key stealer"
        severity = "critical"
    strings:
        $ssh_dir = ".ssh" ascii
        $id_rsa = "id_rsa" ascii
        $id_ed25519 = "id_ed25519" ascii
        $known_hosts = "known_hosts" ascii
        $authorized = "authorized_keys" ascii
        $putty = "PuTTY" ascii
        $pageant = "Pageant" ascii
        $private = "PRIVATE KEY" ascii
    condition:
        uint16(0) == 0x5A4D and ($ssh_dir or any of ($id_rsa, $id_ed25519)) and (any of ($known_hosts, $authorized, $putty, $pageant, $private))
}

rule Credential_RDP_Stealer {
    meta:
        description = "RDP credential stealer"
        severity = "high"
    strings:
        $rdp = "Remote Desktop" ascii
        $mstsc = "mstsc" ascii nocase
        $rdcman = "RDCMan" ascii
        $default_rdp = "Default.rdp" ascii
        $credential = "Credential" ascii
        $terminal = "Terminal Server" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($rdp, $mstsc, $rdcman)) and (any of ($default_rdp, $credential, $terminal))
}

rule Credential_Keylogger_Generic {
    meta:
        description = "Generic keylogger"
        severity = "high"
    strings:
        $api1 = "SetWindowsHookExA" ascii
        $api2 = "SetWindowsHookExW" ascii
        $api3 = "GetAsyncKeyState" ascii
        $api4 = "GetKeyState" ascii
        $api5 = "GetKeyboardState" ascii
        // UNUSED: $hook = "WH_KEYBOARD" ascii
        $log = "log" ascii nocase
        $key = "key" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($api1, $api2) or any of ($api3, $api4, $api5)) and any of ($log, $key)
}

rule Credential_Clipboard_Stealer {
    meta:
        description = "Clipboard credential stealer"
        severity = "medium"
    strings:
        $api1 = "GetClipboardData" ascii
        $api2 = "OpenClipboard" ascii
        $api3 = "SetClipboardViewer" ascii
        $api4 = "AddClipboardFormatListener" ascii
        $format = "CF_TEXT" ascii
        $crypto = "crypto" ascii nocase
        $wallet = "wallet" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (2 of ($api*)) and (any of ($format, $crypto, $wallet))
}

rule Credential_Database_Stealer {
    meta:
        description = "Database credential stealer"
        severity = "high"
    strings:
        $mysql = "MySQL" ascii
        $postgres = "PostgreSQL" ascii
        $mssql = "MSSQL" ascii
        $oracle = "Oracle" ascii
        $connection = "connection" ascii nocase
        $datasource = "Data Source" ascii
        $password = "Password" ascii
        $user = "User" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($mysql, $postgres, $mssql, $oracle)) and ($connection or $datasource) and ($password or $user)
}

rule Credential_Cloud_Stealer {
    meta:
        description = "Cloud credential stealer"
        severity = "critical"
    strings:
        $aws = "AWS" ascii
        $azure = "Azure" ascii
        $gcp = "GCP" ascii
        $credentials = ".aws/credentials" ascii
        $config = ".aws/config" ascii
        $access_key = "aws_access_key" ascii
        $secret = "aws_secret" ascii
        $token = "token" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($aws, $azure, $gcp)) and (any of ($credentials, $config, $access_key, $secret, $token))
}

