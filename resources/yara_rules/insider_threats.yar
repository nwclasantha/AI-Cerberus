/*
    Insider Threat Detection
    Data theft, sabotage, and unauthorized access tools
*/

rule Insider_USB_Exfiltration {
    meta:
        description = "USB data exfiltration tool"
        severity = "critical"
    strings:
        $usb1 = "USB" ascii
        $usb2 = "removable" ascii nocase
        $usb3 = "\\Device\\Harddisk" ascii
        $copy = "copy" ascii nocase
        $transfer = "transfer" ascii nocase
        $auto = "auto" ascii nocase
        $stealth = "stealth" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($usb*)) and (any of ($copy, $transfer)) and any of ($auto, $stealth)
}

rule Insider_Email_Exfiltration {
    meta:
        description = "Email data exfiltration"
        severity = "high"
    strings:
        $smtp = "SMTP" ascii
        $email = "email" ascii nocase
        $send = "send" ascii nocase
        $attach = "attach" ascii nocase
        $forward = "forward" ascii nocase
        $bulk = "bulk" ascii nocase
        $auto = "auto" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($smtp or $email) and $send and any of ($attach, $forward, $bulk, $auto)
}

rule Insider_Cloud_Upload {
    meta:
        description = "Unauthorized cloud upload"
        severity = "high"
    strings:
        $dropbox = "Dropbox" ascii nocase
        $gdrive = "Google Drive" ascii nocase
        $onedrive = "OneDrive" ascii nocase
        $box = "box.com" ascii nocase
        $upload = "upload" ascii nocase
        $sync = "sync" ascii nocase
        $bulk = "bulk" ascii nocase
    condition:
        (any of ($dropbox, $gdrive, $onedrive, $box)) and any of ($upload, $sync, $bulk)
}

rule Insider_Database_Dump {
    meta:
        description = "Database data dump tool"
        severity = "critical"
    strings:
        $mysql = "mysql" ascii nocase
        $mssql = "sqlcmd" ascii nocase
        $oracle = "sqlplus" ascii nocase
        $dump = "dump" ascii nocase
        $export = "export" ascii nocase
        $backup = "backup" ascii nocase
        $all = "all" ascii nocase
    condition:
        (any of ($mysql, $mssql, $oracle)) and any of ($dump, $export, $backup) and $all
}

rule Insider_File_Harvester {
    meta:
        description = "Sensitive file harvester"
        severity = "critical"
    strings:
        $docx = ".docx" ascii nocase
        $xlsx = ".xlsx" ascii nocase
        $pdf = ".pdf" ascii nocase
        $pptx = ".pptx" ascii nocase
        $search = "search" ascii nocase
        $harvest = "harvest" ascii nocase
        $collect = "collect" ascii nocase
        $confidential = "confidential" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (2 of ($docx, $xlsx, $pdf, $pptx)) and any of ($search, $harvest, $collect, $confidential)
}

rule Insider_Network_Scanner_Internal {
    meta:
        description = "Internal network scanning"
        severity = "high"
    strings:
        $scan = "scan" ascii nocase
        $network = "network" ascii nocase
        $port = "port" ascii nocase
        $host = "host" ascii nocase
        $internal = "internal" ascii nocase
        $range = "range" ascii nocase
        $192 = "192.168" ascii
        $10 = "10.0" ascii
    condition:
        uint16(0) == 0x5A4D and ($scan and any of ($network, $port, $host)) and any of ($internal, $range, $192, $10)
}

rule Insider_Credential_Harvest {
    meta:
        description = "Credential harvesting"
        severity = "critical"
    strings:
        $cred = "credential" ascii nocase
        $password = "password" ascii nocase
        $harvest = "harvest" ascii nocase
        $dump = "dump" ascii nocase
        $lsass = "lsass" ascii nocase
        $sam = "SAM" ascii
        $ntds = "NTDS" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($cred, $password)) and any of ($harvest, $dump, $lsass, $sam, $ntds)
}

rule Insider_Keylogger_Install {
    meta:
        description = "Keylogger installation"
        severity = "critical"
    strings:
        $keylog = "keylog" ascii nocase
        $keystroke = "keystroke" ascii nocase
        $install = "install" ascii nocase
        $hook = "hook" ascii nocase
        $capture = "capture" ascii nocase
        $record = "record" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($keylog, $keystroke)) and any of ($install, $hook, $capture, $record)
}

rule Insider_Screenshot_Tool {
    meta:
        description = "Screenshot capture tool"
        severity = "medium"
    strings:
        $screen = "screen" ascii nocase
        $shot = "shot" ascii nocase
        $capture = "capture" ascii nocase
        $desktop = "desktop" ascii nocase
        $auto = "auto" ascii nocase
        $interval = "interval" ascii nocase
        $save = "save" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($screen and any of ($shot, $capture)) and any of ($auto, $interval, $save)
}

rule Insider_Sabotage_Tool {
    meta:
        description = "System sabotage tool"
        severity = "critical"
    strings:
        $delete = "delete" ascii nocase
        $destroy = "destroy" ascii nocase
        $wipe = "wipe" ascii nocase
        $corrupt = "corrupt" ascii nocase
        $disable = "disable" ascii nocase
        $all = "all" ascii nocase
        $force = "force" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($delete, $destroy, $wipe, $corrupt, $disable)) and any of ($all, $force)
}

rule Insider_Time_Bomb {
    meta:
        description = "Logic bomb/time bomb"
        severity = "critical"
    strings:
        $date = "date" ascii nocase
        $time = "time" ascii nocase
        $trigger = "trigger" ascii nocase
        $bomb = "bomb" ascii nocase
        $countdown = "countdown" ascii nocase
        $execute = "execute" ascii nocase
        $schedule = "schedule" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($date, $time)) and (any of ($trigger, $bomb, $countdown)) and any of ($execute, $schedule)
}

rule Insider_Backdoor_Creation {
    meta:
        description = "Backdoor account creation"
        severity = "critical"
    strings:
        $net = "net user" ascii nocase
        $add = "add" ascii nocase
        $admin = "administrator" ascii nocase
        $local = "localgroup" ascii nocase
        $hidden = "hidden" ascii nocase
        $ssh = "authorized_keys" ascii
    condition:
        (($net and $add and any of ($admin, $local)) or ($ssh and $hidden))
}

rule Insider_RDP_Enable {
    meta:
        description = "Unauthorized RDP enabling"
        severity = "high"
    strings:
        $rdp = "Remote Desktop" ascii nocase
        $enable = "enable" ascii nocase
        $reg1 = "fDenyTSConnections" ascii
        $reg2 = "TerminalServices" ascii
        $firewall = "firewall" ascii nocase
        $allow = "allow" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($rdp or any of ($reg1, $reg2)) and any of ($enable, $firewall, $allow)
}

rule Insider_VPN_Backdoor {
    meta:
        description = "Unauthorized VPN setup"
        severity = "high"
    strings:
        $vpn = "VPN" ascii
        $tunnel = "tunnel" ascii nocase
        $remote = "remote" ascii nocase
        $access = "access" ascii nocase
        $install = "install" ascii nocase
        $hidden = "hidden" ascii nocase
    condition:
        uint16(0) == 0x5A4D and $vpn and (any of ($tunnel, $remote)) and any of ($access, $install, $hidden)
}

rule Insider_Data_Staging {
    meta:
        description = "Data staging for exfiltration"
        severity = "high"
    strings:
        $stage = "stage" ascii nocase
        $collect = "collect" ascii nocase
        $compress = "compress" ascii nocase
        $archive = "archive" ascii nocase
        $zip = ".zip" ascii nocase
        $rar = ".rar" ascii nocase
        $encrypt = "encrypt" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($stage, $collect)) and any of ($compress, $archive, $zip, $rar, $encrypt)
}

rule Insider_Print_Exfiltration {
    meta:
        description = "Print-based data exfiltration"
        severity = "medium"
    strings:
        $print = "print" ascii nocase
        $document = "document" ascii nocase
        $bulk = "bulk" ascii nocase
        $queue = "queue" ascii nocase
        $all = "all" ascii nocase
        $batch = "batch" ascii nocase
    condition:
        uint16(0) == 0x5A4D and $print and ($document or $queue) and any of ($bulk, $all, $batch)
}

rule Insider_Source_Code_Theft {
    meta:
        description = "Source code theft tool"
        severity = "critical"
    strings:
        $git = ".git" ascii
        $svn = ".svn" ascii
        $repo = "repository" ascii nocase
        $clone = "clone" ascii nocase
        $source = "source" ascii nocase
        $code = "code" ascii nocase
        $all = "all" ascii nocase
    condition:
        (any of ($git, $svn, $repo)) and ($clone or any of ($source, $code)) and $all
}

rule Insider_Trade_Secret {
    meta:
        description = "Trade secret theft indicators"
        severity = "critical"
    strings:
        $trade = "trade secret" ascii nocase
        $proprietary = "proprietary" ascii nocase
        $confidential = "confidential" ascii nocase
        $copy = "copy" ascii nocase
        $export = "export" ascii nocase
        $send = "send" ascii nocase
        $personal = "personal" ascii nocase
    condition:
        (any of ($trade, $proprietary, $confidential)) and any of ($copy, $export, $send, $personal)
}

rule Insider_Customer_Data {
    meta:
        description = "Customer data exfiltration"
        severity = "critical"
    strings:
        $customer = "customer" ascii nocase
        $client = "client" ascii nocase
        $pii = "PII" ascii
        $export = "export" ascii nocase
        $dump = "dump" ascii nocase
        $all = "all" ascii nocase
        $personal = "personal" ascii nocase
    condition:
        (any of ($customer, $client, $pii)) and any of ($export, $dump) and any of ($all, $personal)
}

rule Insider_Audit_Log_Tampering {
    meta:
        description = "Audit log tampering"
        severity = "critical"
    strings:
        $audit = "audit" ascii nocase
        $log = "log" ascii nocase
        $clear = "clear" ascii nocase
        $delete = "delete" ascii nocase
        $modify = "modify" ascii nocase
        $tamper = "tamper" ascii nocase
        $event = "event" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($audit or $log) and any of ($clear, $delete, $modify, $tamper) and $event
}

