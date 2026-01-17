/*
    Remote Access Tools Detection
    Commercial and underground RATs, legitimate RMM abuse
*/

rule RAT_Cobalt_Strike {
    meta:
        description = "Cobalt Strike beacon"
        severity = "critical"
    strings:
        $beacon1 = "beacon" ascii nocase
        $beacon2 = "ReflectiveLoader" ascii
        $cs1 = "sleeptime" ascii
        $cs2 = "jitter" ascii
        $cs3 = "spawnto" ascii
        $cs4 = "watermark" ascii
        $pipe = "\\\\.\\pipe\\" ascii
        $named_pipe = /\\\\\.\\pipe\\msagent_[a-f0-9]{2}/ ascii
    condition:
        uint16(0) == 0x5A4D and (($beacon1 and any of ($cs*)) or $named_pipe)
}

rule RAT_Metasploit_Meterpreter {
    meta:
        description = "Metasploit Meterpreter"
        severity = "critical"
    strings:
        $meterpreter = "meterpreter" ascii nocase
        $msf = "metasploit" ascii nocase
        $shell = "shell" ascii
        $migrate = "migrate" ascii
        $sysinfo = "sysinfo" ascii
        $hashdump = "hashdump" ascii
        $stub = { 4D 5A E8 00 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and (any of ($meterpreter, $msf) or $stub or (3 of ($shell, $migrate, $sysinfo, $hashdump)))
}

rule RAT_NjRAT {
    meta:
        description = "njRAT/Bladabindi"
        severity = "critical"
    strings:
        $njrat = "njRAT" ascii nocase
        $bladabindi = "Bladabindi" ascii nocase
        $ll = "|'|'|" ascii
        $sep = "Y262SUCCES" ascii
        $im = "im523" ascii
        $key = "kl" ascii
        $cam = "CAM" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($njrat, $bladabindi, $ll, $sep, $im))
}

rule RAT_AsyncRAT {
    meta:
        description = "AsyncRAT"
        severity = "critical"
    strings:
        $async = "AsyncRAT" ascii nocase
        $async2 = "AsyncClient" ascii
        $aes = "AES" ascii
        $mutex = "AsyncMutex" ascii
        $install = "InstallFolder" ascii
        $connect = "Connect" ascii
    condition:
        uint16(0) == 0x5A4D and ($async or $async2 or ($aes and $mutex))
}

rule RAT_QuasarRAT {
    meta:
        description = "QuasarRAT"
        severity = "critical"
    strings:
        $quasar = "Quasar" ascii nocase
        $client = "QuasarClient" ascii
        $server = "QuasarServer" ascii
        $settings = "Settings" ascii
        $keylogger = "Keylogger" ascii
        $remote = "RemoteDesktop" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($quasar, $client, $server))
}

rule RAT_DarkComet {
    meta:
        description = "DarkComet RAT"
        severity = "critical"
    strings:
        $dc1 = "DarkComet" ascii nocase
        $dc2 = "DC_" ascii
        $dc3 = "DCNEW" ascii
        $mutex = "DC_MUTEX" ascii
        $fwb = "FWB" ascii
        $persistence = "SoftwareMicrosoft" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($dc*) or $mutex)
}

rule RAT_RemcosRAT {
    meta:
        description = "Remcos RAT"
        severity = "critical"
    strings:
        $remcos = "Remcos" ascii nocase
        $breaking = "Breaking" ascii
        $security = "Security" ascii
        $config = { 00 00 00 00 00 00 01 }  // Config marker
        $keylog = "keylog" ascii nocase
        $screen = "screen" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($remcos or ($breaking and $security))
}

rule RAT_Warzone {
    meta:
        description = "Warzone/AveMaria RAT"
        severity = "critical"
    strings:
        $warzone = "Warzone" ascii nocase
        $avemaria = "AveMaria" ascii nocase
        $ave = "AVE_MARIA" ascii
        $mutex = "Warzone" ascii
        $rdp = "RDP" ascii
        $hrdp = "HRDP" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($warzone, $avemaria, $ave))
}

rule RAT_NanoCore {
    meta:
        description = "NanoCore RAT"
        severity = "critical"
    strings:
        $nano = "NanoCore" ascii nocase
        $client = "NanoClient" ascii
        $guid = "GUID" ascii
        $des = "DES" ascii
        $plugin = "Plugin" ascii
        $surveillance = "Surveillance" ascii
    condition:
        uint16(0) == 0x5A4D and ($nano or $client)
}

rule RAT_PoisonIvy {
    meta:
        description = "Poison Ivy RAT"
        severity = "critical"
    strings:
        $pivy = "Poison Ivy" ascii nocase
        $pi = "PIVY" ascii
        $admin = "admin" ascii
        $stub = "stub" ascii
        $shell = "shell" ascii
        $persist = "Active Setup" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($pivy, $pi) or ($admin and $stub and $shell))
}

rule RAT_Gh0stRAT {
    meta:
        description = "Gh0st RAT"
        severity = "critical"
    strings:
        $gh0st = "Gh0st" ascii nocase
        $marker = { 47 68 30 73 74 }  // "Gh0st"
        $pcshare = "PcShare" ascii
        $screen = "Screen" ascii
        $keylog = "Keylog" ascii
        $filemanager = "FileManager" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($gh0st, $marker, $pcshare))
}

rule RAT_NetWire {
    meta:
        description = "NetWire RAT"
        severity = "critical"
    strings:
        $netwire = "NetWire" ascii nocase
        $hw = "HWID" ascii
        $key = "KeyLogs" ascii
        $host = "Host" ascii
        $port = "Port" ascii
        $mutex = "Mutex" ascii
    condition:
        uint16(0) == 0x5A4D and ($netwire or (3 of ($hw, $key, $host, $port, $mutex)))
}

rule RAT_Orcus {
    meta:
        description = "Orcus RAT"
        severity = "critical"
    strings:
        $orcus = "Orcus" ascii nocase
        $admin = "OrcusAdmin" ascii
        $client = "OrcusClient" ascii
        $plugin = "Plugin" ascii
        $command = "Command" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($orcus, $admin, $client))
}

rule RAT_LimeRAT {
    meta:
        description = "LimeRAT"
        severity = "critical"
    strings:
        $lime = "LimeRAT" ascii nocase
        $limeclient = "LimeClient" ascii
        $aes = "AES" ascii
        $spread = "Spread" ascii
        $miner = "Miner" ascii
        $ransom = "Ransom" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($lime, $limeclient))
}

rule RAT_RevengeRAT {
    meta:
        description = "RevengeRAT"
        severity = "critical"
    strings:
        $revenge = "Revenge" ascii nocase
        $client = "Client" ascii
        $socket = "Socket" ascii
        $keylog = "KeyLog" ascii
        $config = "Config" ascii
    condition:
        uint16(0) == 0x5A4D and ($revenge and any of ($client, $socket, $keylog))
}

rule RAT_BitRAT {
    meta:
        description = "BitRAT"
        severity = "critical"
    strings:
        $bitrat = "BitRAT" ascii nocase
        $bit = "Bit" ascii
        $hvnc = "HVNC" ascii
        $rdp = "RDP" ascii
        $socks5 = "SOCKS5" ascii
        $miner = "Miner" ascii
    condition:
        uint16(0) == 0x5A4D and ($bitrat or ($hvnc and any of ($rdp, $socks5, $miner)))
}

rule RAT_Agent_Tesla {
    meta:
        description = "Agent Tesla"
        severity = "critical"
    strings:
        $tesla = "Agent Tesla" ascii nocase
        $agenttesla = "AgentTesla" ascii
        $keylog = "KeyLog" ascii
        $smtp = "SMTP" ascii
        $ftp = "FTP" ascii
        $telegram = "Telegram" ascii
        $browser = "Browser" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($tesla, $agenttesla) or (3 of ($keylog, $smtp, $ftp, $telegram, $browser)))
}

rule RAT_Formbook_XLoader {
    meta:
        description = "Formbook/XLoader"
        severity = "critical"
    strings:
        $formbook = "Formbook" ascii nocase
        $xloader = "XLoader" ascii nocase
        $grabber = "Grabber" ascii
        $browser = "Browser" ascii
        $keylog = "Keylog" ascii
        $screen = "Screenshot" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($formbook, $xloader) or (3 of ($grabber, $browser, $keylog, $screen)))
}

rule RMM_Abuse_AnyDesk {
    meta:
        description = "AnyDesk abuse indicators"
        severity = "medium"
    strings:
        $anydesk = "AnyDesk" ascii nocase
        $gcapi = "gcapi" ascii
        $silent = "--silent" ascii
        $install = "--install" ascii
        $unattended = "ad.anynet.id" ascii
    condition:
        uint16(0) == 0x5A4D and $anydesk and (any of ($silent, $install, $unattended))
}

rule RMM_Abuse_TeamViewer {
    meta:
        description = "TeamViewer abuse indicators"
        severity = "medium"
    strings:
        $teamviewer = "TeamViewer" ascii nocase
        $tv = "TV" ascii
        $silent = "--silent" ascii
        $no_gui = "--no-gui" ascii
        $api = "api.teamviewer.com" ascii
    condition:
        uint16(0) == 0x5A4D and $teamviewer and (any of ($silent, $no_gui))
}

rule RMM_Abuse_ScreenConnect {
    meta:
        description = "ScreenConnect/ConnectWise abuse"
        severity = "medium"
    strings:
        $screen = "ScreenConnect" ascii nocase
        $connect = "ConnectWise" ascii nocase
        $relay = "relay" ascii nocase
        $silent = "silent" ascii nocase
        $unattended = "unattended" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($screen, $connect)) and (any of ($relay, $silent, $unattended))
}

rule RMM_Abuse_Atera {
    meta:
        description = "Atera RMM abuse"
        severity = "medium"
    strings:
        $atera = "Atera" ascii nocase
        $agent = "AteraAgent" ascii
        $silent = "silent" ascii nocase
        $integratorlogin = "IntegratorLogin" ascii
    condition:
        uint16(0) == 0x5A4D and $atera and (any of ($agent, $silent, $integratorlogin))
}

