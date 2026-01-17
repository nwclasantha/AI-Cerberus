/*
    Protocol Abuse Detection
    Misuse of legitimate network protocols for malicious purposes
*/

rule Protocol_ICMP_Tunnel {
    meta:
        description = "ICMP tunneling"
        severity = "high"
    strings:
        $icmp = "ICMP" ascii
        $tunnel = "tunnel" ascii nocase
        $ping = "ping" ascii nocase
        $payload = "payload" ascii nocase
        $data = "data" ascii nocase
        $echo = "echo" ascii nocase
    condition:
        $icmp and ($tunnel or ($ping and any of ($payload, $data, $echo)))
}

rule Protocol_DNS_Covert {
    meta:
        description = "DNS covert channel"
        severity = "critical"
    strings:
        $dns = "DNS" ascii
        $covert = "covert" ascii nocase
        $channel = "channel" ascii nocase
        $tunnel = "tunnel" ascii nocase
        $encode = "encode" ascii nocase
        $txt = "TXT" ascii
    condition:
        $dns and (any of ($covert, $channel, $tunnel)) and any of ($encode, $txt)
}

rule Protocol_HTTP_Tunnel {
    meta:
        description = "HTTP tunneling"
        severity = "high"
    strings:
        $http = "HTTP" ascii
        $tunnel = "tunnel" ascii nocase
        $connect = "CONNECT" ascii
        $proxy = "proxy" ascii nocase
        $encapsulate = "encapsulate" ascii nocase
    condition:
        $http and ($tunnel or $connect) and any of ($proxy, $encapsulate)
}

rule Protocol_SSH_Tunnel {
    meta:
        description = "SSH tunneling abuse"
        severity = "medium"
    strings:
        $ssh = "SSH" ascii
        $tunnel = "tunnel" ascii nocase
        $forward = "-L" ascii
        $reverse = "-R" ascii
        $dynamic = "-D" ascii
        $port = "port" ascii nocase
    condition:
        $ssh and ($tunnel or any of ($forward, $reverse, $dynamic)) and $port
}

rule Protocol_SMB_Relay {
    meta:
        description = "SMB relay attack"
        severity = "critical"
    strings:
        $smb = "SMB" ascii
        $relay = "relay" ascii nocase
        $ntlm = "NTLM" ascii
        $hash = "hash" ascii nocase
        $authenticate = "authenticate" ascii nocase
    condition:
        $smb and $relay and any of ($ntlm, $hash, $authenticate)
}

rule Protocol_LDAP_Injection {
    meta:
        description = "LDAP injection attack"
        severity = "critical"
    strings:
        $ldap = "LDAP" ascii
        $inject = "inject" ascii nocase
        $query = "query" ascii nocase
        $filter = "filter" ascii nocase
        $bind = "bind" ascii nocase
        $search = "search" ascii nocase
    condition:
        $ldap and $inject and any of ($query, $filter, $bind, $search)
}

rule Protocol_Kerberos_Attack {
    meta:
        description = "Kerberos protocol attack"
        severity = "critical"
    strings:
        $kerberos = "Kerberos" ascii nocase
        $golden = "golden" ascii nocase
        $silver = "silver" ascii nocase
        $ticket = "ticket" ascii nocase
        $roast = "roast" ascii nocase
        $asrep = "AS-REP" ascii
    condition:
        $kerberos and (any of ($golden, $silver) and $ticket) or ($roast or $asrep)
}

rule Protocol_RDP_Hijack {
    meta:
        description = "RDP session hijacking"
        severity = "critical"
    strings:
        $rdp = "RDP" ascii
        $hijack = "hijack" ascii nocase
        $session = "session" ascii nocase
        $tscon = "tscon" ascii nocase
        $shadow = "shadow" ascii nocase
    condition:
        $rdp and ($hijack or any of ($session, $tscon, $shadow))
}

rule Protocol_WMI_Lateral {
    meta:
        description = "WMI lateral movement"
        severity = "high"
    strings:
        $wmi = "WMI" ascii
        $lateral = "lateral" ascii nocase
        $remote = "remote" ascii nocase
        $process = "Win32_Process" ascii
        $create = "Create" ascii
    condition:
        $wmi and (any of ($lateral, $remote)) and any of ($process, $create)
}

rule Protocol_DCOM_Abuse {
    meta:
        description = "DCOM abuse for lateral movement"
        severity = "high"
    strings:
        $dcom = "DCOM" ascii
        $mmc = "MMC20" ascii
        $shell = "ShellExecute" ascii
        $lateral = "lateral" ascii nocase
        $excel = "Excel.Application" ascii
    condition:
        $dcom and any of ($mmc, $shell, $lateral, $excel)
}

rule Protocol_SNMP_Abuse {
    meta:
        description = "SNMP protocol abuse"
        severity = "high"
    strings:
        $snmp = "SNMP" ascii
        $community = "community" ascii nocase
        $public = "public" ascii
        $private = "private" ascii
        $write = "write" ascii nocase
        $config = "config" ascii nocase
    condition:
        $snmp and ($community or any of ($public, $private)) and any of ($write, $config)
}

rule Protocol_TFTP_Exfil {
    meta:
        description = "TFTP exfiltration"
        severity = "high"
    strings:
        $tftp = "TFTP" ascii
        $transfer = "transfer" ascii nocase
        $get = "get" ascii nocase
        $put = "put" ascii nocase
        $exfil = "exfil" ascii nocase
    condition:
        $tftp and (any of ($transfer, $get, $put)) and $exfil
}

rule Protocol_FTP_Bounce {
    meta:
        description = "FTP bounce attack"
        severity = "high"
    strings:
        $ftp = "FTP" ascii
        $bounce = "bounce" ascii nocase
        $port = "PORT" ascii
        $scan = "scan" ascii nocase
        $proxy = "proxy" ascii nocase
    condition:
        $ftp and ($bounce or $port) and any of ($scan, $proxy)
}

rule Protocol_NFS_Abuse {
    meta:
        description = "NFS protocol abuse"
        severity = "high"
    strings:
        $nfs = "NFS" ascii
        $mount = "mount" ascii nocase
        $export = "export" ascii nocase
        $share = "share" ascii nocase
        $access = "access" ascii nocase
        $root = "root" ascii nocase
    condition:
        $nfs and (any of ($mount, $export, $share)) and any of ($access, $root)
}

rule Protocol_SIP_Abuse {
    meta:
        description = "SIP/VoIP abuse"
        severity = "high"
    strings:
        $sip = "SIP" ascii
        $voip = "VoIP" ascii nocase
        $invite = "INVITE" ascii
        $register = "REGISTER" ascii
        $spoof = "spoof" ascii nocase
        $toll = "toll" ascii nocase
    condition:
        (any of ($sip, $voip)) and (any of ($invite, $register)) and any of ($spoof, $toll)
}

rule Protocol_BGP_Hijack {
    meta:
        description = "BGP route hijacking"
        severity = "critical"
    strings:
        $bgp = "BGP" ascii
        $hijack = "hijack" ascii nocase
        $route = "route" ascii nocase
        $prefix = "prefix" ascii nocase
        $announce = "announce" ascii nocase
    condition:
        $bgp and ($hijack or any of ($route, $prefix, $announce))
}

rule Protocol_ARP_Spoof {
    meta:
        description = "ARP spoofing attack"
        severity = "critical"
    strings:
        $arp = "ARP" ascii
        $spoof = "spoof" ascii nocase
        $poison = "poison" ascii nocase
        $gratuitous = "gratuitous" ascii nocase
        $cache = "cache" ascii nocase
    condition:
        $arp and any of ($spoof, $poison, $gratuitous, $cache)
}

rule Protocol_DHCP_Starvation {
    meta:
        description = "DHCP starvation attack"
        severity = "high"
    strings:
        $dhcp = "DHCP" ascii
        $starv = "starv" ascii nocase
        $exhaust = "exhaust" ascii nocase
        $discover = "DISCOVER" ascii
        $flood = "flood" ascii nocase
    condition:
        $dhcp and any of ($starv, $exhaust, $flood) and $discover
}

rule Protocol_LLMNR_Poison {
    meta:
        description = "LLMNR/NBT-NS poisoning"
        severity = "critical"
    strings:
        $llmnr = "LLMNR" ascii
        $nbtns = "NBT-NS" ascii
        $poison = "poison" ascii nocase
        $spoof = "spoof" ascii nocase
        $response = "response" ascii nocase
    condition:
        (any of ($llmnr, $nbtns)) and any of ($poison, $spoof, $response)
}

rule Protocol_WPAD_Abuse {
    meta:
        description = "WPAD protocol abuse"
        severity = "high"
    strings:
        $wpad = "WPAD" ascii
        $proxy = "proxy" ascii nocase
        $pac = ".pac" ascii nocase
        $auto = "auto" ascii nocase
        $config = "config" ascii nocase
        $intercept = "intercept" ascii nocase
    condition:
        $wpad and ($proxy or $pac) and any of ($auto, $config, $intercept)
}

