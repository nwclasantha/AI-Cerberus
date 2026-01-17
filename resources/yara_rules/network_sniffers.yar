/*
    Network Sniffer and Packet Capture Detection
    Traffic interception and network monitoring tools
*/

rule Sniffer_Wireshark {
    meta:
        description = "Wireshark packet capture"
        severity = "medium"
    strings:
        $s1 = "Wireshark" ascii nocase
        $s2 = "tshark" ascii nocase
        $s3 = "wireshark.exe" ascii nocase
        $pcap = ".pcap" ascii nocase
        $capture = "capture" ascii nocase
    condition:
        (any of ($s*)) and any of ($pcap, $capture)
}

rule Sniffer_Tcpdump {
    meta:
        description = "Tcpdump packet capture"
        severity = "medium"
    strings:
        $s1 = "tcpdump" ascii nocase
        $s2 = "libpcap" ascii nocase
        $interface = "-i" ascii
        $write = "-w" ascii
        $filter = "filter" ascii nocase
    condition:
        (any of ($s*)) and any of ($interface, $write, $filter)
}

rule Sniffer_Winpcap {
    meta:
        description = "WinPcap/Npcap usage"
        severity = "medium"
    strings:
        $winpcap = "WinPcap" ascii nocase
        $npcap = "Npcap" ascii nocase
        $wpcap = "wpcap.dll" ascii nocase
        $packet = "packet.dll" ascii nocase
        $api1 = "pcap_open_live" ascii
        $api2 = "pcap_loop" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($winpcap, $npcap, $wpcap, $packet)) and any of ($api1, $api2)
}

rule Sniffer_Raw_Socket {
    meta:
        description = "Raw socket sniffer"
        severity = "high"
    strings:
        $raw = "SOCK_RAW" ascii
        $promiscuous = "promiscuous" ascii nocase
        $sio = "SIO_RCVALL" ascii
        $ipproto = "IPPROTO_IP" ascii
        $recvfrom = "recvfrom" ascii
    condition:
        uint16(0) == 0x5A4D and ($raw or $promiscuous or $sio) and any of ($ipproto, $recvfrom)
}

rule Sniffer_Ettercap {
    meta:
        description = "Ettercap network sniffer"
        severity = "high"
    strings:
        $s1 = "ettercap" ascii nocase
        $s2 = "Ettercap" ascii
        $arp = "ARP" ascii
        $poison = "poison" ascii nocase
        $mitm = "MITM" ascii
    condition:
        (any of ($s*)) and any of ($arp, $poison, $mitm)
}

rule Sniffer_Bettercap {
    meta:
        description = "Bettercap network tool"
        severity = "high"
    strings:
        $s1 = "bettercap" ascii nocase
        $go = "Go build" ascii
        $spoof = "spoof" ascii nocase
        $sniff = "sniff" ascii nocase
        $caplet = "caplet" ascii nocase
    condition:
        $s1 or ($go and any of ($spoof, $sniff, $caplet))
}

rule Sniffer_Cain_Abel {
    meta:
        description = "Cain and Abel sniffer"
        severity = "high"
    strings:
        $s1 = "Cain" ascii nocase
        $s2 = "Abel" ascii nocase
        $password = "password" ascii nocase
        $arp = "ARP" ascii
        $recovery = "recovery" ascii nocase
    condition:
        (all of ($s*)) or (($s1 or $s2) and any of ($password, $arp, $recovery))
}

rule Sniffer_NetworkMiner {
    meta:
        description = "NetworkMiner analysis tool"
        severity = "medium"
    strings:
        $s1 = "NetworkMiner" ascii nocase
        $forensic = "forensic" ascii nocase
        $pcap = ".pcap" ascii nocase
        $extract = "extract" ascii nocase
        $carve = "carve" ascii nocase
    condition:
        $s1 or ($forensic and $pcap and any of ($extract, $carve))
}

rule Sniffer_ARP_Spoof {
    meta:
        description = "ARP spoofing tool"
        severity = "critical"
    strings:
        $arp = "ARP" ascii
        $spoof = "spoof" ascii nocase
        $poison = "poison" ascii nocase
        $gratuitous = "gratuitous" ascii nocase
        $reply = "reply" ascii nocase
        $mitm = "man-in-the-middle" ascii nocase
    condition:
        $arp and (any of ($spoof, $poison, $gratuitous)) and any of ($reply, $mitm)
}

rule Sniffer_DNS_Spoof {
    meta:
        description = "DNS spoofing tool"
        severity = "critical"
    strings:
        $dns = "DNS" ascii
        $spoof = "spoof" ascii nocase
        $poison = "poison" ascii nocase
        $redirect = "redirect" ascii nocase
        $fake = "fake" ascii nocase
        $response = "response" ascii nocase
    condition:
        $dns and (any of ($spoof, $poison)) and any of ($redirect, $fake, $response)
}

rule Sniffer_SSL_Strip {
    meta:
        description = "SSL stripping tool"
        severity = "critical"
    strings:
        $ssl = "SSL" ascii
        $strip = "strip" ascii nocase
        $https = "HTTPS" ascii
        $http = "HTTP" ascii
        $downgrade = "downgrade" ascii nocase
        $mitm = "MITM" ascii
    condition:
        (($ssl and $strip) or ($https and $http and $downgrade)) and $mitm
}

rule Sniffer_Credential_Capture {
    meta:
        description = "Credential capturing sniffer"
        severity = "critical"
    strings:
        $sniff = "sniff" ascii nocase
        $capture = "capture" ascii nocase
        $password = "password" ascii nocase
        $credential = "credential" ascii nocase
        $login = "login" ascii nocase
        $auth = "auth" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($sniff, $capture)) and (any of ($password, $credential)) and any of ($login, $auth)
}

rule Sniffer_Responder {
    meta:
        description = "Responder LLMNR/NBT-NS poisoner"
        severity = "critical"
    strings:
        $s1 = "Responder" ascii nocase
        $llmnr = "LLMNR" ascii
        $nbt = "NBT-NS" ascii
        $mdns = "mDNS" ascii
        $poison = "poison" ascii nocase
        $hash = "hash" ascii nocase
    condition:
        $s1 or ((any of ($llmnr, $nbt, $mdns)) and any of ($poison, $hash))
}

rule Sniffer_PCAP_Library {
    meta:
        description = "PCAP library usage"
        severity = "low"
    strings:
        $pcap1 = "pcap_" ascii
        $pcap2 = "libpcap" ascii
        $open = "pcap_open" ascii
        $filter = "pcap_compile" ascii
        $loop = "pcap_loop" ascii
        $dump = "pcap_dump" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($pcap1, $pcap2)) and (2 of ($open, $filter, $loop, $dump))
}

rule Sniffer_Dsniff {
    meta:
        description = "Dsniff suite tools"
        severity = "high"
    strings:
        $dsniff = "dsniff" ascii nocase
        $urlsnarf = "urlsnarf" ascii nocase
        $filesnarf = "filesnarf" ascii nocase
        $mailsnarf = "mailsnarf" ascii nocase
        $arpspoof = "arpspoof" ascii nocase
    condition:
        any of them
}

rule Sniffer_HTTP_Intercept {
    meta:
        description = "HTTP traffic interception"
        severity = "high"
    strings:
        $http = "HTTP" ascii
        $intercept = "intercept" ascii nocase
        $proxy = "proxy" ascii nocase
        $mitm = "MITM" ascii
        $modify = "modify" ascii nocase
        $inject = "inject" ascii nocase
    condition:
        $http and (any of ($intercept, $proxy, $mitm)) and any of ($modify, $inject)
}

rule Sniffer_Packet_Injection {
    meta:
        description = "Packet injection capability"
        severity = "high"
    strings:
        $inject = "inject" ascii nocase
        $packet = "packet" ascii nocase
        $raw = "raw socket" ascii nocase
        $craft = "craft" ascii nocase
        $forge = "forge" ascii nocase
        $scapy = "scapy" ascii nocase
    condition:
        ($inject and $packet) and any of ($raw, $craft, $forge, $scapy)
}

rule Sniffer_WiFi_Monitor {
    meta:
        description = "WiFi monitor mode sniffer"
        severity = "high"
    strings:
        $wifi = "WiFi" ascii nocase
        $monitor = "monitor" ascii nocase
        $mode = "mode" ascii nocase
        $airmon = "airmon" ascii nocase
        $channel = "channel" ascii nocase
        $80211 = "802.11" ascii
    condition:
        ($wifi and $monitor and $mode) or ($airmon and any of ($channel, $80211))
}

rule Sniffer_Protocol_Analyzer {
    meta:
        description = "Protocol analyzer"
        severity = "medium"
    strings:
        $protocol = "protocol" ascii nocase
        $analyzer = "analyzer" ascii nocase
        $dissect = "dissect" ascii nocase
        $decode = "decode" ascii nocase
        $layer = "layer" ascii nocase
    condition:
        ($protocol and $analyzer) and any of ($dissect, $decode, $layer)
}

rule Sniffer_MITMf {
    meta:
        description = "MITMf framework"
        severity = "critical"
    strings:
        $mitmf = "MITMf" ascii nocase
        $framework = "framework" ascii nocase
        $inject = "inject" ascii nocase
        $spoof = "spoof" ascii nocase
        $plugin = "plugin" ascii nocase
    condition:
        $mitmf or ($framework and any of ($inject, $spoof) and $plugin)
}

