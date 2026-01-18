/*
    DDoS Tools Detection
    Denial of Service tools and botnets
*/

rule DDoS_Generic_Flood {
    meta:
        description = "Generic flood attack tool"
        severity = "high"
    strings:
        $flood1 = "flood" ascii nocase
        $flood2 = "ddos" ascii nocase
        $syn = "SYN" ascii
        $udp = "UDP" ascii
        $icmp = "ICMP" ascii
        $http = "HTTP" ascii
        $socket = "socket" ascii
        $raw = "SOCK_RAW" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($flood*)) and (any of ($syn, $udp, $icmp, $http)) and ($socket or $raw)
}

rule DDoS_LOIC {
    meta:
        description = "Low Orbit Ion Cannon"
        severity = "high"
    strings:
        $loic = "LOIC" ascii nocase
        $ion = "Ion Cannon" ascii nocase
        $imma = "IMMA CHARGIN" ascii
        $target = "target" ascii nocase
        $attack = "attack" ascii nocase
        $flood = "flood" ascii nocase
    condition:
        (any of ($loic, $ion, $imma)) or (($target and $attack) and $flood)
}

rule DDoS_HOIC {
    meta:
        description = "High Orbit Ion Cannon"
        severity = "high"
    strings:
        $hoic = "HOIC" ascii nocase
        $high = "High Orbit" ascii nocase
        $booster = "booster" ascii nocase
        $power = "power" ascii nocase
        // UNUSED: $script = ".hoic" ascii nocase
    condition:
        (any of ($hoic, $high)) or ($booster and $power)
}

rule DDoS_Slowloris {
    meta:
        description = "Slowloris DoS tool"
        severity = "high"
    strings:
        $slowloris = "Slowloris" ascii nocase
        $slow = "slow" ascii nocase
        $http = "HTTP" ascii
        $header = "header" ascii nocase
        $keep = "keep-alive" ascii nocase
        $partial = "partial" ascii nocase
    condition:
        $slowloris or (($slow and $http) and any of ($header, $keep, $partial))
}

rule DDoS_Hping {
    meta:
        description = "Hping network tool"
        severity = "medium"
    strings:
        $hping = "hping" ascii nocase
        $flood = "--flood" ascii
        $syn = "-S" ascii
        $rand = "--rand-source" ascii
        $spoof = "spoof" ascii nocase
    condition:
        $hping and (any of ($flood, $syn, $rand, $spoof))
}

rule DDoS_GoldenEye {
    meta:
        description = "GoldenEye HTTP DoS"
        severity = "high"
    strings:
        $goldeneye = "GoldenEye" ascii nocase
        $golden = "Golden" ascii nocase
        $http = "HTTP" ascii
        $siege = "siege" ascii nocase
        $useragent = "User-Agent" ascii
        $workers = "workers" ascii nocase
    condition:
        $goldeneye or ($golden and $http and any of ($siege, $useragent, $workers))
}

rule DDoS_Xerxes {
    meta:
        description = "Xerxes DoS tool"
        severity = "high"
    strings:
        $xerxes = "Xerxes" ascii nocase
        $th3 = "th3" ascii nocase
        $flood = "flood" ascii nocase
        // UNUSED: $target = "target" ascii nocase
        // UNUSED: $port = "port" ascii nocase
    condition:
        $xerxes or ($th3 and $flood)
}

rule DDoS_Hulk {
    meta:
        description = "HULK DoS tool"
        severity = "high"
    strings:
        $hulk = "HULK" ascii nocase
        $http = "HTTP" ascii
        $unbearable = "Unbearable" ascii
        $load = "Load" ascii nocase
        $king = "King" ascii nocase
        // UNUSED: $random = "random" ascii nocase
    condition:
        $hulk or ($http and ($unbearable or ($load and $king)))
}

rule DDoS_Torshammer {
    meta:
        description = "Tor's Hammer DoS"
        severity = "high"
    strings:
        $torshammer = "Tor's Hammer" ascii nocase
        $tors = "Tors" ascii nocase
        $hammer = "hammer" ascii nocase
        $slow = "slow" ascii nocase
        $post = "POST" ascii
        // UNUSED: $tor = "Tor" ascii
    condition:
        $torshammer or (($hammer or $tors) and $slow and $post)
}

rule DDoS_R_U_Dead_Yet {
    meta:
        description = "R-U-Dead-Yet (RUDY)"
        severity = "high"
    strings:
        $rudy = "RUDY" ascii nocase
        $rudead = "R-U-Dead-Yet" ascii nocase
        $slow = "slow" ascii nocase
        $post = "POST" ascii
        $body = "body" ascii nocase
        $content = "Content-Length" ascii
    condition:
        (any of ($rudy, $rudead)) or ($slow and $post and any of ($body, $content))
}

rule DDoS_PyLoris {
    meta:
        description = "PyLoris DoS tool"
        severity = "high"
    strings:
        $pyloris = "PyLoris" ascii nocase
        $python = "python" ascii nocase
        $loris = "loris" ascii nocase
        $slow = "slow" ascii nocase
        $http = "HTTP" ascii
    condition:
        $pyloris or ($python and $loris and any of ($slow, $http))
}

rule DDoS_THC_SSL_DoS {
    meta:
        description = "THC-SSL-DoS tool"
        severity = "high"
    strings:
        $thc = "THC" ascii
        $ssl = "SSL" ascii
        $dos = "DoS" ascii nocase
        $renegotiation = "renegotiation" ascii nocase
        $handshake = "handshake" ascii nocase
    condition:
        $thc and $ssl and (any of ($dos, $renegotiation, $handshake))
}

rule DDoS_SYN_Flood {
    meta:
        description = "SYN flood tool"
        severity = "high"
    strings:
        $syn = "SYN" ascii
        $flood = "flood" ascii nocase
        $raw = "SOCK_RAW" ascii
        $hdrincl = "IP_HDRINCL" ascii
        $spoof = "spoof" ascii nocase
        $tcp = "IPPROTO_TCP" ascii
    condition:
        uint16(0) == 0x5A4D and $syn and $flood and (any of ($raw, $hdrincl, $spoof, $tcp))
}

rule DDoS_UDP_Flood {
    meta:
        description = "UDP flood tool"
        severity = "high"
    strings:
        $udp = "UDP" ascii
        $flood = "flood" ascii nocase
        $sock = "SOCK_DGRAM" ascii
        $send = "sendto" ascii
        $random = "random" ascii nocase
        $amplify = "amplify" ascii nocase
    condition:
        uint16(0) == 0x5A4D and $udp and $flood and (any of ($sock, $send, $random, $amplify))
}

rule DDoS_DNS_Amplification {
    meta:
        description = "DNS amplification attack"
        severity = "critical"
    strings:
        $dns = "DNS" ascii
        $amplify = "amplify" ascii nocase
        $amplification = "amplification" ascii nocase
        $any = "ANY" ascii
        $spoof = "spoof" ascii nocase
        $reflect = "reflect" ascii nocase
        // UNUSED: $port = "53" ascii
    condition:
        $dns and (any of ($amplify, $amplification)) and (any of ($any, $spoof, $reflect))
}

rule DDoS_NTP_Amplification {
    meta:
        description = "NTP amplification attack"
        severity = "critical"
    strings:
        $ntp = "NTP" ascii
        $amplify = "amplify" ascii nocase
        $monlist = "monlist" ascii
        $mode7 = "mode 7" ascii nocase
        $reflect = "reflect" ascii nocase
        // UNUSED: $port = "123" ascii
    condition:
        $ntp and (any of ($amplify, $monlist, $mode7, $reflect))
}

rule DDoS_Memcached_Amplification {
    meta:
        description = "Memcached amplification attack"
        severity = "critical"
    strings:
        $memcached = "memcached" ascii nocase
        $amplify = "amplify" ascii nocase
        $stats = "stats" ascii
        $get = "get " ascii
        $set = "set " ascii
        $port = "11211" ascii
    condition:
        $memcached and (any of ($amplify, $stats, $get, $set, $port))
}

rule DDoS_SSDP_Amplification {
    meta:
        description = "SSDP amplification attack"
        severity = "critical"
    strings:
        $ssdp = "SSDP" ascii
        $upnp = "UPnP" ascii nocase
        $msearch = "M-SEARCH" ascii
        $amplify = "amplify" ascii nocase
        $reflect = "reflect" ascii nocase
        // UNUSED: $port = "1900" ascii
    condition:
        ($ssdp or $upnp) and ($msearch or any of ($amplify, $reflect))
}

rule DDoS_Botnet_Command {
    meta:
        description = "DDoS botnet command"
        severity = "critical"
    strings:
        $ddos = "ddos" ascii nocase
        $attack = "attack" ascii nocase
        $flood = "flood" ascii nocase
        $target = "target" ascii nocase
        $duration = "duration" ascii nocase
        $method = "method" ascii nocase
        $start = "start" ascii nocase
        $stop = "stop" ascii nocase
    condition:
        (any of ($ddos, $attack, $flood)) and $target and (any of ($duration, $method, $start, $stop))
}

rule DDoS_Stresser_Booter {
    meta:
        description = "Stresser/Booter service"
        severity = "critical"
    strings:
        $stresser = "stresser" ascii nocase
        $booter = "booter" ascii nocase
        $stress = "stress" ascii nocase
        $boot = "boot" ascii nocase
        $api = "api" ascii nocase
        $layer = "layer" ascii nocase
        $l4 = "L4" ascii
        $l7 = "L7" ascii
    condition:
        (any of ($stresser, $booter)) or (any of ($stress, $boot) and $api and any of ($layer, $l4, $l7))
}

