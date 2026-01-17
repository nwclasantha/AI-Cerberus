/*
    Tor and Dark Web Communication Detection
    Onion routing, hidden services, and anonymous networks
*/

rule Tor_Client_Embedded {
    meta:
        description = "Embedded Tor client"
        severity = "high"
    strings:
        $tor = "Tor" ascii
        $onion = ".onion" ascii
        $socks = "SOCKS" ascii
        $circuit = "circuit" ascii nocase
        $relay = "relay" ascii nocase
        $exit = "exit node" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($tor or $onion) and any of ($socks, $circuit, $relay, $exit)
}

rule Tor_Browser_Artifacts {
    meta:
        description = "Tor Browser artifacts"
        severity = "medium"
    strings:
        $torbrowser = "Tor Browser" ascii nocase
        $torrc = "torrc" ascii
        $data = "Data/Tor" ascii
        $state = "state" ascii
        $cached = "cached-" ascii
    condition:
        $torbrowser or ($torrc and any of ($data, $state, $cached))
}

rule Tor_Hidden_Service {
    meta:
        description = "Tor hidden service configuration"
        severity = "high"
    strings:
        $hidden = "HiddenServiceDir" ascii
        $port = "HiddenServicePort" ascii
        $hostname = "hostname" ascii
        $private = "private_key" ascii
        $onion = ".onion" ascii
    condition:
        (any of ($hidden, $port)) or (($hostname or $private) and $onion)
}

rule Tor_Library_Usage {
    meta:
        description = "Tor library integration"
        severity = "high"
    strings:
        $libtor = "libtor" ascii
        $stem = "stem.control" ascii
        $txtorcon = "txtorcon" ascii
        $torpy = "torpy" ascii
        $controller = "TorController" ascii
    condition:
        any of them
}

rule Onion_Address_Pattern {
    meta:
        description = "Onion address pattern"
        severity = "high"
    strings:
        $onion_v2 = /[a-z2-7]{16}\.onion/ ascii
        $onion_v3 = /[a-z2-7]{56}\.onion/ ascii
        $http_onion = "http://" ascii
        $https_onion = "https://" ascii
    condition:
        (any of ($onion_v2, $onion_v3)) and any of ($http_onion, $https_onion)
}

rule I2P_Network {
    meta:
        description = "I2P anonymous network"
        severity = "high"
    strings:
        $i2p = "I2P" ascii
        $i2cp = "I2CP" ascii
        $eepsite = ".i2p" ascii
        $router = "router.info" ascii
        $netdb = "netDb" ascii
        $garlic = "garlic" ascii nocase
    condition:
        ($i2p or $i2cp) and any of ($eepsite, $router, $netdb, $garlic)
}

rule Freenet_Network {
    meta:
        description = "Freenet anonymous network"
        severity = "high"
    strings:
        $freenet = "Freenet" ascii nocase
        $fcp = "FCP" ascii
        $freenet_key = "CHK@" ascii
        $ssk = "SSK@" ascii
        $usk = "USK@" ascii
    condition:
        $freenet or ($fcp and any of ($freenet_key, $ssk, $usk))
}

rule Tor_Proxy_Config {
    meta:
        description = "Tor SOCKS proxy configuration"
        severity = "medium"
    strings:
        $socks = "SOCKS" ascii nocase
        $proxy = "proxy" ascii nocase
        $port1 = "9050" ascii
        $port2 = "9150" ascii
        $localhost = "127.0.0.1" ascii
        $tor = "tor" ascii nocase
    condition:
        $socks and $proxy and (any of ($port1, $port2) or ($localhost and $tor))
}

rule Tor_Control_Protocol {
    meta:
        description = "Tor control protocol usage"
        severity = "high"
    strings:
        $control = "AUTHENTICATE" ascii
        $getinfo = "GETINFO" ascii
        $signal = "SIGNAL" ascii
        $newnym = "NEWNYM" ascii
        $port = "9051" ascii
        $cookie = "control_auth_cookie" ascii
    condition:
        (2 of ($control, $getinfo, $signal, $newnym)) or ($port and $cookie)
}

rule Onion_Routing_Malware {
    meta:
        description = "Malware using onion routing"
        severity = "critical"
    strings:
        $onion = ".onion" ascii
        $c2 = "C2" ascii
        $callback = "callback" ascii nocase
        $beacon = "beacon" ascii nocase
        $connect = "connect" ascii nocase
        $tor = "tor" ascii nocase
    condition:
        uint16(0) == 0x5A4D and $onion and any of ($c2, $callback, $beacon) and any of ($connect, $tor)
}

rule DarkWeb_Marketplace {
    meta:
        description = "Dark web marketplace indicators"
        severity = "high"
    strings:
        $market = "market" ascii nocase
        $vendor = "vendor" ascii nocase
        $escrow = "escrow" ascii nocase
        $pgp = "PGP" ascii
        $btc = "BTC" ascii
        $xmr = "XMR" ascii
        $onion = ".onion" ascii
    condition:
        $onion and (2 of ($market, $vendor, $escrow, $pgp, $btc, $xmr))
}

rule Tor_Bridge_Usage {
    meta:
        description = "Tor bridge/pluggable transport"
        severity = "medium"
    strings:
        $bridge = "Bridge" ascii
        $obfs4 = "obfs4" ascii
        $meek = "meek" ascii
        $snowflake = "snowflake" ascii
        $transport = "pluggable transport" ascii nocase
        $circumvent = "circumvent" ascii nocase
    condition:
        $bridge and any of ($obfs4, $meek, $snowflake, $transport, $circumvent)
}

rule Tor_Exit_Node_Abuse {
    meta:
        description = "Tor exit node abuse indicators"
        severity = "high"
    strings:
        $exit = "exit" ascii nocase
        $node = "node" ascii nocase
        $tor = "tor" ascii nocase
        $attack = "attack" ascii nocase
        $inject = "inject" ascii nocase
        $mitm = "MITM" ascii
    condition:
        ($exit and $node and $tor) and any of ($attack, $inject, $mitm)
}

rule Anonymous_VPN_Protocol {
    meta:
        description = "Anonymous VPN protocol usage"
        severity = "medium"
    strings:
        $vpn = "VPN" ascii
        $wireguard = "WireGuard" ascii nocase
        $openvpn = "OpenVPN" ascii nocase
        $anonymous = "anonymous" ascii nocase
        $no_log = "no-log" ascii nocase
        $privacy = "privacy" ascii nocase
    condition:
        $vpn and (any of ($wireguard, $openvpn)) and any of ($anonymous, $no_log, $privacy)
}

rule Tor_Ransomware_Payment {
    meta:
        description = "Ransomware Tor payment portal"
        severity = "critical"
    strings:
        $ransom = "ransom" ascii nocase
        $decrypt = "decrypt" ascii nocase
        $pay = "pay" ascii nocase
        $bitcoin = "bitcoin" ascii nocase
        $onion = ".onion" ascii
        $key = "key" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($ransom or $decrypt) and $onion and any of ($pay, $bitcoin, $key)
}

rule Tor_C2_Infrastructure {
    meta:
        description = "Tor-based C2 infrastructure"
        severity = "critical"
    strings:
        $onion = ".onion" ascii
        $c2_1 = "command" ascii nocase
        $c2_2 = "control" ascii nocase
        $c2_3 = "beacon" ascii nocase
        $c2_4 = "heartbeat" ascii nocase
        $c2_5 = "checkin" ascii nocase
    condition:
        uint16(0) == 0x5A4D and $onion and (2 of ($c2_*))
}

rule Tor_Data_Exfiltration {
    meta:
        description = "Data exfiltration via Tor"
        severity = "critical"
    strings:
        $tor = "tor" ascii nocase
        $onion = ".onion" ascii
        $exfil = "exfil" ascii nocase
        $upload = "upload" ascii nocase
        $send = "send" ascii nocase
        $data = "data" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($tor or $onion) and any of ($exfil, $upload, $send) and $data
}

rule Darknet_Forum {
    meta:
        description = "Darknet forum indicators"
        severity = "medium"
    strings:
        $forum = "forum" ascii nocase
        $board = "board" ascii nocase
        $hack = "hack" ascii nocase
        $carding = "carding" ascii nocase
        $onion = ".onion" ascii
        $register = "register" ascii nocase
    condition:
        $onion and (any of ($forum, $board)) and any of ($hack, $carding, $register)
}

rule Tor_Malware_Dropper {
    meta:
        description = "Malware dropper using Tor"
        severity = "critical"
    strings:
        $tor = "tor" ascii nocase
        $onion = ".onion" ascii
        $drop = "drop" ascii nocase
        $download = "download" ascii nocase
        $payload = "payload" ascii nocase
        $stage = "stage" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($tor or $onion) and any of ($drop, $download, $payload, $stage)
}

