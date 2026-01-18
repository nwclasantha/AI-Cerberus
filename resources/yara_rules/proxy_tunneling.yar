/*
    Proxy and Tunneling Tools Detection
    VPN, proxy, and network tunneling tools
*/

rule Proxy_Chisel {
    meta:
        description = "Chisel tunneling tool"
        severity = "high"
    strings:
        $s1 = "chisel" ascii nocase
        $s2 = "jpillora" ascii
        $go = "Go build" ascii
        $server = "server" ascii nocase
        $client = "client" ascii nocase
        $socks = "socks" ascii nocase
    condition:
        (any of ($s*)) or ($go and $server and $client and $socks)
}

rule Proxy_Ngrok {
    meta:
        description = "Ngrok tunneling service"
        severity = "medium"
    strings:
        $s1 = "ngrok" ascii nocase
        $s2 = "ngrok.io" ascii
        $s3 = "ngrok.com" ascii
        $tunnel = "tunnel" ascii nocase
        $http = "http" ascii nocase
        $tcp = "tcp" ascii nocase
    condition:
        (any of ($s*)) or ($tunnel and any of ($http, $tcp))
}

rule Proxy_Plink {
    meta:
        description = "Plink SSH tunneling"
        severity = "high"
    strings:
        $s1 = "plink" ascii nocase
        $s2 = "plink.exe" ascii nocase
        $putty = "PuTTY" ascii
        $ssh = "SSH" ascii
        $forward = "-L" ascii
        $remote = "-R" ascii
        $dynamic = "-D" ascii
    condition:
        (any of ($s*) and $putty) or ($ssh and any of ($forward, $remote, $dynamic))
}

rule Proxy_Proxychains {
    meta:
        description = "Proxychains tool"
        severity = "medium"
    strings:
        $s1 = "proxychains" ascii nocase
        $s2 = "proxychains4" ascii nocase
        $conf = "proxychains.conf" ascii
        $socks4 = "socks4" ascii nocase
        $socks5 = "socks5" ascii nocase
    condition:
        (any of ($s*)) or ($conf and any of ($socks4, $socks5))
}

rule Proxy_Socat {
    meta:
        description = "Socat multipurpose relay"
        severity = "medium"
    strings:
        $s1 = "socat" ascii nocase
        $tcp = "TCP:" ascii
        $udp = "UDP:" ascii
        $exec = "EXEC:" ascii
        $fork = "fork" ascii nocase
        $listen = "LISTEN" ascii
    condition:
        $s1 and (any of ($tcp, $udp, $exec) or ($fork and $listen))
}

rule Proxy_SSHuttle {
    meta:
        description = "SSHuttle VPN over SSH"
        severity = "medium"
    strings:
        $s1 = "sshuttle" ascii nocase
        $s2 = "poor man's VPN" ascii nocase
        $python = "python" ascii nocase
        $ssh = "ssh" ascii nocase
        $route = "route" ascii nocase
    condition:
        (any of ($s*)) or ($python and $ssh and $route)
}

rule Proxy_Stunnel {
    meta:
        description = "Stunnel SSL wrapper"
        severity = "medium"
    strings:
        $s1 = "stunnel" ascii nocase
        $ssl = "SSL" ascii
        $tls = "TLS" ascii
        $accept = "accept" ascii nocase
        $connect = "connect" ascii nocase
        $client = "client" ascii nocase
    condition:
        $s1 and (any of ($ssl, $tls)) and any of ($accept, $connect, $client)
}

rule Proxy_Frp {
    meta:
        description = "FRP fast reverse proxy"
        severity = "high"
    strings:
        $s1 = "frp" ascii nocase
        $s2 = "frpc" ascii nocase
        $s3 = "frps" ascii nocase
        $go = "Go build" ascii
        $reverse = "reverse" ascii nocase
        $proxy = "proxy" ascii nocase
    condition:
        (any of ($s*)) or ($go and $reverse and $proxy)
}

rule Proxy_Revsocks {
    meta:
        description = "Revsocks reverse tunnel"
        severity = "high"
    strings:
        $s1 = "revsocks" ascii nocase
        $s2 = "reverse" ascii nocase
        $socks = "socks" ascii nocase
        $tunnel = "tunnel" ascii nocase
        $connect = "connect" ascii nocase
    condition:
        $s1 or ($s2 and $socks and any of ($tunnel, $connect))
}

rule Proxy_Shadowsocks {
    meta:
        description = "Shadowsocks proxy"
        severity = "medium"
    strings:
        $s1 = "shadowsocks" ascii nocase
        $s2 = "ss-local" ascii nocase
        $s3 = "ss-server" ascii nocase
        $socks5 = "socks5" ascii nocase
        $cipher = "cipher" ascii nocase
        $aes = "aes-256-gcm" ascii nocase
    condition:
        (any of ($s*)) or ($socks5 and $cipher and $aes)
}

rule Proxy_V2Ray {
    meta:
        description = "V2Ray proxy platform"
        severity = "medium"
    strings:
        $s1 = "v2ray" ascii nocase
        $s2 = "vmess" ascii nocase
        $s3 = "vless" ascii nocase
        $config = "config.json" ascii
        $inbound = "inbounds" ascii
        $outbound = "outbounds" ascii
    condition:
        (any of ($s*)) or ($config and any of ($inbound, $outbound))
}

rule Proxy_GoProxy {
    meta:
        description = "GoProxy tool"
        severity = "high"
    strings:
        $s1 = "goproxy" ascii nocase
        $go = "Go build" ascii
        $http = "http proxy" ascii nocase
        $socks = "socks" ascii nocase
        $tcp = "tcp" ascii nocase
    condition:
        $s1 or ($go and any of ($http, $socks, $tcp))
}

rule Proxy_Rpivot {
    meta:
        description = "Rpivot reverse SOCKS proxy"
        severity = "high"
    strings:
        $s1 = "rpivot" ascii nocase
        $s2 = "reverse" ascii nocase
        $socks = "socks" ascii nocase
        $python = "python" ascii nocase
        $pivot = "pivot" ascii nocase
    condition:
        $s1 or ($s2 and $socks and any of ($python, $pivot))
}

rule Proxy_DNScat_Tunnel {
    meta:
        description = "DNS-based tunneling proxy"
        severity = "critical"
    strings:
        $dns = "dns" ascii nocase
        $tunnel = "tunnel" ascii nocase
        $proxy = "proxy" ascii nocase
        $socks = "socks" ascii nocase
        $encapsulate = "encapsulate" ascii nocase
    condition:
        $dns and $tunnel and any of ($proxy, $socks, $encapsulate)
}

rule Proxy_ICMP_Tunnel {
    meta:
        description = "ICMP tunneling tool"
        severity = "high"
    strings:
        $icmp = "ICMP" ascii
        $tunnel = "tunnel" ascii nocase
        $ping = "ping" ascii nocase
        $ptunnel = "ptunnel" ascii nocase
        $payload = "payload" ascii nocase
    condition:
        $icmp and ($tunnel or $ptunnel) and any of ($ping, $payload)
}

rule Proxy_HTTP_Tunnel {
    meta:
        description = "HTTP tunneling tool"
        severity = "medium"
    strings:
        $http = "HTTP" ascii
        $tunnel = "tunnel" ascii nocase
        $proxy = "CONNECT" ascii
        $encapsulate = "encapsulate" ascii nocase
        $wrap = "wrap" ascii nocase
    condition:
        $http and $tunnel and any of ($proxy, $encapsulate, $wrap)
}

rule Proxy_LocalTunnel {
    meta:
        description = "Localtunnel exposure tool"
        severity = "medium"
    strings:
        $s1 = "localtunnel" ascii nocase
        // UNUSED: $s2 = "lt" ascii nocase
        $expose = "expose" ascii nocase
        $localhost = "localhost" ascii nocase
        $subdomain = "subdomain" ascii nocase
    condition:
        $s1 or ($expose and $localhost and $subdomain)
}

rule Proxy_Bore {
    meta:
        description = "Bore TCP tunnel"
        severity = "medium"
    strings:
        $s1 = "bore" ascii nocase
        $tcp = "TCP" ascii
        $tunnel = "tunnel" ascii nocase
        $expose = "expose" ascii nocase
        $local = "local" ascii nocase
    condition:
        $s1 and $tcp and any of ($tunnel, $expose, $local)
}

rule Proxy_Rathole {
    meta:
        description = "Rathole tunnel tool"
        severity = "high"
    strings:
        $s1 = "rathole" ascii nocase
        $rust = "Rust" ascii
        $tunnel = "tunnel" ascii nocase
        $server = "server" ascii nocase
        $client = "client" ascii nocase
    condition:
        $s1 or ($rust and $tunnel and any of ($server, $client))
}

rule Proxy_Generic_SOCKS {
    meta:
        description = "Generic SOCKS proxy usage"
        severity = "medium"
    strings:
        $socks4 = "SOCKS4" ascii nocase
        $socks5 = "SOCKS5" ascii nocase
        $proxy = "proxy" ascii nocase
        $connect = "connect" ascii nocase
        $auth = "authentication" ascii nocase
        $port = "1080" ascii
    condition:
        (any of ($socks4, $socks5)) and any of ($proxy, $connect, $auth, $port)
}

