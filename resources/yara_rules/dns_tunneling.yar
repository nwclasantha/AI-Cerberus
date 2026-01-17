/*
    DNS Tunneling Detection
    DNS-based data exfiltration and C2 communication
*/

rule DNS_Tunnel_Iodine {
    meta:
        description = "Iodine DNS tunnel"
        severity = "critical"
    strings:
        $s1 = "iodine" ascii nocase
        $s2 = "iodined" ascii nocase
        $s3 = "kryo.se" ascii
        $dns = "DNS" ascii
        $tunnel = "tunnel" ascii nocase
        $tun = "tun0" ascii
    condition:
        (any of ($s*)) or ($dns and $tunnel and $tun)
}

rule DNS_Tunnel_DNScat2 {
    meta:
        description = "DNScat2 tunnel"
        severity = "critical"
    strings:
        $s1 = "dnscat" ascii nocase
        $s2 = "dnscat2" ascii nocase
        $s3 = "skullsecurity" ascii
        $cmd = "command" ascii nocase
        $session = "session" ascii nocase
        $dns = "DNS" ascii
    condition:
        (any of ($s*)) or ($cmd and $session and $dns)
}

rule DNS_Tunnel_DNS2TCP {
    meta:
        description = "dns2tcp tunnel"
        severity = "critical"
    strings:
        $s1 = "dns2tcp" ascii nocase
        $s2 = "dns2tcpd" ascii nocase
        $s3 = "dns2tcpc" ascii nocase
        $tcp = "TCP" ascii
        $dns = "DNS" ascii
        $tunnel = "tunnel" ascii nocase
    condition:
        (any of ($s*)) or ($tcp and $dns and $tunnel)
}

rule DNS_Tunnel_Heyoka {
    meta:
        description = "Heyoka DNS tunnel"
        severity = "critical"
    strings:
        $s1 = "heyoka" ascii nocase
        $s2 = "Heyoka" ascii
        $spoof = "spoof" ascii nocase
        $dns = "DNS" ascii
        $exfil = "exfil" ascii nocase
    condition:
        (any of ($s*)) or ($spoof and $dns and $exfil)
}

rule DNS_Tunnel_DNSExfiltrator {
    meta:
        description = "DNSExfiltrator tool"
        severity = "critical"
    strings:
        $s1 = "DNSExfiltrator" ascii nocase
        $s2 = "dns-exfiltrator" ascii nocase
        $s3 = "Arno0x" ascii
        $base = "base64" ascii nocase
        $chunk = "chunk" ascii nocase
        $dns = "DNS" ascii
    condition:
        (any of ($s*)) or ($base and $chunk and $dns)
}

rule DNS_Tunnel_Cobalt_Strike_DNS {
    meta:
        description = "Cobalt Strike DNS beacon"
        severity = "critical"
    strings:
        $s1 = "beacon" ascii nocase
        $s2 = "dns-beacon" ascii nocase
        $dns = "dns" ascii nocase
        $mode = "mode" ascii nocase
        $txt = "TXT" ascii
        $a = "A record" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($s1 and $dns) and any of ($mode, $txt, $a)
}

rule DNS_Tunnel_PowerDNS_Exfil {
    meta:
        description = "PowerShell DNS exfiltration"
        severity = "critical"
    strings:
        $ps = "powershell" ascii nocase
        $dns1 = "Resolve-DnsName" ascii
        $dns2 = "nslookup" ascii nocase
        $encode = "ConvertTo-Base64" ascii
        $encode2 = "[Convert]::ToBase64String" ascii
        $chunk = "substring" ascii nocase
    condition:
        $ps and (any of ($dns*)) and (any of ($encode, $encode2, $chunk))
}

rule DNS_Tunnel_Generic_Subdomain {
    meta:
        description = "Generic DNS subdomain tunneling"
        severity = "high"
    strings:
        $dns = "dns" ascii nocase
        $sub = "subdomain" ascii nocase
        $encode1 = "base64" ascii nocase
        $encode2 = "hex" ascii nocase
        $tunnel = "tunnel" ascii nocase
        $exfil = "exfil" ascii nocase
        $query = "query" ascii nocase
    condition:
        $dns and ($sub or any of ($encode*)) and any of ($tunnel, $exfil, $query)
}

rule DNS_Tunnel_TXT_Record {
    meta:
        description = "DNS TXT record tunneling"
        severity = "high"
    strings:
        $txt = "TXT" ascii
        $dns1 = "DnsQuery" ascii
        $dns2 = "res_query" ascii
        $dns3 = "getdns" ascii
        $record = "record" ascii nocase
        $tunnel = "tunnel" ascii nocase
        $data = "data" ascii nocase
    condition:
        $txt and (any of ($dns*)) and any of ($record, $tunnel, $data)
}

rule DNS_Tunnel_CNAME_Exfil {
    meta:
        description = "DNS CNAME exfiltration"
        severity = "high"
    strings:
        $cname = "CNAME" ascii
        $dns = "dns" ascii nocase
        $exfil = "exfil" ascii nocase
        $encode = "encode" ascii nocase
        $chunk = "chunk" ascii nocase
    condition:
        $cname and $dns and any of ($exfil, $encode, $chunk)
}

rule DNS_Tunnel_High_Entropy_Query {
    meta:
        description = "High entropy DNS queries"
        severity = "medium"
    strings:
        $dns = "dns" ascii nocase
        $entropy = "entropy" ascii nocase
        $random = "random" ascii nocase
        $query = "query" ascii nocase
        $long = "long" ascii nocase
        $subdomain = "subdomain" ascii nocase
    condition:
        $dns and $query and any of ($entropy, $random, $long, $subdomain)
}

rule DNS_Tunnel_Frequency_Analysis {
    meta:
        description = "Frequent DNS query pattern"
        severity = "medium"
    strings:
        $dns = "dns" ascii nocase
        $freq = "frequency" ascii nocase
        $interval = "interval" ascii nocase
        $beacon = "beacon" ascii nocase
        $periodic = "periodic" ascii nocase
        $timer = "timer" ascii nocase
    condition:
        $dns and any of ($freq, $interval, $beacon, $periodic, $timer)
}

rule DNS_Tunnel_AAAA_Record {
    meta:
        description = "DNS AAAA record tunneling"
        severity = "medium"
    strings:
        $aaaa = "AAAA" ascii
        $ipv6 = "IPv6" ascii nocase
        $dns = "dns" ascii nocase
        $tunnel = "tunnel" ascii nocase
        $encode = "encode" ascii nocase
    condition:
        $aaaa and ($ipv6 or $dns) and any of ($tunnel, $encode)
}

rule DNS_Tunnel_MX_Record {
    meta:
        description = "DNS MX record abuse"
        severity = "medium"
    strings:
        $mx = "MX" ascii
        $mail = "mail" ascii nocase
        $dns = "dns" ascii nocase
        $tunnel = "tunnel" ascii nocase
        $exfil = "exfil" ascii nocase
    condition:
        $mx and $dns and any of ($mail, $tunnel, $exfil)
}

rule DNS_Tunnel_NULL_Record {
    meta:
        description = "DNS NULL record tunneling"
        severity = "high"
    strings:
        $null = "NULL" ascii
        $type10 = "type 10" ascii nocase
        $dns = "dns" ascii nocase
        $raw = "raw" ascii nocase
        $binary = "binary" ascii nocase
    condition:
        ($null or $type10) and $dns and any of ($raw, $binary)
}

rule DNS_Tunnel_SRV_Record {
    meta:
        description = "DNS SRV record abuse"
        severity = "medium"
    strings:
        $srv = "SRV" ascii
        $service = "_service" ascii
        $dns = "dns" ascii nocase
        $exfil = "exfil" ascii nocase
        $data = "data" ascii nocase
    condition:
        $srv and ($service or $dns) and any of ($exfil, $data)
}

rule DNS_Tunnel_DoH_Abuse {
    meta:
        description = "DNS over HTTPS tunneling"
        severity = "high"
    strings:
        $doh = "dns-query" ascii
        $https = "https://" ascii
        $cloudflare = "cloudflare-dns.com" ascii
        $google = "dns.google" ascii
        $tunnel = "tunnel" ascii nocase
        $exfil = "exfil" ascii nocase
    condition:
        ($doh or any of ($cloudflare, $google)) and $https and any of ($tunnel, $exfil)
}

rule DNS_Tunnel_DoT_Abuse {
    meta:
        description = "DNS over TLS tunneling"
        severity = "high"
    strings:
        $dot = "853" ascii
        $tls = "TLS" ascii
        $dns = "dns" ascii nocase
        $tunnel = "tunnel" ascii nocase
        $encrypted = "encrypted" ascii nocase
    condition:
        $dot and ($tls or $dns) and any of ($tunnel, $encrypted)
}

rule DNS_Tunnel_Rebinding {
    meta:
        description = "DNS rebinding attack"
        severity = "critical"
    strings:
        $rebind = "rebind" ascii nocase
        $dns = "dns" ascii nocase
        $ttl = "TTL" ascii
        $low = "0" ascii
        $localhost = "127.0.0.1" ascii
        $internal = "192.168" ascii
    condition:
        $rebind and $dns and ($ttl or any of ($localhost, $internal))
}

rule DNS_Tunnel_Fast_Flux {
    meta:
        description = "Fast flux DNS technique"
        severity = "high"
    strings:
        $flux = "flux" ascii nocase
        $fast = "fast" ascii nocase
        $dns = "dns" ascii nocase
        $rotate = "rotate" ascii nocase
        $ip = "IP" ascii
        $multiple = "multiple" ascii nocase
    condition:
        ($flux and $fast) or ($dns and any of ($rotate, $multiple) and $ip)
}

