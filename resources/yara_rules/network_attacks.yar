/*
    Network Attack Tools and Protocol Abuse Detection
    Covers: Port scanners, exploit frameworks, tunneling, C2 protocols
*/

rule NetAttack_Nmap_Scanner {
    meta:
        description = "Nmap network scanner indicators"
        severity = "medium"
    strings:
        $s1 = "nmap" ascii nocase
        $s2 = "zenmap" ascii nocase
        $s3 = "nmap-services" ascii
        $s4 = "nmap-payloads" ascii
        $s5 = "nmap-mac-prefixes" ascii
        $nse = ".nse" ascii
        $scan = "SYN scan" ascii
    condition:
        2 of them
}

rule NetAttack_Masscan {
    meta:
        description = "Masscan high-speed scanner"
        severity = "medium"
    strings:
        $s1 = "masscan" ascii nocase
        $s2 = "--rate" ascii
        $s3 = "--ports" ascii
        $s4 = "banner-" ascii
    condition:
        $s1 or 3 of ($s*)
}

rule NetAttack_Responder {
    meta:
        description = "Responder LLMNR/NBT-NS poisoner"
        severity = "high"
    strings:
        $s1 = "Responder" ascii
        $s2 = "LLMNR" ascii
        $s3 = "NBT-NS" ascii
        $s4 = "WPAD" ascii
        $s5 = "poisoner" ascii nocase
        $hash = "NTLMv" ascii
    condition:
        3 of them
}

rule NetAttack_Impacket {
    meta:
        description = "Impacket network protocol tools"
        severity = "high"
    strings:
        $s1 = "impacket" ascii nocase
        $s2 = "psexec.py" ascii
        $s3 = "smbexec.py" ascii
        $s4 = "wmiexec.py" ascii
        $s5 = "secretsdump" ascii
        $s6 = "ntlmrelayx" ascii
        $s7 = "GetNPUsers" ascii
        $s8 = "GetUserSPNs" ascii
    condition:
        2 of them
}

rule NetAttack_Mimikatz_Network {
    meta:
        description = "Mimikatz network credential dumping"
        severity = "critical"
    strings:
        $s1 = "mimikatz" ascii nocase
        $s2 = "sekurlsa" ascii
        $s3 = "kerberos" ascii
        $s4 = "lsadump" ascii
        $s5 = "dpapi" ascii
        $s6 = "privilege::debug" ascii
        $s7 = "sekurlsa::logonpasswords" ascii
    condition:
        3 of them
}

rule NetAttack_BloodHound {
    meta:
        description = "BloodHound AD reconnaissance"
        severity = "high"
    strings:
        $s1 = "BloodHound" ascii
        $s2 = "SharpHound" ascii
        $s3 = "CollectionMethod" ascii
        $s4 = "Ingestors" ascii
        $ldap = "LDAP" ascii
        $neo4j = "neo4j" ascii nocase
    condition:
        2 of ($s*) or ($ldap and $neo4j)
}

rule NetAttack_Rubeus {
    meta:
        description = "Rubeus Kerberos abuse tool"
        severity = "critical"
    strings:
        $s1 = "Rubeus" ascii
        $s2 = "asreproast" ascii nocase
        $s3 = "kerberoast" ascii nocase
        $s4 = "s4u" ascii nocase
        $s5 = "tgtdeleg" ascii nocase
        $s6 = "ptt" ascii nocase
        $s7 = "kirbi" ascii nocase
    condition:
        $s1 or 3 of ($s*)
}

rule NetAttack_CrackMapExec {
    meta:
        description = "CrackMapExec lateral movement"
        severity = "critical"
    strings:
        $s1 = "crackmapexec" ascii nocase
        $s2 = "cme" ascii nocase
        $s3 = "CME" ascii
        $proto1 = "smb" ascii nocase
        $proto2 = "winrm" ascii nocase
        $proto3 = "ldap" ascii nocase
        $proto4 = "mssql" ascii nocase
    condition:
        any of ($s*) and any of ($proto*)
}

rule NetAttack_Chisel_Tunnel {
    meta:
        description = "Chisel TCP/UDP tunneling"
        severity = "high"
    strings:
        $s1 = "chisel" ascii nocase
        $s2 = "client" ascii
        $s3 = "server" ascii
        $s4 = "--reverse" ascii
        $s5 = "R:" ascii
        $s6 = "socks" ascii
    condition:
        $s1 and 2 of ($s*)
}

rule NetAttack_Ligolo {
    meta:
        description = "Ligolo network pivoting"
        severity = "high"
    strings:
        $s1 = "ligolo" ascii nocase
        $s2 = "agent" ascii
        $s3 = "proxy" ascii
        $s4 = "-connect" ascii
        $s5 = "selfcert" ascii
    condition:
        $s1 and 2 of ($s*)
}

rule NetAttack_Proxychains {
    meta:
        description = "Proxychains network pivoting"
        severity = "medium"
    strings:
        $s1 = "proxychains" ascii nocase
        $s2 = "ProxyList" ascii
        $s3 = "chain_len" ascii
        $s4 = "socks4" ascii
        $s5 = "socks5" ascii
        $s6 = "strict_chain" ascii
        $s7 = "dynamic_chain" ascii
    condition:
        $s1 or 3 of ($s*)
}

rule NetAttack_DNS_Tunnel {
    meta:
        description = "DNS tunneling indicators"
        severity = "high"
    strings:
        $tool1 = "dnscat" ascii nocase
        $tool2 = "iodine" ascii nocase
        $tool3 = "dns2tcp" ascii nocase
        $s1 = "TXT" ascii
        $s2 = "CNAME" ascii
        $s3 = "MX" ascii
        $enc = "base" ascii nocase
        $long = /[a-z0-9]{50,}\.[a-z]{2,}/ ascii
    condition:
        any of ($tool*) or (2 of ($s*) and ($enc or $long))
}

rule NetAttack_ICMP_Tunnel {
    meta:
        description = "ICMP tunneling"
        severity = "high"
    strings:
        $tool1 = "ptunnel" ascii nocase
        $tool2 = "icmpsh" ascii nocase
        $tool3 = "icmptunnel" ascii nocase
        $raw = "SOCK_RAW" ascii
        $icmp = "IPPROTO_ICMP" ascii
    condition:
        any of ($tool*) or ($raw and $icmp)
}

rule NetAttack_HTTP_Tunnel {
    meta:
        description = "HTTP tunneling"
        severity = "high"
    strings:
        $tool1 = "reGeorg" ascii nocase
        $tool2 = "tunna" ascii nocase
        $tool3 = "ABPTTS" ascii nocase
        $tool4 = "Neo-reGeorg" ascii nocase
        $webshell = "<%@" ascii
        $connect = "CONNECT" ascii
        $tunnel = "tunnel" ascii nocase
    condition:
        any of ($tool*) or ($webshell and ($connect or $tunnel))
}

rule NetAttack_SSH_Tunnel {
    meta:
        description = "SSH tunneling/port forwarding"
        severity = "medium"
    strings:
        $ssh = "ssh" ascii nocase
        $L = "-L" ascii
        $R = "-R" ascii
        $D = "-D" ascii
        $N = "-N" ascii
        $f = "-f" ascii
        $forward = "forward" ascii nocase
    condition:
        $ssh and 2 of ($L, $R, $D, $N, $f, $forward)
}

rule NetAttack_Reverse_Shell {
    meta:
        description = "Reverse shell patterns"
        severity = "critical"
    strings:
        $nc1 = "nc -e" ascii
        $nc2 = "ncat -e" ascii
        $nc3 = "netcat" ascii nocase
        $bash = "bash -i" ascii
        $sh = "/bin/sh" ascii
        $python = "python -c" ascii
        $perl = "perl -e" ascii
        $ruby = "ruby -rsocket" ascii
        $php = "php -r" ascii
        $socket = "socket" ascii
        $connect = "connect" ascii
        $dup2 = "dup2" ascii
        $exec = "exec" ascii
    condition:
        any of ($nc*) or ($bash and any of ($sh, $socket)) or
        (any of ($python, $perl, $ruby, $php) and 2 of ($socket, $connect, $dup2, $exec))
}

rule NetAttack_PortForward {
    meta:
        description = "Port forwarding tools"
        severity = "medium"
    strings:
        $tool1 = "socat" ascii nocase
        $tool2 = "rinetd" ascii nocase
        $tool3 = "redir" ascii nocase
        $tool4 = "fpipe" ascii nocase
        $tool5 = "portfwd" ascii nocase
        $sock = "SOCK_STREAM" ascii
        $listen = "listen" ascii
        $accept = "accept" ascii
    condition:
        any of ($tool*) or ($sock and $listen and $accept)
}

rule NetAttack_ARP_Spoof {
    meta:
        description = "ARP spoofing/poisoning"
        severity = "high"
    strings:
        $tool1 = "arpspoof" ascii nocase
        $tool2 = "ettercap" ascii nocase
        $tool3 = "bettercap" ascii nocase
        $arp = "ARP" ascii
        $spoof = "spoof" ascii nocase
        $poison = "poison" ascii nocase
        $mitm = "mitm" ascii nocase
    condition:
        any of ($tool*) or ($arp and any of ($spoof, $poison, $mitm))
}

rule NetAttack_SMB_Relay {
    meta:
        description = "SMB relay attack"
        severity = "critical"
    strings:
        $tool1 = "ntlmrelayx" ascii nocase
        $tool2 = "smbrelayx" ascii nocase
        $tool3 = "MultiRelay" ascii nocase
        $smb = "SMB" ascii
        $relay = "relay" ascii nocase
        $ntlm = "NTLM" ascii
    condition:
        any of ($tool*) or ($smb and $relay and $ntlm)
}

rule NetAttack_Pass_The_Hash {
    meta:
        description = "Pass-the-hash attack"
        severity = "critical"
    strings:
        $pth1 = "pth-" ascii nocase
        $pth2 = "pass-the-hash" ascii nocase
        $pth3 = "PassTheHash" ascii
        $hash = /[a-f0-9]{32}:[a-f0-9]{32}/ ascii nocase
        $lm = "LM:" ascii
        $nt = "NT:" ascii
    condition:
        any of ($pth*) or $hash or ($lm and $nt)
}
