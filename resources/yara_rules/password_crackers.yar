/*
    Password Cracking Tools Detection
    Hash crackers and brute force tools
*/

rule Cracker_Hashcat {
    meta:
        description = "Hashcat password cracker"
        severity = "high"
    strings:
        $s1 = "hashcat" ascii nocase
        $s2 = "hashcat.exe" ascii nocase
        $s3 = "hashcat64" ascii nocase
        $mode = "-m" ascii
        $attack = "-a" ascii
        $wordlist = "wordlist" ascii nocase
        $rules = "rules" ascii nocase
    condition:
        (any of ($s*)) or ($mode and $attack and any of ($wordlist, $rules))
}

rule Cracker_John_The_Ripper {
    meta:
        description = "John the Ripper password cracker"
        severity = "high"
    strings:
        $s1 = "john" ascii nocase
        $s2 = "john.exe" ascii nocase
        $s3 = "john the ripper" ascii nocase
        $format = "--format" ascii
        $wordlist = "--wordlist" ascii
        $rules = "--rules" ascii
        $pot = "john.pot" ascii
    condition:
        (any of ($s*) and any of ($format, $wordlist, $rules, $pot))
}

rule Cracker_Hydra {
    meta:
        description = "THC Hydra brute forcer"
        severity = "critical"
    strings:
        $s1 = "hydra" ascii nocase
        $s2 = "thc-hydra" ascii nocase
        $s3 = "hydra.exe" ascii nocase
        $login = "-l" ascii
        $pass = "-p" ascii
        $ssh = "ssh" ascii nocase
        $ftp = "ftp" ascii nocase
        $http = "http" ascii nocase
    condition:
        (any of ($s*)) and (any of ($login, $pass) or any of ($ssh, $ftp, $http))
}

rule Cracker_Medusa {
    meta:
        description = "Medusa parallel brute forcer"
        severity = "high"
    strings:
        $s1 = "medusa" ascii nocase
        $s2 = "medusa.exe" ascii nocase
        $user = "-u" ascii
        $pass = "-p" ascii
        $host = "-h" ascii
        $module = "-M" ascii
    condition:
        (any of ($s*)) and ($user or $pass) and ($host or $module)
}

rule Cracker_Aircrack {
    meta:
        description = "Aircrack-ng WiFi cracker"
        severity = "high"
    strings:
        $s1 = "aircrack" ascii nocase
        $s2 = "aircrack-ng" ascii nocase
        $wep = "WEP" ascii
        $wpa = "WPA" ascii
        $capture = ".cap" ascii
        $wordlist = "-w" ascii
    condition:
        (any of ($s*)) and (any of ($wep, $wpa) or any of ($capture, $wordlist))
}

rule Cracker_Ophcrack {
    meta:
        description = "Ophcrack Windows password cracker"
        severity = "high"
    strings:
        $s1 = "ophcrack" ascii nocase
        $s2 = "rainbow" ascii nocase
        $table = "table" ascii nocase
        $lm = "LM" ascii
        $ntlm = "NTLM" ascii
        $sam = "SAM" ascii
    condition:
        $s1 or ($s2 and $table and any of ($lm, $ntlm, $sam))
}

rule Cracker_L0phtCrack {
    meta:
        description = "L0phtCrack password auditor"
        severity = "high"
    strings:
        $s1 = "L0phtCrack" ascii nocase
        $s2 = "l0pht" ascii nocase
        $windows = "Windows" ascii nocase
        $hash = "hash" ascii nocase
        $audit = "audit" ascii nocase
    condition:
        (any of ($s*)) or ($windows and $hash and $audit)
}

rule Cracker_CeWL {
    meta:
        description = "CeWL custom wordlist generator"
        severity = "medium"
    strings:
        $s1 = "cewl" ascii nocase
        $spider = "spider" ascii nocase
        $wordlist = "wordlist" ascii nocase
        $depth = "depth" ascii nocase
        $min = "min" ascii nocase
    condition:
        $s1 or ($spider and $wordlist and any of ($depth, $min))
}

rule Cracker_Crunch {
    meta:
        description = "Crunch wordlist generator"
        severity = "medium"
    strings:
        $s1 = "crunch" ascii nocase
        $generate = "generate" ascii nocase
        $charset = "charset" ascii nocase
        $pattern = "pattern" ascii nocase
        $min = "min" ascii nocase
        $max = "max" ascii nocase
    condition:
        $s1 and ($generate or $charset) and any of ($pattern, $min, $max)
}

rule Cracker_Brutus {
    meta:
        description = "Brutus password cracker"
        severity = "high"
    strings:
        $s1 = "Brutus" ascii nocase
        $s2 = "brutus" ascii nocase
        $http = "HTTP" ascii
        $ftp = "FTP" ascii
        $telnet = "Telnet" ascii
        $brute = "brute" ascii nocase
    condition:
        (any of ($s*)) and (any of ($http, $ftp, $telnet) or $brute)
}

rule Cracker_Patator {
    meta:
        description = "Patator multi-purpose brute forcer"
        severity = "high"
    strings:
        $s1 = "patator" ascii nocase
        $python = "python" ascii nocase
        $ssh = "ssh_login" ascii nocase
        $ftp = "ftp_login" ascii nocase
        $http = "http_fuzz" ascii nocase
    condition:
        $s1 or ($python and any of ($ssh, $ftp, $http))
}

rule Cracker_Crowbar {
    meta:
        description = "Crowbar brute forcer"
        severity = "high"
    strings:
        $s1 = "crowbar" ascii nocase
        $rdp = "RDP" ascii
        $ssh = "SSH" ascii
        $vpn = "VPN" ascii
        $brute = "brute" ascii nocase
        $key = "key" ascii nocase
    condition:
        $s1 and (any of ($rdp, $ssh, $vpn) or ($brute and $key))
}

rule Cracker_Ncrack {
    meta:
        description = "Ncrack network authentication cracker"
        severity = "high"
    strings:
        $s1 = "ncrack" ascii nocase
        $nmap = "nmap" ascii nocase
        $auth = "authentication" ascii nocase
        $crack = "crack" ascii nocase
        $service = "service" ascii nocase
    condition:
        $s1 or ($nmap and $auth and any of ($crack, $service))
}

rule Cracker_RainbowCrack {
    meta:
        description = "RainbowCrack table cracker"
        severity = "high"
    strings:
        $s1 = "rainbowcrack" ascii nocase
        $s2 = "rcrack" ascii nocase
        $rainbow = "rainbow" ascii nocase
        $table = "table" ascii nocase
        $rt = ".rt" ascii nocase
        $rtc = ".rtc" ascii nocase
    condition:
        (any of ($s*)) or ($rainbow and $table and any of ($rt, $rtc))
}

rule Cracker_KeePass_Crack {
    meta:
        description = "KeePass database cracker"
        severity = "high"
    strings:
        $keepass = "KeePass" ascii nocase
        $kdbx = ".kdbx" ascii nocase
        $kdb = ".kdb" ascii nocase
        $crack = "crack" ascii nocase
        $brute = "brute" ascii nocase
        $keyfile = "keyfile" ascii nocase
    condition:
        $keepass and (any of ($kdbx, $kdb)) and any of ($crack, $brute, $keyfile)
}

rule Cracker_Office_Crack {
    meta:
        description = "Microsoft Office password cracker"
        severity = "high"
    strings:
        $office = "Office" ascii nocase
        $crack = "crack" ascii nocase
        $xlsx = ".xlsx" ascii nocase
        $docx = ".docx" ascii nocase
        $pptx = ".pptx" ascii nocase
        $password = "password" ascii nocase
    condition:
        $office and $crack and any of ($xlsx, $docx, $pptx, $password)
}

rule Cracker_PDF_Crack {
    meta:
        description = "PDF password cracker"
        severity = "medium"
    strings:
        $pdf = "PDF" ascii
        $crack = "crack" ascii nocase
        $pdfcrack = "pdfcrack" ascii nocase
        $password = "password" ascii nocase
        $brute = "brute" ascii nocase
    condition:
        ($pdf and $crack and any of ($password, $brute)) or $pdfcrack
}

rule Cracker_ZIP_Crack {
    meta:
        description = "ZIP/RAR password cracker"
        severity = "medium"
    strings:
        $zip = "ZIP" ascii
        $rar = "RAR" ascii
        $crack = "crack" ascii nocase
        $fcrackzip = "fcrackzip" ascii nocase
        $rarcrack = "rarcrack" ascii nocase
        $john = "zip2john" ascii nocase
    condition:
        (any of ($zip, $rar) and $crack) or any of ($fcrackzip, $rarcrack, $john)
}

rule Cracker_WiFi_Pineapple {
    meta:
        description = "WiFi Pineapple related"
        severity = "high"
    strings:
        $s1 = "WiFi Pineapple" ascii nocase
        $s2 = "pineapple" ascii nocase
        $hak5 = "Hak5" ascii nocase
        $mitm = "MITM" ascii
        $evil = "evil twin" ascii nocase
    condition:
        (any of ($s*) and $hak5) or ($mitm and $evil)
}

rule Cracker_Generic_Bruteforce {
    meta:
        description = "Generic brute force tool"
        severity = "high"
    strings:
        $brute = "brute" ascii nocase
        $force = "force" ascii nocase
        $crack = "crack" ascii nocase
        $password = "password" ascii nocase
        $wordlist = "wordlist" ascii nocase
        $dictionary = "dictionary" ascii nocase
        $attempt = "attempt" ascii nocase
    condition:
        (($brute and $force) or $crack) and any of ($password, $wordlist, $dictionary, $attempt)
}

