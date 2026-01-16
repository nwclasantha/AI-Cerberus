/*
    Worm and Botnet Detection Rules
    Covers: Mirai, Conficker, Sality, various botnets
*/

rule Mirai_Botnet {
    meta:
        description = "Mirai IoT botnet"
        severity = "critical"
    strings:
        $s1 = "mirai" nocase
        $s2 = "/bin/busybox" ascii
        $s3 = "SCANNER" ascii
        $s4 = "killer" ascii
        $s5 = "attack" ascii
        $telnet = "telnet" ascii
    condition:
        2 of ($s*) or ($telnet and any of ($s*))
}

rule Mirai_Variant {
    meta:
        description = "Mirai variant"
        severity = "critical"
    strings:
        $s1 = "gafgyt" nocase
        $s2 = "bashlite" nocase
        $s3 = "qbot" nocase
        $s4 = "tsunami" nocase
        $s5 = "kaiten" nocase
    condition:
        any of them
}

rule Conficker_Worm {
    meta:
        description = "Conficker/Downadup worm"
        severity = "critical"
    strings:
        $s1 = "conficker" nocase
        $s2 = "downadup" nocase
        $s3 = "kido" nocase
        $mutex = "Global\\M" ascii
        $api = "DnsQuery" ascii
    condition:
        any of ($s*) or ($mutex and $api)
}

rule Sality_Virus {
    meta:
        description = "Sality file infector"
        severity = "critical"
    strings:
        $s1 = "sality" nocase
        $s2 = {E8 ?? ?? ?? ?? 5D 8B C5}
        $mutex = "sal" ascii
    condition:
        any of them
}

rule Virut_Virus {
    meta:
        description = "Virut file infector"
        severity = "critical"
    strings:
        $s1 = "virut" nocase
        $s2 = {E8 00 00 00 00 5D 81 ED}
        $irc = "irc" ascii
    condition:
        any of ($s*) or ($irc and $s2)
}

rule Ramnit_Worm {
    meta:
        description = "Ramnit worm"
        severity = "critical"
    strings:
        $s1 = "ramnit" nocase
        $s2 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 04}
        $s3 = "Wirus" ascii
    condition:
        any of them
}

rule WannaCry_Worm {
    meta:
        description = "WannaCry ransomworm"
        severity = "critical"
    strings:
        $s1 = "WannaCry" ascii
        $s2 = "WanaCrypt0r" ascii
        $s3 = "tasksche.exe" ascii
        $smb = "SMB" ascii
        $eb = "EternalBlue" ascii
    condition:
        any of ($s*) or ($smb and $eb)
}

rule NotPetya_Worm {
    meta:
        description = "NotPetya/ExPetr worm"
        severity = "critical"
    strings:
        $s1 = "NotPetya" ascii
        $s2 = "ExPetr" ascii
        $s3 = "perfc.dat" ascii
        $psexec = "psexec" nocase
    condition:
        any of ($s*) or $psexec
}

rule Emotet_Botnet {
    meta:
        description = "Emotet botnet"
        severity = "critical"
    strings:
        $s1 = "emotet" nocase
        $s2 = {8B 45 ?? 83 C0 ?? 50 8B 4D ?? 51}
        $http = "Content-Type:" ascii
    condition:
        any of ($s*) or $http
}

rule TrickBot_Botnet {
    meta:
        description = "TrickBot botnet"
        severity = "critical"
    strings:
        $s1 = "trickbot" nocase
        $mod1 = "systeminfo" ascii
        $mod2 = "injectDll" ascii
        $cfg = "<mcconf>" ascii
    condition:
        $s1 or 2 of ($mod*) or $cfg
}

rule ZeuS_Botnet {
    meta:
        description = "ZeuS/Zbot botnet"
        severity = "critical"
    strings:
        $s1 = "zeus" nocase
        $s2 = "zbot" nocase
        $cfg = "local.ds" ascii
        $web = "webinject" ascii
    condition:
        any of ($s*) or ($cfg and $web)
}

rule Necurs_Botnet {
    meta:
        description = "Necurs botnet"
        severity = "critical"
    strings:
        $s1 = "necurs" nocase
        $s2 = {8B 45 ?? 89 45 ?? 8B 4D ??}
        $p2p = "p2p" ascii
    condition:
        any of ($s*) or $p2p
}

rule Andromeda_Botnet {
    meta:
        description = "Andromeda/Gamarue botnet"
        severity = "critical"
    strings:
        $s1 = "andromeda" nocase
        $s2 = "gamarue" nocase
        $mutex = "Global\\" ascii
        $task = "schtasks" ascii
    condition:
        any of ($s*) or ($mutex and $task)
}

rule Dridex_Botnet {
    meta:
        description = "Dridex botnet"
        severity = "critical"
    strings:
        $s1 = "dridex" nocase
        $s2 = "bugat" nocase
        $s3 = "cridex" nocase
        $cfg = {C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ??}
    condition:
        any of ($s*) or $cfg
}

rule Phorpiex_Worm {
    meta:
        description = "Phorpiex/Trik worm"
        severity = "critical"
    strings:
        $s1 = "phorpiex" nocase
        $s2 = "trik" nocase
        $usb = "autorun.inf" nocase
        $spam = "smtp" nocase
    condition:
        any of ($s*) or ($usb and $spam)
}

rule Mydoom_Worm {
    meta:
        description = "MyDoom worm"
        severity = "critical"
    strings:
        $s1 = "mydoom" nocase
        $s2 = "novarg" nocase
        $s3 = "andy" ascii
        $mutex = "Sync" ascii
    condition:
        any of ($s*) or $mutex
}

rule Sasser_Worm {
    meta:
        description = "Sasser worm"
        severity = "critical"
    strings:
        $s1 = "sasser" nocase
        $s2 = "lsasss.exe" ascii
        $s3 = "avserve" ascii
    condition:
        any of them
}

rule Blaster_Worm {
    meta:
        description = "Blaster/MSBlast worm"
        severity = "critical"
    strings:
        $s1 = "blaster" nocase
        $s2 = "msblast" nocase
        $s3 = "I just want to say LOVE YOU SAN!!" ascii
    condition:
        any of them
}

rule Koobface_Worm {
    meta:
        description = "Koobface worm"
        severity = "critical"
    strings:
        $s1 = "koobface" nocase
        $s2 = "facebook" nocase
        $s3 = "youtube" nocase
        $social = "social" ascii
    condition:
        $s1 or (any of ($s2, $s3) and $social)
}

rule Mozi_Botnet {
    meta:
        description = "Mozi IoT botnet"
        severity = "critical"
    strings:
        $s1 = "mozi" nocase
        $s2 = "/bin/sh" ascii
        $s3 = "wget" ascii
        $dht = "dht" ascii
    condition:
        2 of ($s*) or ($dht and any of ($s*))
}

rule Hajime_Botnet {
    meta:
        description = "Hajime IoT botnet"
        severity = "critical"
    strings:
        $s1 = "hajime" nocase
        $s2 = ".i.hajime" ascii
        $s3 = "atk" ascii
        $p2p = "BitTorrent" ascii
    condition:
        any of ($s*) or $p2p
}

rule Reaper_Botnet {
    meta:
        description = "IoT Reaper botnet"
        severity = "critical"
    strings:
        $s1 = "reaper" nocase
        $s2 = "iotroop" nocase
        $s3 = "exploit" ascii
        $iot = "nvr" nocase
    condition:
        any of ($s*) or $iot
}

rule USB_Worm_Generic {
    meta:
        description = "Generic USB worm"
        severity = "high"
    strings:
        $s1 = "autorun.inf" nocase
        $s2 = "RECYCLER" ascii
        $s3 = "[autorun]" nocase
        $action = "open=" nocase
    condition:
        2 of ($s*) or $action
}

rule Email_Worm_Generic {
    meta:
        description = "Generic email worm"
        severity = "high"
    strings:
        $s1 = "smtp" nocase
        $s2 = "@" ascii
        $s3 = "From:" ascii
        $s4 = "To:" ascii
        $s5 = "Subject:" ascii
        $attach = "attachment" nocase
    condition:
        3 of ($s*) and $attach
}

rule P2P_Worm_Generic {
    meta:
        description = "Generic P2P worm"
        severity = "high"
    strings:
        $s1 = "kazaa" nocase
        $s2 = "limewire" nocase
        $s3 = "emule" nocase
        $s4 = "shared folder" nocase
        $s5 = "torrent" nocase
    condition:
        any of them
}

rule IRC_Botnet_Generic {
    meta:
        description = "Generic IRC botnet"
        severity = "high"
    strings:
        $irc1 = "PRIVMSG" ascii
        $irc2 = "JOIN #" ascii
        $irc3 = "NICK " ascii
        $irc4 = "PING" ascii
        $irc5 = "PONG" ascii
        $cmd = "!cmd" ascii
    condition:
        3 of ($irc*) or $cmd
}
