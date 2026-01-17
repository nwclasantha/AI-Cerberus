/*
    Russian APT Detection Rules (Advanced)
    APT28, APT29, Turla, Sandworm, Gamaredon, and other Russian threat actors
*/

rule Russian_APT28_Fancy_Bear {
    meta:
        description = "APT28/Fancy Bear indicators"
        severity = "critical"
    strings:
        $s1 = "SOFACY" ascii nocase
        $s2 = "SEDKIT" ascii nocase
        $s3 = "JHUHUGIT" ascii nocase
        $s4 = "CHOPSTICK" ascii nocase
        $s5 = "GAMEFISH" ascii nocase
        $s6 = "EVILTOSS" ascii nocase
        $s7 = "X-Agent" ascii nocase
        $s8 = "Zebrocy" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of them)
}

rule Russian_APT29_Cozy_Bear {
    meta:
        description = "APT29/Cozy Bear indicators"
        severity = "critical"
    strings:
        $s1 = "HAMMERTOSS" ascii nocase
        $s2 = "COZYDUKE" ascii nocase
        $s3 = "SEADUKE" ascii nocase
        $s4 = "MINIDUKE" ascii nocase
        $s5 = "POSHSPY" ascii nocase
        $s6 = "WELLMESS" ascii nocase
        $s7 = "WELLMAIL" ascii nocase
        $s8 = "EnvyScout" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of them)
}

rule Russian_Turla_Snake {
    meta:
        description = "Turla/Snake indicators"
        severity = "critical"
    strings:
        $s1 = "TURLA" ascii nocase
        $s2 = "UROBUROS" ascii nocase
        $s3 = "Carbon" ascii nocase
        $s4 = "KAZUAR" ascii nocase
        $s5 = "GAZER" ascii nocase
        $s6 = "COMRAT" ascii nocase
        $s7 = "CRUTCH" ascii nocase
        $s8 = "Penquin" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of them)
}

rule Russian_Sandworm {
    meta:
        description = "Sandworm Team indicators"
        severity = "critical"
    strings:
        $s1 = "BlackEnergy" ascii nocase
        $s2 = "INDUSTROYER" ascii nocase
        $s3 = "CRASHOVERRIDE" ascii nocase
        $s4 = "NotPetya" ascii nocase
        $s5 = "GreyEnergy" ascii nocase
        $s6 = "Exaramel" ascii nocase
        $s7 = "Cyclops Blink" ascii nocase
        $voodoo = "VoodooB" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of them)
}

rule Russian_Gamaredon {
    meta:
        description = "Gamaredon Group indicators"
        severity = "critical"
    strings:
        $s1 = "Gamaredon" ascii nocase
        $s2 = "PTERODO" ascii nocase
        $s3 = "QUOTASPEC" ascii nocase
        $s4 = "EvilGnome" ascii nocase
        $s5 = "Shuckworm" ascii nocase
        $ukraine = "ukraine" ascii nocase
        $lnk = ".lnk" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($s*))
}

rule Russian_Dragonfly_Energetic_Bear {
    meta:
        description = "Dragonfly/Energetic Bear"
        severity = "critical"
    strings:
        $s1 = "Dragonfly" ascii nocase
        $s2 = "Energetic Bear" ascii nocase
        $s3 = "Havex" ascii nocase
        $s4 = "DORSHEL" ascii nocase
        $s5 = "Karagany" ascii nocase
        $ics = "ICS" ascii
        $scada = "SCADA" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($s*) or ($ics and $scada))
}

rule Russian_FIN7_Carbanak {
    meta:
        description = "FIN7/Carbanak indicators"
        severity = "critical"
    strings:
        $s1 = "Carbanak" ascii nocase
        $s2 = "GRIFFON" ascii nocase
        $s3 = "HALFBAKED" ascii nocase
        $s4 = "DICELOADER" ascii nocase
        $s5 = "TIRION" ascii nocase
        $s6 = "JSSLoader" ascii nocase
        $pos = "POS" ascii
        $payment = "payment" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($s*))
}

rule Russian_Evil_Corp {
    meta:
        description = "Evil Corp indicators"
        severity = "critical"
    strings:
        $s1 = "DoppelPaymer" ascii nocase
        $s2 = "BitPaymer" ascii nocase
        $s3 = "WastedLocker" ascii nocase
        $s4 = "Hades" ascii nocase
        $s5 = "Phoenix" ascii nocase
        $s6 = "Dridex" ascii nocase
        $s7 = "SocGholish" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of them)
}

rule Russian_Buhtrap {
    meta:
        description = "Buhtrap banking group"
        severity = "critical"
    strings:
        $s1 = "Buhtrap" ascii nocase
        $s2 = "Ratopak" ascii nocase
        $s3 = "nworm" ascii nocase
        $bank = "bank" ascii nocase
        $finance = "finance" ascii nocase
        $swift = "SWIFT" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($s*) or ($bank and $finance))
}

rule Russian_Silence_Group {
    meta:
        description = "Silence cybercrime group"
        severity = "critical"
    strings:
        $s1 = "Silence" ascii nocase
        $s2 = "TrueBot" ascii nocase
        $s3 = "FlawedAmmyy" ascii nocase
        $atm = "ATM" ascii
        $bank = "bank" ascii nocase
        $swift = "SWIFT" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($s*) or ($atm and $bank))
}

rule Russian_InvisiMole {
    meta:
        description = "InvisiMole APT"
        severity = "critical"
    strings:
        $s1 = "InvisiMole" ascii nocase
        $s2 = "RC2FM" ascii nocase
        $s3 = "RC2CL" ascii nocase
        $spy = "spy" ascii nocase
        $screen = "screen" ascii nocase
        $audio = "audio" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($s*))
}

rule Russian_Berserk_Bear {
    meta:
        description = "Berserk Bear APT"
        severity = "critical"
    strings:
        $s1 = "BerserkBear" ascii nocase
        $s2 = "TeamSpy" ascii nocase
        $s3 = "Havex" ascii nocase
        $s4 = "CrouchingYeti" ascii nocase
        $energy = "energy" ascii nocase
        $grid = "grid" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($s*))
}

rule Russian_GRU_Tools {
    meta:
        description = "GRU APT tools"
        severity = "critical"
    strings:
        $s1 = "X-Tunnel" ascii nocase
        $s2 = "XTunnel" ascii nocase
        $s3 = "CompuTrace" ascii nocase
        $s4 = "LoJax" ascii nocase
        $s5 = "VPNFilter" ascii nocase
        $uefi = "UEFI" ascii
        $bios = "BIOS" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($s*))
}

rule Russian_FSB_Tools {
    meta:
        description = "FSB APT tools"
        severity = "critical"
    strings:
        $s1 = "Snake" ascii nocase
        $s2 = "Agent.BTZ" ascii nocase
        $s3 = "ComRAT" ascii nocase
        $s4 = "Chinoxy" ascii nocase
        $s5 = "LightNeuron" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of them)
}

rule Russian_Triton_Trisis {
    meta:
        description = "TRITON/TRISIS ICS malware"
        severity = "critical"
    strings:
        $s1 = "TRITON" ascii nocase
        $s2 = "TRISIS" ascii nocase
        $s3 = "HatMan" ascii nocase
        $triconex = "Triconex" ascii
        $sis = "SIS" ascii
        $safety = "Safety" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($s*) or ($triconex and any of ($sis, $safety)))
}

rule Russian_Olympic_Destroyer {
    meta:
        description = "Olympic Destroyer"
        severity = "critical"
    strings:
        $s1 = "OlympicDestroyer" ascii nocase
        $s2 = "Olympic" ascii nocase
        $wiper = "wipe" ascii nocase
        $evtlog = "evtlog" ascii nocase
        $wevtutil = "wevtutil" ascii nocase
        $shadow = "shadowcopy" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($s1 or ($s2 and any of ($wiper, $evtlog, $wevtutil, $shadow)))
}

rule Russian_WhisperGate {
    meta:
        description = "WhisperGate wiper"
        severity = "critical"
    strings:
        $s1 = "WhisperGate" ascii nocase
        $s2 = "WhisperKill" ascii nocase
        $mbr = "\\\\.\\\\" ascii
        $overwrite = { 00 00 00 00 00 00 00 00 }
        $ransom_fake = "ransom" ascii nocase
        $discord = "discord" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($s*) or ($mbr and $overwrite))
}

rule Russian_HermeticWiper {
    meta:
        description = "HermeticWiper"
        severity = "critical"
    strings:
        $s1 = "HermeticWiper" ascii nocase
        $s2 = "Hermetic" ascii nocase
        $driver = "epmntdrv.sys" ascii
        $driver2 = "empntdrv.sys" ascii
        $rawdisk = "RawDisk" ascii
        $wipe = "wipe" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($s*) or any of ($driver, $driver2, $rawdisk))
}

rule Russian_CaddyWiper {
    meta:
        description = "CaddyWiper"
        severity = "critical"
    strings:
        $s1 = "CaddyWiper" ascii nocase
        $dsquery = "dsquery" ascii
        $domain = "domain" ascii nocase
        $wipe = { 00 00 00 00 00 00 00 00 }
        $file_zero = "CreateFileW" ascii
    condition:
        uint16(0) == 0x5A4D and ($s1 or ($dsquery and $domain and $wipe))
}

rule Russian_IsaacWiper {
    meta:
        description = "IsaacWiper"
        severity = "critical"
    strings:
        $s1 = "IsaacWiper" ascii nocase
        $isaac = "ISAAC" ascii
        $random = "random" ascii nocase
        $wipe = "wipe" ascii nocase
        $overwrite = "overwrite" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($s1 or ($isaac and any of ($random, $wipe, $overwrite)))
}

rule Russian_DoubleZero {
    meta:
        description = "DoubleZero wiper"
        severity = "critical"
    strings:
        $s1 = "DoubleZero" ascii nocase
        $dotnet = "mscorlib" ascii
        $file = "File.Delete" ascii
        $reg = "RegistryKey" ascii
        $zero = { 00 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and ($s1 or ($dotnet and $file and $reg))
}

