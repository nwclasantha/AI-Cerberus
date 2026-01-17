/*
   YARA Rules for Government-Targeted APT Detection

   This file contains rules for detecting:
   - Government-targeted APT campaigns
   - Nation-state sponsored attacks
   - Cyber espionage against government entities
   - Critical infrastructure attacks
   - Diplomatic targeting malware

   These rules target advanced persistent threats aimed at government organizations
*/

rule GovAPT_Turla_Carbon
{
    meta:
        description = "Detects Turla Carbon backdoor targeting governments"
        severity = "critical"
        category = "government_apt"
        author = "MalwareAnalyzer"
        date = "2024-01-01"
        reference = "FSB-linked APT group"

    strings:
        $carbon1 = "carbon_system" ascii
        $carbon2 = "mini_http_server" ascii
        $carbon3 = "task_config" ascii
        $turla1 = "C:\\Users\\Public\\" ascii wide
        $turla2 = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
        $cmd1 = "cmd.exe /c" ascii
        $cmd2 = "ipconfig /all" ascii
        $mutex = "Global\\Carbon" ascii

    condition:
        uint16(0) == 0x5A4D and
        (2 of ($carbon*) and 1 of ($turla*)) or
        (1 of ($carbon*) and $mutex and 1 of ($cmd*))
}

rule GovAPT_APT29_CozyBear
{
    meta:
        description = "Detects APT29/Cozy Bear malware components"
        severity = "critical"
        category = "government_apt"
        author = "MalwareAnalyzer"
        reference = "SVR-linked APT group"

    strings:
        $cozy1 = "WellMess" ascii wide
        $cozy2 = "WellMail" ascii wide
        $cozy3 = "SoreFang" ascii wide
        $go_str = "main.main" ascii
        $go_str2 = "runtime.morestack" ascii
        $beacon1 = "POST /api/" ascii
        $beacon2 = "User-Agent:" ascii
        $gov1 = "government" ascii nocase
        $gov2 = "ministry" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        (1 of ($cozy*) and 1 of ($go_str*)) or
        (2 of ($beacon*) and 1 of ($gov*))
}

rule GovAPT_APT28_Sednit
{
    meta:
        description = "Detects APT28/Fancy Bear/Sednit malware"
        severity = "critical"
        category = "government_apt"
        author = "MalwareAnalyzer"
        reference = "GRU-linked APT group"

    strings:
        $sednit1 = "Sofacy" ascii wide nocase
        $sednit2 = "Sednit" ascii wide nocase
        $sednit3 = "X-Agent" ascii wide
        $zebrocy1 = "zebrocy" ascii nocase
        $zebrocy2 = "delphocy" ascii nocase
        $target1 = "NATO" ascii wide
        $target2 = "OSCE" ascii wide
        $target3 = "embassy" ascii wide nocase
        $c2 = { 68 74 74 70 73 3A 2F 2F }

    condition:
        uint16(0) == 0x5A4D and
        (2 of ($sednit*) or 1 of ($zebrocy*)) or
        (2 of ($target*) and $c2)
}

rule GovAPT_Equation_Group
{
    meta:
        description = "Detects Equation Group malware components"
        severity = "critical"
        category = "government_apt"
        author = "MalwareAnalyzer"
        reference = "NSA-linked threat actor"

    strings:
        $eq1 = "STRAITBIZARRE" ascii
        $eq2 = "BANANAGLEE" ascii
        $eq3 = "JETPLOW" ascii
        $eq4 = "ETERNALBLUE" ascii
        $firm1 = "firmware" ascii nocase
        $firm2 = "HDD" ascii
        $exploit1 = "SMBv1" ascii
        $exploit2 = "MS17-010" ascii

    condition:
        uint16(0) == 0x5A4D and
        (1 of ($eq*)) or
        (1 of ($firm*) and 1 of ($exploit*))
}

rule GovAPT_Diplomatic_Phishing
{
    meta:
        description = "Detects diplomatic-themed phishing malware"
        severity = "high"
        category = "government_phishing"
        author = "MalwareAnalyzer"

    strings:
        $diplo1 = "embassy" ascii wide nocase
        $diplo2 = "ambassador" ascii wide nocase
        $diplo3 = "diplomat" ascii wide nocase
        $diplo4 = "consulate" ascii wide nocase
        $ministry1 = "Ministry of Foreign" ascii wide nocase
        $ministry2 = "State Department" ascii wide nocase
        $doc1 = "document" ascii wide nocase
        $doc2 = "confidential" ascii wide nocase
        $macro = "AutoOpen" ascii

    condition:
        (2 of ($diplo*) and 1 of ($ministry*)) or
        (1 of ($diplo*) and 1 of ($doc*) and $macro)
}

rule GovAPT_MUDDYWATER
{
    meta:
        description = "Detects MuddyWater APT targeting government entities"
        severity = "critical"
        category = "government_apt"
        author = "MalwareAnalyzer"
        reference = "Iranian APT group"

    strings:
        $muddy1 = "POWERSTATS" ascii wide
        $muddy2 = "SHARPSTATS" ascii wide
        $muddy3 = "lazagne" ascii nocase
        $ps1 = "powershell" ascii nocase
        $ps2 = "-exec bypass" ascii nocase
        $ps3 = "IEX" ascii
        $target1 = "government" ascii nocase
        $target2 = "military" ascii nocase
        $b64 = "FromBase64String" ascii

    condition:
        (1 of ($muddy*) and 1 of ($ps*)) or
        (2 of ($ps*) and 1 of ($target*) and $b64)
}

rule GovAPT_SideWinder
{
    meta:
        description = "Detects SideWinder APT targeting government agencies"
        severity = "critical"
        category = "government_apt"
        author = "MalwareAnalyzer"
        reference = "India-linked APT group"

    strings:
        $sw1 = "SideWinder" ascii wide nocase
        $sw2 = "RattleSnake" ascii wide nocase
        $hta1 = "mshta.exe" ascii wide
        $hta2 = ".hta" ascii wide
        $lnk = ".lnk" ascii wide
        $target1 = "Pakistan" ascii wide
        $target2 = "China" ascii wide
        $gov = "ministry" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        (1 of ($sw*) and 1 of ($hta*)) or
        (1 of ($hta*) and $lnk and $gov)
}

rule GovAPT_Defense_Contractor_Attack
{
    meta:
        description = "Detects malware targeting defense contractors"
        severity = "critical"
        category = "government_defense"
        author = "MalwareAnalyzer"

    strings:
        $defense1 = "Lockheed" ascii wide nocase
        $defense2 = "Raytheon" ascii wide nocase
        $defense3 = "Northrop" ascii wide nocase
        $defense4 = "Boeing" ascii wide nocase
        $defense5 = "BAE Systems" ascii wide nocase
        $project1 = "classified" ascii wide nocase
        $project2 = "SECRET" ascii wide
        $project3 = "TOP SECRET" ascii wide
        $exfil1 = "upload" ascii nocase
        $exfil2 = "compress" ascii nocase

    condition:
        (2 of ($defense*) and 1 of ($project*)) or
        (1 of ($defense*) and 2 of ($project*) and 1 of ($exfil*))
}

rule GovAPT_Election_Infrastructure
{
    meta:
        description = "Detects attacks on election infrastructure"
        severity = "critical"
        category = "government_election"
        author = "MalwareAnalyzer"

    strings:
        $elect1 = "election" ascii wide nocase
        $elect2 = "voting" ascii wide nocase
        $elect3 = "ballot" ascii wide nocase
        $elect4 = "voter" ascii wide nocase
        $sys1 = "registration" ascii wide nocase
        $sys2 = "tabulation" ascii wide nocase
        $sys3 = "database" ascii wide nocase
        $attack1 = "SQL" ascii
        $attack2 = "inject" ascii nocase
        $target = "state" ascii wide nocase

    condition:
        (2 of ($elect*) and 1 of ($sys*) and 1 of ($attack*)) or
        (3 of ($elect*) and $target)
}

rule GovAPT_Intelligence_Collection
{
    meta:
        description = "Detects intelligence collection malware"
        severity = "critical"
        category = "government_espionage"
        author = "MalwareAnalyzer"

    strings:
        $intel1 = "intelligence" ascii wide nocase
        $intel2 = "CIA" ascii wide
        $intel3 = "NSA" ascii wide
        $intel4 = "FBI" ascii wide
        $collect1 = "keylog" ascii nocase
        $collect2 = "screenshot" ascii nocase
        $collect3 = "webcam" ascii nocase
        $collect4 = "microphone" ascii nocase
        $exfil = "exfiltrate" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        (2 of ($intel*) and 2 of ($collect*)) or
        (1 of ($intel*) and 3 of ($collect*) and $exfil)
}

rule GovAPT_Sandworm_Industroyer
{
    meta:
        description = "Detects Sandworm Industroyer malware"
        severity = "critical"
        category = "government_apt"
        author = "MalwareAnalyzer"
        reference = "GRU Unit 74455"

    strings:
        $ind1 = "Industroyer" ascii wide
        $ind2 = "CrashOverride" ascii wide
        $ics1 = "IEC 104" ascii
        $ics2 = "IEC 61850" ascii
        $ics3 = "OPC DA" ascii
        $wiper1 = "MBR" ascii
        $wiper2 = "wiper" ascii nocase
        $target = "grid" ascii wide nocase

    condition:
        (1 of ($ind*) and 1 of ($ics*)) or
        (2 of ($ics*) and 1 of ($wiper*))
}

rule GovAPT_Military_Targeting
{
    meta:
        description = "Detects malware targeting military organizations"
        severity = "critical"
        category = "government_military"
        author = "MalwareAnalyzer"

    strings:
        $mil1 = "military" ascii wide nocase
        $mil2 = "armed forces" ascii wide nocase
        $mil3 = "Pentagon" ascii wide
        $mil4 = "DoD" ascii wide
        $branch1 = "Army" ascii wide
        $branch2 = "Navy" ascii wide
        $branch3 = "Air Force" ascii wide
        $data1 = "deployment" ascii wide nocase
        $data2 = "operation" ascii wide nocase
        $data3 = "mission" ascii wide nocase

    condition:
        (2 of ($mil*) and 1 of ($branch*) and 1 of ($data*)) or
        (1 of ($mil*) and 2 of ($data*))
}

rule GovAPT_HAFNIUM_Exchange
{
    meta:
        description = "Detects HAFNIUM Exchange server exploitation"
        severity = "critical"
        category = "government_apt"
        author = "MalwareAnalyzer"
        reference = "Chinese APT targeting government Exchange servers"

    strings:
        $hafnium1 = "ProxyLogon" ascii wide
        $hafnium2 = "ProxyShell" ascii wide
        $webshell1 = "China Chopper" ascii
        $webshell2 = "<%@ Page Language" ascii
        $webshell3 = "eval(Request" ascii
        $path1 = "\\inetpub\\wwwroot\\" ascii wide
        $path2 = "\\Microsoft\\Exchange\\" ascii wide
        $aspx = ".aspx" ascii wide

    condition:
        (1 of ($hafnium*) and 1 of ($webshell*)) or
        (1 of ($path*) and $aspx and 1 of ($webshell*))
}

rule GovAPT_Law_Enforcement_Spyware
{
    meta:
        description = "Detects law enforcement targeting spyware"
        severity = "high"
        category = "government_surveillance"
        author = "MalwareAnalyzer"

    strings:
        $spy1 = "Pegasus" ascii wide
        $spy2 = "FinFisher" ascii wide
        $spy3 = "Predator" ascii wide
        $spy4 = "Candiru" ascii wide
        $cap1 = "GetMicrophoneAudio" ascii
        $cap2 = "GetWebcamVideo" ascii
        $cap3 = "GetKeystrokes" ascii
        $cap4 = "GetScreenshot" ascii
        $target1 = "journalist" ascii wide nocase
        $target2 = "activist" ascii wide nocase

    condition:
        (1 of ($spy*) and 2 of ($cap*)) or
        (3 of ($cap*) and 1 of ($target*))
}

rule GovAPT_Critical_Infrastructure
{
    meta:
        description = "Detects attacks on critical infrastructure"
        severity = "critical"
        category = "government_infrastructure"
        author = "MalwareAnalyzer"

    strings:
        $infra1 = "power grid" ascii wide nocase
        $infra2 = "water treatment" ascii wide nocase
        $infra3 = "nuclear" ascii wide nocase
        $infra4 = "dam" ascii wide nocase
        $scada1 = "SCADA" ascii wide
        $scada2 = "PLC" ascii wide
        $scada3 = "HMI" ascii wide
        $attack1 = "Triton" ascii wide
        $attack2 = "Stuxnet" ascii wide

    condition:
        (2 of ($infra*) and 1 of ($scada*)) or
        (1 of ($attack*) and 1 of ($infra*))
}

rule GovAPT_State_Secrets_Theft
{
    meta:
        description = "Detects state secrets exfiltration malware"
        severity = "critical"
        category = "government_espionage"
        author = "MalwareAnalyzer"

    strings:
        $class1 = "TOP SECRET" ascii wide
        $class2 = "SECRET" ascii wide
        $class3 = "CONFIDENTIAL" ascii wide
        $class4 = "NOFORN" ascii wide
        $class5 = "SCI" ascii wide
        $search1 = "FindFirstFile" ascii
        $search2 = ".doc" ascii wide nocase
        $search3 = ".pdf" ascii wide nocase
        $exfil = "upload" ascii nocase
        $encrypt = "AES" ascii

    condition:
        uint16(0) == 0x5A4D and
        (2 of ($class*) and 1 of ($search*) and $exfil) or
        (3 of ($class*) and $encrypt)
}

rule GovAPT_Cyber_Warfare_Tool
{
    meta:
        description = "Detects cyber warfare tools"
        severity = "critical"
        category = "government_cyberwar"
        author = "MalwareAnalyzer"

    strings:
        $war1 = "cyberwar" ascii wide nocase
        $war2 = "offensive" ascii wide nocase
        $war3 = "implant" ascii wide nocase
        $destroy1 = "wipe" ascii nocase
        $destroy2 = "destroy" ascii nocase
        $destroy3 = "corrupt" ascii nocase
        $persist1 = "firmware" ascii nocase
        $persist2 = "BIOS" ascii nocase
        $persist3 = "MBR" ascii

    condition:
        uint16(0) == 0x5A4D and
        (1 of ($war*) and 2 of ($destroy*)) or
        (1 of ($destroy*) and 1 of ($persist*))
}

rule GovAPT_Think_Tank_Target
{
    meta:
        description = "Detects malware targeting think tanks and NGOs"
        severity = "high"
        category = "government_research"
        author = "MalwareAnalyzer"

    strings:
        $org1 = "think tank" ascii wide nocase
        $org2 = "NGO" ascii wide
        $org3 = "foundation" ascii wide nocase
        $org4 = "institute" ascii wide nocase
        $topic1 = "policy" ascii wide nocase
        $topic2 = "foreign affairs" ascii wide nocase
        $topic3 = "geopolitical" ascii wide nocase
        $phish1 = "conference" ascii wide nocase
        $phish2 = "invitation" ascii wide nocase

    condition:
        (2 of ($org*) and 1 of ($topic*)) or
        (1 of ($org*) and 1 of ($phish*) and 1 of ($topic*))
}

rule GovAPT_Embassy_Implant
{
    meta:
        description = "Detects embassy network implants"
        severity = "critical"
        category = "government_diplomatic"
        author = "MalwareAnalyzer"

    strings:
        $emb1 = "embassy" ascii wide nocase
        $emb2 = "consulate" ascii wide nocase
        $emb3 = "diplomatic" ascii wide nocase
        $implant1 = "beacon" ascii nocase
        $implant2 = "callback" ascii nocase
        $implant3 = "heartbeat" ascii nocase
        $persist1 = "scheduled task" ascii nocase
        $persist2 = "registry" ascii nocase
        $covert = "encrypted" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        (2 of ($emb*) and 1 of ($implant*) and $covert) or
        (1 of ($emb*) and 2 of ($implant*) and 1 of ($persist*))
}
