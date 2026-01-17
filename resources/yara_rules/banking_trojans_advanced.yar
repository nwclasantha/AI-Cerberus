/*
    Advanced Banking Trojan Detection
    Modern banking malware, form grabbers, and financial threats
*/

rule Banking_Emotet {
    meta:
        description = "Emotet banking trojan/loader"
        severity = "critical"
    strings:
        $emotet = "Emotet" ascii nocase
        $heodo = "Heodo" ascii nocase
        $geodo = "Geodo" ascii nocase
        $epoch = "Epoch" ascii nocase
        $dll_export = "DllRegisterServer" ascii
        $cmd = "cmd.exe" ascii
        $ps = "powershell" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($emotet, $heodo, $geodo) or ($dll_export and any of ($cmd, $ps)))
}

rule Banking_TrickBot {
    meta:
        description = "TrickBot banking trojan"
        severity = "critical"
    strings:
        $trick = "TrickBot" ascii nocase
        $trick2 = "Trickster" ascii nocase
        $module1 = "injectDll" ascii
        $module2 = "systemInfo" ascii
        $module3 = "networkDll" ascii
        $module4 = "pwgrab" ascii
        $config = "<mcconf>" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($trick*) or (2 of ($module*)) or $config)
}

rule Banking_QakBot {
    meta:
        description = "QakBot/QBot banking trojan"
        severity = "critical"
    strings:
        $qak = "QakBot" ascii nocase
        $qbot = "QBot" ascii nocase
        $quakbot = "QuakBot" ascii nocase
        $pinkslip = "PinkSlip" ascii nocase
        $campaign = "campaign" ascii nocase
        $dll = "DllRegisterServer" ascii
        $export = "DllEntryPoint" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($qak, $qbot, $quakbot, $pinkslip))
}

rule Banking_IcedID {
    meta:
        description = "IcedID/BokBot banking trojan"
        severity = "critical"
    strings:
        $icedid = "IcedID" ascii nocase
        $bokbot = "BokBot" ascii nocase
        $loader = "loader" ascii nocase
        $hook = "hook" ascii nocase
        $ssl = "ssl" ascii nocase
        $browser = "browser" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($icedid, $bokbot))
}

rule Banking_Dridex {
    meta:
        description = "Dridex banking trojan"
        severity = "critical"
    strings:
        $dridex = "Dridex" ascii nocase
        $bugat = "Bugat" ascii nocase
        $cridex = "Cridex" ascii nocase
        $botnet = "botnet" ascii nocase
        $config = "config" ascii nocase
        $inject = "inject" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($dridex, $bugat, $cridex))
}

rule Banking_Zeus_Variants {
    meta:
        description = "Zeus banking trojan variants"
        severity = "critical"
    strings:
        $zeus = "Zeus" ascii nocase
        $zbot = "Zbot" ascii nocase
        $citadel = "Citadel" ascii nocase
        $ice_ix = "ICE IX" ascii nocase
        $config = "local.ds" ascii
        $webinject = "webinject" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($zeus, $zbot, $citadel, $ice_ix) or ($config and $webinject))
}

rule Banking_Ursnif_Gozi {
    meta:
        description = "Ursnif/Gozi banking trojan"
        severity = "critical"
    strings:
        $ursnif = "Ursnif" ascii nocase
        $gozi = "Gozi" ascii nocase
        $isfb = "ISFB" ascii nocase
        $dreambot = "Dreambot" ascii nocase
        $client32 = "client32" ascii
        $serpent = "serpent" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($ursnif, $gozi, $isfb, $dreambot))
}

rule Banking_Tinba {
    meta:
        description = "Tinba/TinyBanker"
        severity = "critical"
    strings:
        $tinba = "Tinba" ascii nocase
        $tiny = "TinyBanker" ascii nocase
        $kins = "Kins" ascii nocase
        $zusy = "Zusy" ascii nocase
        $small = "small" ascii nocase
        $inject = "inject" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($tinba, $tiny, $kins, $zusy))
}

rule Banking_Vawtrak {
    meta:
        description = "Vawtrak/Neverquest"
        severity = "critical"
    strings:
        $vawtrak = "Vawtrak" ascii nocase
        $neverquest = "Neverquest" ascii nocase
        $snifula = "Snifula" ascii nocase
        $inject = "inject" ascii nocase
        $form = "form" ascii nocase
        $grab = "grab" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($vawtrak, $neverquest, $snifula))
}

rule Banking_Kronos {
    meta:
        description = "Kronos banking trojan"
        severity = "critical"
    strings:
        $kronos = "Kronos" ascii nocase
        $osiris = "Osiris" ascii nocase
        $form = "formgrabber" ascii nocase
        $webinject = "webinject" ascii nocase
        $vnc = "VNC" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($kronos, $osiris) or ($form and $webinject))
}

rule Banking_Panda_Banker {
    meta:
        description = "Panda Banker/Zeus Panda"
        severity = "critical"
    strings:
        $panda = "Panda" ascii nocase
        $zeus = "Zeus" ascii nocase
        $banker = "Banker" ascii nocase
        $webinject = "webinject" ascii nocase
        $form = "form" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($panda and ($zeus or $banker))
}

rule Banking_Ramnit {
    meta:
        description = "Ramnit banking worm"
        severity = "critical"
    strings:
        $ramnit = "Ramnit" ascii nocase
        $nimnul = "Nimnul" ascii nocase
        $worm = "worm" ascii nocase
        $ftp = "FTP" ascii
        $grab = "grab" ascii nocase
        $cookie = "cookie" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($ramnit, $nimnul))
}

rule Banking_Shylock {
    meta:
        description = "Shylock banking trojan"
        severity = "critical"
    strings:
        $shylock = "Shylock" ascii nocase
        $caphaw = "Caphaw" ascii nocase
        $skype = "Skype" ascii
        $spread = "spread" ascii nocase
        $hook = "hook" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($shylock, $caphaw))
}

rule Banking_Sphinx {
    meta:
        description = "Sphinx banking trojan"
        severity = "critical"
    strings:
        $sphinx = "Sphinx" ascii nocase
        $zloader = "ZLoader" ascii nocase
        $zeus = "Zeus" ascii nocase
        $webinject = "webinject" ascii nocase
        $grab = "grab" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($sphinx, $zloader))
}

rule Banking_Webinject {
    meta:
        description = "Web injection framework"
        severity = "high"
    strings:
        $webinject = "webinject" ascii nocase
        $inject = "inject" ascii nocase
        $set_url = "set_url" ascii
        $data_before = "data_before" ascii
        $data_after = "data_after" ascii
        $data_inject = "data_inject" ascii
    condition:
        uint16(0) == 0x5A4D and ($webinject or (2 of ($set_url, $data_before, $data_after, $data_inject)))
}

rule Banking_FormGrabber {
    meta:
        description = "Form grabbing functionality"
        severity = "high"
    strings:
        $form = "form" ascii nocase
        $grab = "grab" ascii nocase
        $hook = "hook" ascii nocase
        $http = "HTTP" ascii
        $post = "POST" ascii
        $ssl = "SSL" ascii
        $intercept = "intercept" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($form and $grab) and (any of ($hook, $http, $post, $ssl, $intercept))
}

rule Banking_Man_in_Browser {
    meta:
        description = "Man-in-the-Browser attack"
        severity = "critical"
    strings:
        $mitb = "MitB" ascii
        $browser = "browser" ascii nocase
        $hook = "hook" ascii nocase
        $inject = "inject" ascii nocase
        $chrome = "chrome" ascii nocase
        $firefox = "firefox" ascii nocase
        $ie = "iexplore" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($mitb or ($browser and $hook and $inject))
}

rule Banking_ATS_Engine {
    meta:
        description = "Automated Transfer System"
        severity = "critical"
    strings:
        $ats = "ATS" ascii
        $transfer = "transfer" ascii nocase
        $automated = "automated" ascii nocase
        $account = "account" ascii nocase
        $balance = "balance" ascii nocase
        $amount = "amount" ascii nocase
        $replace = "replace" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (($ats and $transfer) or (3 of ($account, $balance, $amount, $replace)))
}

rule Banking_POS_Malware {
    meta:
        description = "Point-of-Sale malware"
        severity = "critical"
    strings:
        $pos = "POS" ascii
        $track1 = "Track1" ascii
        $track2 = "Track2" ascii
        $pan = "PAN" ascii
        $magstripe = "magstripe" ascii nocase
        $ram = "RAM" ascii
        $scrape = "scrape" ascii nocase
        $card = "card" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (($pos and any of ($track1, $track2, $pan)) or ($ram and $scrape and $card))
}

rule Banking_ATM_Malware {
    meta:
        description = "ATM malware"
        severity = "critical"
    strings:
        $atm = "ATM" ascii
        $xfs = "XFS" ascii
        $cen = "CEN/XFS" ascii
        $dispenser = "dispenser" ascii nocase
        $cassette = "cassette" ascii nocase
        $cash = "cash" ascii nocase
        $jackpot = "jackpot" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (($atm or $xfs or $cen) and any of ($dispenser, $cassette, $cash, $jackpot))
}

