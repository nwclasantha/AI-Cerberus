/*
    Adware and Potentially Unwanted Programs (PUP) Detection
    Bundleware, browser hijackers, and unwanted software
*/

rule Adware_Generic_Indicators {
    meta:
        description = "Generic adware indicators"
        severity = "medium"
    strings:
        $ad1 = "advertisement" ascii nocase
        $ad2 = "advert" ascii nocase
        $ad3 = "sponsor" ascii nocase
        $inject = "inject" ascii nocase
        $browser = "browser" ascii nocase
        $popup = "popup" ascii nocase
        $banner = "banner" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($ad*)) and any of ($inject, $browser, $popup, $banner)
}

rule Adware_Browser_Hijacker {
    meta:
        description = "Browser hijacker"
        severity = "high"
    strings:
        $home = "homepage" ascii nocase
        $search = "search engine" ascii nocase
        $default = "default" ascii nocase
        $change = "change" ascii nocase
        $chrome = "Chrome" ascii nocase
        $firefox = "Firefox" ascii nocase
        $ie = "Internet Explorer" ascii nocase
        $edge = "Edge" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($home or $search) and $default and $change and any of ($chrome, $firefox, $ie, $edge)
}

rule Adware_Toolbar {
    meta:
        description = "Unwanted toolbar installation"
        severity = "medium"
    strings:
        $toolbar = "toolbar" ascii nocase
        $addon = "addon" ascii nocase
        $extension = "extension" ascii nocase
        $install = "install" ascii nocase
        $browser = "browser" ascii nocase
        $helper = "BHO" ascii
    condition:
        uint16(0) == 0x5A4D and ($toolbar or $helper) and any of ($addon, $extension, $install, $browser)
}

rule Adware_Ask_Toolbar {
    meta:
        description = "Ask Toolbar adware"
        severity = "medium"
    strings:
        $s1 = "Ask Toolbar" ascii nocase
        $s2 = "ask.com" ascii nocase
        $s3 = "AskTBar" ascii nocase
        $search = "search" ascii nocase
        $partner = "partner" ascii nocase
    condition:
        (any of ($s*)) and any of ($search, $partner)
}

rule Adware_Conduit {
    meta:
        description = "Conduit Search adware"
        severity = "medium"
    strings:
        $s1 = "Conduit" ascii nocase
        $s2 = "conduit.com" ascii nocase
        $search = "search" ascii nocase
        $toolbar = "toolbar" ascii nocase
        $protect = "Search Protect" ascii nocase
    condition:
        (any of ($s*)) and any of ($search, $toolbar, $protect)
}

rule Adware_Superfish {
    meta:
        description = "Superfish adware"
        severity = "high"
    strings:
        $s1 = "Superfish" ascii nocase
        $s2 = "VisualDiscovery" ascii nocase
        $ssl = "SSL" ascii
        $mitm = "certificate" ascii nocase
        $inject = "inject" ascii nocase
    condition:
        (any of ($s*)) and any of ($ssl, $mitm, $inject)
}

rule Adware_Mindspark {
    meta:
        description = "Mindspark adware"
        severity = "medium"
    strings:
        $s1 = "Mindspark" ascii nocase
        $s2 = "mindspark.com" ascii nocase
        $toolbar = "toolbar" ascii nocase
        $search = "search" ascii nocase
        $iac = "IAC" ascii
    condition:
        (any of ($s*)) and any of ($toolbar, $search, $iac)
}

rule Adware_Bundleware {
    meta:
        description = "Bundleware installer"
        severity = "medium"
    strings:
        $bundle = "bundle" ascii nocase
        $offer = "offer" ascii nocase
        $partner = "partner" ascii nocase
        $install = "install" ascii nocase
        $optional = "optional" ascii nocase
        $recommend = "recommend" ascii nocase
        $accept = "accept" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($bundle or ($offer and $partner)) and any of ($install, $optional, $recommend, $accept)
}

rule Adware_ClickOnce_Abuse {
    meta:
        description = "ClickOnce deployment abuse"
        severity = "medium"
    strings:
        $clickonce = "ClickOnce" ascii nocase
        $deploy = ".application" ascii
        $manifest = "deployment" ascii nocase
        $auto = "autoUpdate" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($clickonce or $deploy) and any of ($manifest, $auto)
}

rule PUP_System_Optimizer {
    meta:
        description = "Fake system optimizer"
        severity = "medium"
    strings:
        $opt1 = "optimizer" ascii nocase
        $opt2 = "speed up" ascii nocase
        $opt3 = "clean" ascii nocase
        $reg = "registry" ascii nocase
        $fix = "fix" ascii nocase
        $error = "error" ascii nocase
        $scan = "scan" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($opt*)) and ($reg or any of ($fix, $error, $scan))
}

rule PUP_Driver_Updater {
    meta:
        description = "Potentially unwanted driver updater"
        severity = "medium"
    strings:
        $driver = "driver" ascii nocase
        $update = "update" ascii nocase
        $scan = "scan" ascii nocase
        $outdated = "outdated" ascii nocase
        $install = "install" ascii nocase
    condition:
        uint16(0) == 0x5A4D and $driver and $update and any of ($scan, $outdated, $install)
}

rule PUP_Fake_Antivirus {
    meta:
        description = "Fake antivirus/scareware"
        severity = "high"
    strings:
        $av = "antivirus" ascii nocase
        $scan = "scan" ascii nocase
        $threat = "threat" ascii nocase
        $infect = "infected" ascii nocase
        $clean = "clean" ascii nocase
        $buy = "buy" ascii nocase
        $activate = "activate" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($av and $scan and any of ($threat, $infect)) and any of ($buy, $activate, $clean)
}

rule Adware_PopUp_Generator {
    meta:
        description = "Pop-up ad generator"
        severity = "medium"
    strings:
        $popup = "popup" ascii nocase
        $pop = "pop-up" ascii nocase
        $window = "window.open" ascii nocase
        $ad = "advertisement" ascii nocase
        $show = "show" ascii nocase
        $display = "display" ascii nocase
    condition:
        (any of ($popup, $pop, $window)) and any of ($ad, $show, $display)
}

rule Adware_Affiliate_Fraud {
    meta:
        description = "Affiliate fraud software"
        severity = "high"
    strings:
        $affiliate = "affiliate" ascii nocase
        $referral = "referral" ascii nocase
        $click = "click" ascii nocase
        $inject = "inject" ascii nocase
        $cookie = "cookie" ascii nocase
        $replace = "replace" ascii nocase
    condition:
        ($affiliate or $referral) and $click and any of ($inject, $cookie, $replace)
}

rule PUP_Registry_Cleaner {
    meta:
        description = "Potentially unwanted registry cleaner"
        severity = "low"
    strings:
        $reg = "registry" ascii nocase
        $clean = "clean" ascii nocase
        $fix = "fix" ascii nocase
        $error = "error" ascii nocase
        $invalid = "invalid" ascii nocase
        $orphan = "orphan" ascii nocase
    condition:
        uint16(0) == 0x5A4D and $reg and ($clean or $fix) and any of ($error, $invalid, $orphan)
}

rule Adware_DNS_Changer {
    meta:
        description = "DNS changer adware"
        severity = "high"
    strings:
        $dns = "DNS" ascii
        $change = "change" ascii nocase
        $server = "server" ascii nocase
        $nameserver = "nameserver" ascii nocase
        $redirect = "redirect" ascii nocase
    condition:
        uint16(0) == 0x5A4D and $dns and ($change or $nameserver) and any of ($server, $redirect)
}

rule PUP_Cryptominer_Hidden {
    meta:
        description = "Hidden cryptominer PUP"
        severity = "high"
    strings:
        $miner = "miner" ascii nocase
        $crypto = "crypto" ascii nocase
        $monero = "monero" ascii nocase
        $coinhive = "coinhive" ascii nocase
        $hidden = "hidden" ascii nocase
        $background = "background" ascii nocase
    condition:
        (any of ($miner, $crypto, $monero, $coinhive)) and any of ($hidden, $background)
}

rule Adware_Proxy_Injector {
    meta:
        description = "Proxy injection adware"
        severity = "high"
    strings:
        $proxy = "proxy" ascii nocase
        $inject = "inject" ascii nocase
        $traffic = "traffic" ascii nocase
        $intercept = "intercept" ascii nocase
        $ssl = "SSL" ascii
        $mitm = "man-in-the-middle" ascii nocase
    condition:
        uint16(0) == 0x5A4D and $proxy and ($inject or $intercept) and any of ($traffic, $ssl, $mitm)
}

rule PUP_Tech_Support_Scam {
    meta:
        description = "Tech support scam software"
        severity = "high"
    strings:
        $support = "support" ascii nocase
        $call = "call" ascii nocase
        $phone = "phone" ascii nocase
        $microsoft = "Microsoft" ascii nocase
        $virus = "virus" ascii nocase
        $error = "error" ascii nocase
        $lock = "lock" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($support and $call) and any of ($microsoft, $virus, $error, $lock)
}

rule Adware_Search_Redirect {
    meta:
        description = "Search redirect adware"
        severity = "medium"
    strings:
        $search = "search" ascii nocase
        $redirect = "redirect" ascii nocase
        $query = "query" ascii nocase
        $google = "google" ascii nocase
        $bing = "bing" ascii nocase
        $yahoo = "yahoo" ascii nocase
        $partner = "partner" ascii nocase
    condition:
        uint16(0) == 0x5A4D and $search and $redirect and ($query or any of ($google, $bing, $yahoo, $partner))
}

