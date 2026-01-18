/*
    Social Engineering Tools Detection
    Phishing kits, credential harvesters, and social engineering frameworks
*/

rule SocialEng_Gophish {
    meta:
        description = "Gophish phishing framework"
        severity = "high"
    strings:
        $s1 = "gophish" ascii nocase
        $s2 = "Gophish" ascii
        $campaign = "campaign" ascii nocase
        $template = "template" ascii nocase
        $landing = "landing" ascii nocase
        $smtp = "SMTP" ascii
    condition:
        (any of ($s*)) and any of ($campaign, $template, $landing, $smtp)
}

rule SocialEng_SET {
    meta:
        description = "Social Engineering Toolkit"
        severity = "high"
    strings:
        $set = "Social-Engineer Toolkit" ascii nocase
        $setoolkit = "setoolkit" ascii nocase
        $trustedsec = "TrustedSec" ascii nocase
        $phish = "phish" ascii nocase
        $credential = "credential" ascii nocase
    condition:
        (any of ($set, $setoolkit, $trustedsec)) and any of ($phish, $credential)
}

rule SocialEng_Evilginx {
    meta:
        description = "Evilginx2 phishing proxy"
        severity = "critical"
    strings:
        $s1 = "evilginx" ascii nocase
        $s2 = "Evilginx2" ascii nocase
        $phishlet = "phishlet" ascii nocase
        $session = "session" ascii nocase
        $token = "token" ascii nocase
        $2fa = "2FA" ascii
    condition:
        (any of ($s*)) or ($phishlet and any of ($session, $token, $2fa))
}

rule SocialEng_Modlishka {
    meta:
        description = "Modlishka reverse proxy phishing"
        severity = "critical"
    strings:
        $s1 = "Modlishka" ascii nocase
        $s2 = "modlishka" ascii nocase
        $proxy = "proxy" ascii nocase
        $intercept = "intercept" ascii nocase
        $credential = "credential" ascii nocase
    condition:
        (any of ($s*)) and any of ($proxy, $intercept, $credential)
}

rule SocialEng_King_Phisher {
    meta:
        description = "King Phisher phishing campaign"
        severity = "high"
    strings:
        $s1 = "King Phisher" ascii nocase
        $s2 = "kingphisher" ascii nocase
        $campaign = "campaign" ascii nocase
        $email = "email" ascii nocase
        $template = "template" ascii nocase
    condition:
        (any of ($s*)) and any of ($campaign, $email, $template)
}

rule SocialEng_Credential_Harvester {
    meta:
        description = "Credential harvesting page"
        severity = "critical"
    strings:
        $form = "<form" ascii nocase
        $input = "<input" ascii nocase
        $password = "password" ascii nocase
        $login = "login" ascii nocase
        $submit = "submit" ascii nocase
        $action = "action=" ascii nocase
        $post = "POST" ascii
    condition:
        $form and $input and $password and ($login or $submit) and any of ($action, $post)
}

rule SocialEng_Fake_Login {
    meta:
        description = "Fake login page"
        severity = "critical"
    strings:
        $microsoft = "Microsoft" ascii nocase
        $google = "Google" ascii nocase
        $facebook = "Facebook" ascii nocase
        $apple = "Apple" ascii nocase
        $login = "login" ascii nocase
        $signin = "sign in" ascii nocase
        $password = "password" ascii nocase
        // UNUSED: $fake = "fake" ascii nocase
    condition:
        (any of ($microsoft, $google, $facebook, $apple)) and (any of ($login, $signin)) and $password
}

rule SocialEng_Office365_Phish {
    meta:
        description = "Office 365 phishing page"
        severity = "critical"
    strings:
        $o365 = "Office 365" ascii nocase
        $microsoft = "Microsoft" ascii nocase
        $outlook = "Outlook" ascii nocase
        $login = "login" ascii nocase
        $password = "password" ascii nocase
        // UNUSED: $phish = "phish" ascii nocase
        // UNUSED: $harvest = "harvest" ascii nocase
    condition:
        (any of ($o365, $microsoft, $outlook)) and ($login and $password)
}

rule SocialEng_QR_Phishing {
    meta:
        description = "QR code phishing"
        severity = "high"
    strings:
        $qr = "QR" ascii
        $code = "code" ascii nocase
        $phish = "phish" ascii nocase
        $scan = "scan" ascii nocase
        $link = "link" ascii nocase
        $redirect = "redirect" ascii nocase
    condition:
        ($qr and $code) and any of ($phish, $scan, $link, $redirect)
}

rule SocialEng_USB_Drop {
    meta:
        description = "USB drop attack tool"
        severity = "high"
    strings:
        $usb = "USB" ascii
        $drop = "drop" ascii nocase
        $rubber = "Rubber Ducky" ascii nocase
        $badusb = "BadUSB" ascii nocase
        $hid = "HID" ascii
        $payload = "payload" ascii nocase
    condition:
        $usb and ($drop or any of ($rubber, $badusb, $hid, $payload))
}

rule SocialEng_Vishing_Tool {
    meta:
        description = "Voice phishing tool"
        severity = "high"
    strings:
        $vish = "vishing" ascii nocase
        $voice = "voice" ascii nocase
        $phone = "phone" ascii nocase
        $call = "call" ascii nocase
        $spoof = "spoof" ascii nocase
        $social = "social" ascii nocase
    condition:
        ($vish or ($voice and $phone)) and any of ($call, $spoof, $social)
}

rule SocialEng_SMS_Phishing {
    meta:
        description = "SMS phishing (smishing)"
        severity = "high"
    strings:
        $smish = "smishing" ascii nocase
        $sms = "SMS" ascii
        $text = "text" ascii nocase
        $phish = "phish" ascii nocase
        $link = "link" ascii nocase
        $send = "send" ascii nocase
    condition:
        ($smish or ($sms and $phish)) and any of ($text, $link, $send)
}

rule SocialEng_Clone_Site {
    meta:
        description = "Website cloning tool"
        severity = "high"
    strings:
        $clone = "clone" ascii nocase
        $mirror = "mirror" ascii nocase
        $website = "website" ascii nocase
        $httrack = "httrack" ascii nocase
        $wget = "wget" ascii nocase
        $copy = "copy" ascii nocase
    condition:
        (any of ($clone, $mirror)) and ($website or any of ($httrack, $wget, $copy))
}

rule SocialEng_Browser_Hook {
    meta:
        description = "Browser hooking framework"
        severity = "critical"
    strings:
        $beef = "BeEF" ascii nocase
        $browser = "browser" ascii nocase
        $hook = "hook" ascii nocase
        $exploit = "exploit" ascii nocase
        $framework = "framework" ascii nocase
        $zombie = "zombie" ascii nocase
    condition:
        $beef or (($browser and $hook) and any of ($exploit, $framework, $zombie))
}

rule SocialEng_Fake_Update {
    meta:
        description = "Fake software update"
        severity = "high"
    strings:
        $update = "update" ascii nocase
        $download = "download" ascii nocase
        $flash = "Flash" ascii nocase
        $java = "Java" ascii nocase
        $chrome = "Chrome" ascii nocase
        $fake = "fake" ascii nocase
        $urgent = "urgent" ascii nocase
    condition:
        $update and $download and (any of ($flash, $java, $chrome) or any of ($fake, $urgent))
}

rule SocialEng_Tech_Support_Scam {
    meta:
        description = "Tech support scam"
        severity = "high"
    strings:
        $support = "tech support" ascii nocase
        $call = "call" ascii nocase
        $microsoft = "Microsoft" ascii nocase
        $virus = "virus" ascii nocase
        $infected = "infected" ascii nocase
        $warning = "warning" ascii nocase
    condition:
        $support and ($call or any of ($microsoft, $virus, $infected, $warning))
}

rule SocialEng_Pretexting {
    meta:
        description = "Pretexting attack indicators"
        severity = "medium"
    strings:
        $pretext = "pretext" ascii nocase
        $impersonate = "impersonate" ascii nocase
        $scenario = "scenario" ascii nocase
        $trust = "trust" ascii nocase
        $verify = "verify" ascii nocase
        $urgent = "urgent" ascii nocase
    condition:
        ($pretext or $impersonate) and any of ($scenario, $trust, $verify, $urgent)
}

rule SocialEng_Watering_Hole {
    meta:
        description = "Watering hole attack setup"
        severity = "critical"
    strings:
        $watering = "watering hole" ascii nocase
        $compromise = "compromise" ascii nocase
        $website = "website" ascii nocase
        $inject = "inject" ascii nocase
        $target = "target" ascii nocase
        $visitor = "visitor" ascii nocase
    condition:
        $watering or (($compromise and $website) and any of ($inject, $target, $visitor))
}

rule SocialEng_Callback_Phishing {
    meta:
        description = "Callback phishing attack"
        severity = "high"
    strings:
        $callback = "callback" ascii nocase
        $phish = "phish" ascii nocase
        $bazarcall = "BazarCall" ascii nocase
        $invoice = "invoice" ascii nocase
        $subscription = "subscription" ascii nocase
        $cancel = "cancel" ascii nocase
    condition:
        ($callback and $phish) or $bazarcall or (($invoice or $subscription) and $cancel)
}

rule SocialEng_MFA_Fatigue {
    meta:
        description = "MFA fatigue attack"
        severity = "critical"
    strings:
        $mfa = "MFA" ascii
        $2fa = "2FA" ascii
        $fatigue = "fatigue" ascii nocase
        $push = "push" ascii nocase
        $spam = "spam" ascii nocase
        $approve = "approve" ascii nocase
        $bomb = "bomb" ascii nocase
    condition:
        (any of ($mfa, $2fa)) and (any of ($fatigue, $spam, $bomb)) and any of ($push, $approve)
}

