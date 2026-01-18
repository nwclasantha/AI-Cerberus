/*
    Spyware and Surveillance Software Detection
    Commercial spyware, stalkerware, and surveillance tools
*/

rule Spyware_Commercial_Generic {
    meta:
        description = "Generic commercial spyware"
        severity = "critical"
    strings:
        $spy = "spy" ascii nocase
        $monitor = "monitor" ascii nocase
        $track = "track" ascii nocase
        $stealth = "stealth" ascii nocase
        $hidden = "hidden" ascii nocase
        $invisible = "invisible" ascii nocase
        $parental = "parental" ascii nocase
        $employee = "employee" ascii nocase
    condition:
        (any of ($spy, $monitor, $track)) and (any of ($stealth, $hidden, $invisible)) or (any of ($parental, $employee) and any of ($monitor, $track))
}

rule Spyware_FlexiSpy {
    meta:
        description = "FlexiSpy commercial spyware"
        severity = "critical"
    strings:
        $flexispy = "FlexiSpy" ascii nocase
        $flexi = "Flexi" ascii nocase
        $call = "call" ascii nocase
        $record = "record" ascii nocase
        $sms = "SMS" ascii
        $gps = "GPS" ascii
        $ambient = "ambient" ascii nocase
    condition:
        $flexispy or ($flexi and (2 of ($call, $record, $sms, $gps, $ambient)))
}

rule Spyware_mSpy {
    meta:
        description = "mSpy monitoring software"
        severity = "critical"
    strings:
        $mspy = "mSpy" ascii nocase
        $monitor = "monitor" ascii nocase
        $phone = "phone" ascii nocase
        $track = "track" ascii nocase
        $keylog = "keylog" ascii nocase
        $social = "social" ascii nocase
    condition:
        $mspy or ($monitor and $phone and any of ($track, $keylog, $social))
}

rule Spyware_Spyera {
    meta:
        description = "Spyera surveillance software"
        severity = "critical"
    strings:
        $spyera = "Spyera" ascii nocase
        $spy = "spy" ascii nocase
        $phone = "phone" ascii nocase
        $call = "call" ascii nocase
        $intercept = "intercept" ascii nocase
        $live = "live" ascii nocase
    condition:
        $spyera or ($spy and $phone and any of ($call, $intercept, $live))
}

rule Spyware_Cocospy {
    meta:
        description = "Cocospy monitoring app"
        severity = "critical"
    strings:
        $cocospy = "Cocospy" ascii nocase
        $coco = "Coco" ascii nocase
        $spy = "spy" ascii nocase
        $location = "location" ascii nocase
        $track = "track" ascii nocase
        $stealth = "stealth" ascii nocase
    condition:
        $cocospy or ($coco and $spy and any of ($location, $track, $stealth))
}

rule Spyware_Hoverwatch {
    meta:
        description = "Hoverwatch phone tracker"
        severity = "critical"
    strings:
        $hoverwatch = "Hoverwatch" ascii nocase
        $hover = "Hover" ascii nocase
        $watch = "watch" ascii nocase
        $track = "track" ascii nocase
        $invisible = "invisible" ascii nocase
        $sms = "SMS" ascii
    condition:
        $hoverwatch or ($hover and $watch and any of ($track, $invisible, $sms))
}

rule Spyware_XNSPY {
    meta:
        description = "XNSPY monitoring software"
        severity = "critical"
    strings:
        $xnspy = "XNSPY" ascii nocase
        $monitor = "monitor" ascii nocase
        $control = "control" ascii nocase
        $remote = "remote" ascii nocase
        $record = "record" ascii nocase
        $surround = "surround" ascii nocase
    condition:
        $xnspy or ($monitor and $remote and any of ($control, $record, $surround))
}

rule Spyware_iKeyMonitor {
    meta:
        description = "iKeyMonitor keylogger"
        severity = "critical"
    strings:
        $ikeymonitor = "iKeyMonitor" ascii nocase
        $ikey = "iKey" ascii nocase
        $keylog = "keylog" ascii nocase
        $monitor = "monitor" ascii nocase
        $screenshot = "screenshot" ascii nocase
        $app = "app" ascii nocase
    condition:
        $ikeymonitor or ($ikey and $keylog and any of ($monitor, $screenshot, $app))
}

rule Spyware_Stalkerware_Generic {
    meta:
        description = "Generic stalkerware indicators"
        severity = "critical"
    strings:
        $stalker = "stalker" ascii nocase
        $track = "track" ascii nocase
        $location = "location" ascii nocase
        $gps = "GPS" ascii
        $hidden = "hidden" ascii nocase
        $stealth = "stealth" ascii nocase
        $partner = "partner" ascii nocase
        $spouse = "spouse" ascii nocase
    condition:
        $stalker or (($track or $location or $gps) and (any of ($hidden, $stealth)) and any of ($partner, $spouse))
}

rule Spyware_Screen_Recorder {
    meta:
        description = "Covert screen recorder"
        severity = "high"
    strings:
        $screen = "screen" ascii nocase
        $record = "record" ascii nocase
        // UNUSED: $capture = "capture" ascii nocase
        $hidden = "hidden" ascii nocase
        $stealth = "stealth" ascii nocase
        $background = "background" ascii nocase
        $auto = "auto" ascii nocase
    condition:
        ($screen and $record) and (any of ($hidden, $stealth, $background)) and $auto
}

rule Spyware_Microphone_Spy {
    meta:
        description = "Covert microphone recording"
        severity = "critical"
    strings:
        $mic = "microphone" ascii nocase
        $audio = "audio" ascii nocase
        $record = "record" ascii nocase
        $ambient = "ambient" ascii nocase
        $surround = "surround" ascii nocase
        $hidden = "hidden" ascii nocase
        $stealth = "stealth" ascii nocase
    condition:
        (any of ($mic, $audio)) and $record and (any of ($ambient, $surround, $hidden, $stealth))
}

rule Spyware_Camera_Spy {
    meta:
        description = "Covert camera recording"
        severity = "critical"
    strings:
        $camera = "camera" ascii nocase
        $webcam = "webcam" ascii nocase
        $photo = "photo" ascii nocase
        $video = "video" ascii nocase
        $hidden = "hidden" ascii nocase
        $stealth = "stealth" ascii nocase
        $remote = "remote" ascii nocase
    condition:
        (any of ($camera, $webcam)) and (any of ($photo, $video)) and (any of ($hidden, $stealth, $remote))
}

rule Spyware_Browser_Monitor {
    meta:
        description = "Browser monitoring spyware"
        severity = "high"
    strings:
        $browser = "browser" ascii nocase
        $history = "history" ascii nocase
        $bookmark = "bookmark" ascii nocase
        $cookie = "cookie" ascii nocase
        $monitor = "monitor" ascii nocase
        $track = "track" ascii nocase
        $password = "password" ascii nocase
    condition:
        $browser and ($history or $bookmark or $cookie) and (any of ($monitor, $track, $password))
}

rule Spyware_Social_Media_Monitor {
    meta:
        description = "Social media monitoring"
        severity = "high"
    strings:
        $facebook = "Facebook" ascii nocase
        $instagram = "Instagram" ascii nocase
        $whatsapp = "WhatsApp" ascii nocase
        $snapchat = "Snapchat" ascii nocase
        $tiktok = "TikTok" ascii nocase
        $monitor = "monitor" ascii nocase
        $track = "track" ascii nocase
        $spy = "spy" ascii nocase
    condition:
        (2 of ($facebook, $instagram, $whatsapp, $snapchat, $tiktok)) and (any of ($monitor, $track, $spy))
}

rule Spyware_Email_Monitor {
    meta:
        description = "Email monitoring spyware"
        severity = "high"
    strings:
        $email = "email" ascii nocase
        $gmail = "Gmail" ascii nocase
        $outlook = "Outlook" ascii nocase
        $inbox = "inbox" ascii nocase
        $monitor = "monitor" ascii nocase
        $track = "track" ascii nocase
        $forward = "forward" ascii nocase
    condition:
        (any of ($email, $gmail, $outlook)) and ($inbox or any of ($monitor, $track, $forward))
}

rule Spyware_Location_Tracker {
    meta:
        description = "Location tracking spyware"
        severity = "high"
    strings:
        $location = "location" ascii nocase
        $gps = "GPS" ascii
        $track = "track" ascii nocase
        $geofence = "geofence" ascii nocase
        $history = "history" ascii nocase
        $real_time = "real-time" ascii nocase
        $live = "live" ascii nocase
    condition:
        ($location or $gps) and ($track or $geofence) and (any of ($history, $real_time, $live))
}

rule Spyware_Call_Recorder {
    meta:
        description = "Call recording spyware"
        severity = "critical"
    strings:
        $call = "call" ascii nocase
        $record = "record" ascii nocase
        $intercept = "intercept" ascii nocase
        $voice = "voice" ascii nocase
        $phone = "phone" ascii nocase
        $hidden = "hidden" ascii nocase
        $stealth = "stealth" ascii nocase
    condition:
        $call and ($record or $intercept) and (any of ($voice, $phone, $hidden, $stealth))
}

rule Spyware_SMS_Spy {
    meta:
        description = "SMS spying software"
        severity = "critical"
    strings:
        $sms = "SMS" ascii
        $text = "text" ascii nocase
        $message = "message" ascii nocase
        $spy = "spy" ascii nocase
        $intercept = "intercept" ascii nocase
        $forward = "forward" ascii nocase
        $hidden = "hidden" ascii nocase
    condition:
        $sms and (any of ($text, $message)) and (any of ($spy, $intercept, $forward, $hidden))
}

rule Spyware_FinFisher {
    meta:
        description = "FinFisher/FinSpy surveillance"
        severity = "critical"
    strings:
        $finfisher = "FinFisher" ascii nocase
        $finspy = "FinSpy" ascii nocase
        $gamma = "Gamma" ascii nocase
        $surveillance = "surveillance" ascii nocase
        $lawful = "lawful" ascii nocase
        $intercept = "intercept" ascii nocase
    condition:
        (any of ($finfisher, $finspy, $gamma)) or ($surveillance and $lawful and $intercept)
}

rule Spyware_Hacking_Team_RCS {
    meta:
        description = "Hacking Team RCS/Galileo"
        severity = "critical"
    strings:
        $hacking_team = "HackingTeam" ascii nocase
        $rcs = "RCS" ascii
        $galileo = "Galileo" ascii nocase
        $implant = "implant" ascii nocase
        $agent = "agent" ascii nocase
        $collector = "collector" ascii nocase
    condition:
        (any of ($hacking_team, $rcs, $galileo)) or ($implant and $agent and $collector)
}

