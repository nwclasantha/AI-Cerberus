/*
   YARA Rules for Malicious Browser Extension Detection

   This file contains rules for detecting:
   - Malicious Chrome/Firefox/Edge extensions
   - Adware extensions
   - Data stealing extensions
   - Cryptojacking extensions
   - Browser hijackers

   These rules target malicious browser add-ons and extensions
*/

rule BrowserExt_Data_Stealer_Generic
{
    meta:
        description = "Detects generic data stealing browser extensions"
        severity = "high"
        category = "browser_extension"
        author = "MalwareAnalyzer"
        date = "2024-01-01"

    strings:
        $manifest = "manifest.json" ascii wide
        $steal1 = "document.forms" ascii
        $steal2 = "input[type=\"password\"]" ascii
        $steal3 = "creditcard" ascii nocase
        $steal4 = "card-number" ascii
        $exfil1 = "XMLHttpRequest" ascii
        $exfil2 = "fetch(" ascii
        $exfil3 = "sendBeacon" ascii
        $keylog = "addEventListener(\"keydown\"" ascii

    condition:
        $manifest and
        (2 of ($steal*) and 1 of ($exfil*)) or
        ($keylog and 1 of ($exfil*))
}

rule BrowserExt_Cryptominer_Injection
{
    meta:
        description = "Detects cryptomining browser extensions"
        severity = "high"
        category = "browser_cryptojacking"
        author = "MalwareAnalyzer"

    strings:
        $miner1 = "CoinHive" ascii nocase
        $miner2 = "coinhive.min.js" ascii
        $miner3 = "Cryptonight" ascii nocase
        $miner4 = "minerstart" ascii nocase
        $wasm1 = "WebAssembly.instantiate" ascii
        $wasm2 = ".wasm" ascii
        $cpu1 = "navigator.hardwareConcurrency" ascii
        $cpu2 = "performance.now()" ascii
        $pool = "stratum+tcp://" ascii

    condition:
        (2 of ($miner*)) or
        ($wasm1 and $cpu1 and $pool) or
        (all of ($cpu*) and $wasm2)
}

rule BrowserExt_Adware_Injector
{
    meta:
        description = "Detects adware browser extensions"
        severity = "medium"
        category = "browser_adware"
        author = "MalwareAnalyzer"

    strings:
        $inject1 = "document.createElement(\"script\")" ascii
        $inject2 = "document.createElement(\"iframe\")" ascii
        $inject3 = "innerHTML" ascii
        $ad1 = "googlesyndication" ascii
        $ad2 = "doubleclick.net" ascii
        $ad3 = "adservice" ascii nocase
        $replace1 = "replaceAds" ascii
        $replace2 = "injectAds" ascii
        $affiliate = "affiliate" ascii nocase

    condition:
        (2 of ($inject*) and 2 of ($ad*)) or
        (1 of ($replace*) and 1 of ($inject*)) or
        ($affiliate and 2 of ($inject*))
}

rule BrowserExt_Cookie_Stealer
{
    meta:
        description = "Detects cookie stealing browser extensions"
        severity = "high"
        category = "browser_stealer"
        author = "MalwareAnalyzer"

    strings:
        $cookie1 = "document.cookie" ascii
        $cookie2 = "chrome.cookies.getAll" ascii
        $cookie3 = "browser.cookies.getAll" ascii
        $session1 = "sessionStorage" ascii
        $session2 = "localStorage" ascii
        $exfil1 = "btoa(" ascii
        $exfil2 = "encodeURIComponent" ascii
        $send1 = ".php?" ascii
        $send2 = "POST" ascii

    condition:
        (1 of ($cookie*) and 1 of ($exfil*) and 1 of ($send*)) or
        (2 of ($cookie*) and 1 of ($session*))
}

rule BrowserExt_Credential_Harvester
{
    meta:
        description = "Detects credential harvesting browser extensions"
        severity = "critical"
        category = "browser_stealer"
        author = "MalwareAnalyzer"

    strings:
        $login1 = "login" ascii nocase
        $login2 = "password" ascii nocase
        $login3 = "username" ascii nocase
        $capture1 = "onsubmit" ascii
        $capture2 = "addEventListener(\"submit\"" ascii
        $capture3 = "form.action" ascii
        $bank1 = "bank" ascii nocase
        $bank2 = "paypal" ascii nocase
        $bank3 = "amazon" ascii nocase
        $exfil = "new Image().src" ascii

    condition:
        (2 of ($login*) and 1 of ($capture*) and 1 of ($bank*)) or
        (all of ($login*) and $exfil)
}

rule BrowserExt_History_Tracker
{
    meta:
        description = "Detects browser history tracking extensions"
        severity = "medium"
        category = "browser_spyware"
        author = "MalwareAnalyzer"

    strings:
        $history1 = "chrome.history.search" ascii
        $history2 = "browser.history.search" ascii
        $history3 = "getVisits" ascii
        $url1 = "chrome.tabs.onUpdated" ascii
        $url2 = "browser.tabs.onUpdated" ascii
        // UNUSED: $track1 = "tracking" ascii nocase
        // UNUSED: $track2 = "analytics" ascii nocase
        $send = "beacon" ascii nocase

    condition:
        (1 of ($history*) and 1 of ($url*)) or
        (2 of ($history*) and $send)
}

rule BrowserExt_Proxy_Hijacker
{
    meta:
        description = "Detects proxy hijacking browser extensions"
        severity = "high"
        category = "browser_hijacker"
        author = "MalwareAnalyzer"

    strings:
        $proxy1 = "chrome.proxy.settings" ascii
        $proxy2 = "browser.proxy.settings" ascii
        $proxy3 = "PAC_SCRIPT" ascii
        $hijack1 = "FindProxyForURL" ascii
        $hijack2 = "PROXY " ascii
        $hijack3 = "SOCKS" ascii
        $mitm1 = "127.0.0.1" ascii
        $mitm2 = "localhost:8" ascii

    condition:
        (1 of ($proxy*) and 1 of ($hijack*)) or
        (1 of ($proxy*) and 1 of ($mitm*))
}

rule BrowserExt_Search_Hijacker
{
    meta:
        description = "Detects search engine hijacking extensions"
        severity = "medium"
        category = "browser_hijacker"
        author = "MalwareAnalyzer"

    strings:
        $search1 = "chrome.search" ascii
        $search2 = "omnibox" ascii
        $search3 = "defaultSearchProvider" ascii
        $hijack1 = "searchengine" ascii nocase
        $hijack2 = "newtab" ascii
        $redirect1 = "window.location" ascii
        $redirect2 = "chrome.tabs.update" ascii
        // UNUSED: $domain1 = "search.yahoo" ascii
        // UNUSED: $domain2 = "bing.com" ascii

    condition:
        (2 of ($search*) and 1 of ($hijack*)) or
        (1 of ($search*) and 1 of ($redirect*))
}

rule BrowserExt_Clipboard_Hijacker
{
    meta:
        description = "Detects clipboard hijacking extensions (crypto address swap)"
        severity = "critical"
        category = "browser_hijacker"
        author = "MalwareAnalyzer"

    strings:
        $clip1 = "navigator.clipboard" ascii
        $clip2 = "document.execCommand(\"copy\")" ascii
        $clip3 = "clipboardData" ascii
        $crypto1 = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ ascii
        $crypto2 = /0x[a-fA-F0-9]{40}/ ascii
        $crypto3 = "bitcoin" ascii nocase
        $crypto4 = "ethereum" ascii nocase
        $replace = "replace(" ascii

    condition:
        (1 of ($clip*) and 1 of ($crypto*) and $replace)
}

rule BrowserExt_Screenshot_Spy
{
    meta:
        description = "Detects screenshot capturing browser extensions"
        severity = "high"
        category = "browser_spyware"
        author = "MalwareAnalyzer"

    strings:
        $screen1 = "chrome.tabs.captureVisibleTab" ascii
        $screen2 = "browser.tabs.captureVisibleTab" ascii
        $screen3 = "html2canvas" ascii
        $screen4 = "getDisplayMedia" ascii
        $upload1 = "FormData" ascii
        $upload2 = "toDataURL" ascii
        $upload3 = "toBlob" ascii
        $interval = "setInterval" ascii

    condition:
        (1 of ($screen*) and 1 of ($upload*)) or
        (2 of ($screen*) and $interval)
}

rule BrowserExt_WebRequest_Interceptor
{
    meta:
        description = "Detects malicious request intercepting extensions"
        severity = "high"
        category = "browser_mitm"
        author = "MalwareAnalyzer"

    strings:
        $request1 = "chrome.webRequest.onBeforeRequest" ascii
        $request2 = "chrome.webRequest.onHeadersReceived" ascii
        $request3 = "browser.webRequest.onBeforeRequest" ascii
        $modify1 = "requestHeaders" ascii
        $modify2 = "responseHeaders" ascii
        $modify3 = "redirectUrl" ascii
        $block = "blocking" ascii
        $inject = "Content-Security-Policy" ascii

    condition:
        (2 of ($request*) and 1 of ($modify*)) or
        (1 of ($request*) and $block and $inject)
}

rule BrowserExt_Facebook_Stealer
{
    meta:
        description = "Detects Facebook token stealing extensions"
        severity = "critical"
        category = "browser_stealer"
        author = "MalwareAnalyzer"

    strings:
        $fb1 = "facebook.com" ascii
        $fb2 = "fb_dtsg" ascii
        $fb3 = "access_token" ascii
        $fb4 = "xs=" ascii
        $api1 = "graph.facebook.com" ascii
        $api2 = "/me?" ascii
        $steal1 = "friends" ascii
        $steal2 = "messages" ascii
        $exfil = "XMLHttpRequest" ascii

    condition:
        (2 of ($fb*) and 1 of ($api*) and $exfil) or
        (3 of ($fb*) and 1 of ($steal*))
}

rule BrowserExt_Banking_Overlay
{
    meta:
        description = "Detects banking overlay attack extensions"
        severity = "critical"
        category = "browser_banking"
        author = "MalwareAnalyzer"

    strings:
        $bank1 = "wellsfargo" ascii nocase
        $bank2 = "bankofamerica" ascii nocase
        $bank3 = "chase" ascii nocase
        $bank4 = "citibank" ascii nocase
        $overlay1 = "z-index: 9999" ascii
        $overlay2 = "position: fixed" ascii
        $overlay3 = "position: absolute" ascii
        $inject1 = "insertBefore" ascii
        $inject2 = "appendChild" ascii
        $phish = "verify" ascii nocase

    condition:
        (2 of ($bank*) and 2 of ($overlay*) and 1 of ($inject*)) or
        (1 of ($bank*) and all of ($overlay*) and $phish)
}

rule BrowserExt_Notification_Spam
{
    meta:
        description = "Detects notification spam extensions"
        severity = "low"
        category = "browser_adware"
        author = "MalwareAnalyzer"

    strings:
        $notif1 = "Notification.requestPermission" ascii
        $notif2 = "chrome.notifications.create" ascii
        $notif3 = "browser.notifications.create" ascii
        $spam1 = "click here" ascii nocase
        $spam2 = "congratulations" ascii nocase
        $spam3 = "winner" ascii nocase
        $repeat = "setInterval" ascii
        // UNUSED: $random = "Math.random()" ascii

    condition:
        (1 of ($notif*) and 2 of ($spam*)) or
        (2 of ($notif*) and $repeat)
}

rule BrowserExt_Content_Replacer
{
    meta:
        description = "Detects malicious content replacement extensions"
        severity = "medium"
        category = "browser_hijacker"
        author = "MalwareAnalyzer"

    strings:
        $content1 = "MutationObserver" ascii
        $content2 = "innerHTML" ascii
        $content3 = "outerHTML" ascii
        $replace1 = "replaceChild" ascii
        $replace2 = "textContent" ascii
        $target1 = "querySelectorAll" ascii
        $target2 = "getElementsByClassName" ascii
        $affiliate = "affiliate" ascii nocase
        $link = "href=" ascii

    condition:
        ($content1 and 1 of ($replace*) and 1 of ($target*)) or
        (2 of ($content*) and $affiliate and $link)
}

rule BrowserExt_Password_Exfiltration
{
    meta:
        description = "Detects password exfiltration extensions"
        severity = "critical"
        category = "browser_stealer"
        author = "MalwareAnalyzer"

    strings:
        $pass1 = "type=\"password\"" ascii
        $pass2 = "autocomplete=\"current-password\"" ascii
        $pass3 = "[type=password]" ascii
        $grab1 = "value" ascii
        $grab2 = "getAttribute" ascii
        $send1 = "webhook" ascii
        $send2 = "discord.com/api/webhooks" ascii
        $send3 = "telegram" ascii nocase
        $encode = "btoa" ascii

    condition:
        (2 of ($pass*) and 1 of ($grab*) and 1 of ($send*)) or
        (1 of ($pass*) and $encode and 1 of ($send*))
}

rule BrowserExt_Tab_Nabbing
{
    meta:
        description = "Detects tab nabbing/reverse tabnabbing extensions"
        severity = "high"
        category = "browser_phishing"
        author = "MalwareAnalyzer"

    strings:
        $tab1 = "window.opener" ascii
        // UNUSED: $tab2 = "_blank" ascii
        // UNUSED: $tab3 = "noopener" ascii
        $nab1 = "opener.location" ascii
        $nab2 = "parent.location" ascii
        $phish1 = "login" ascii nocase
        $phish2 = "signin" ascii nocase
        $timer = "setTimeout" ascii

    condition:
        (($tab1 or $nab1 or $nab2) and 1 of ($phish*) and $timer)
}

rule BrowserExt_Session_Hijacker
{
    meta:
        description = "Detects session hijacking extensions"
        severity = "critical"
        category = "browser_hijacker"
        author = "MalwareAnalyzer"

    strings:
        $session1 = "JSESSIONID" ascii
        $session2 = "PHPSESSID" ascii
        $session3 = "ASP.NET_SessionId" ascii
        $header1 = "Set-Cookie" ascii
        $header2 = "Cookie:" ascii
        $steal1 = "getAllCookies" ascii
        $steal2 = "onHeadersReceived" ascii
        $replay = "setRequestHeader" ascii

    condition:
        (2 of ($session*) and 1 of ($steal*)) or
        (1 of ($header*) and $steal2 and $replay)
}

rule BrowserExt_Formjacking
{
    meta:
        description = "Detects formjacking browser extensions"
        severity = "critical"
        category = "browser_skimmer"
        author = "MalwareAnalyzer"

    strings:
        $form1 = "document.forms" ascii
        $form2 = "querySelector(\"form\")" ascii
        $form3 = "getElementsByTagName(\"form\")" ascii
        $card1 = "card" ascii nocase
        $card2 = "cvv" ascii nocase
        $card3 = "expir" ascii nocase
        $card4 = "billing" ascii nocase
        $exfil1 = "navigator.sendBeacon" ascii
        $exfil2 = "img.src=" ascii
        $encode = "JSON.stringify" ascii

    condition:
        (1 of ($form*) and 2 of ($card*) and 1 of ($exfil*)) or
        (2 of ($form*) and 3 of ($card*) and $encode)
}

rule BrowserExt_Malicious_Manifest
{
    meta:
        description = "Detects malicious browser extension manifest patterns"
        severity = "medium"
        category = "browser_extension"
        author = "MalwareAnalyzer"

    strings:
        $manifest = "\"manifest_version\"" ascii
        $perm1 = "\"<all_urls>\"" ascii
        $perm2 = "\"*://*/*\"" ascii
        $perm3 = "\"webRequest\"" ascii
        $perm4 = "\"webRequestBlocking\"" ascii
        $perm5 = "\"cookies\"" ascii
        $perm6 = "\"tabs\"" ascii
        $perm7 = "\"storage\"" ascii
        $bg = "\"background\"" ascii
        $content = "\"content_scripts\"" ascii

    condition:
        $manifest and
        (($perm1 or $perm2) and 3 of ($perm3, $perm4, $perm5, $perm6, $perm7)) and
        ($bg or $content)
}
