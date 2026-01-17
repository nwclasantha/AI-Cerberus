/*
    Phishing and Social Engineering Indicators
    Phishing kits, credential harvesting, and social engineering attacks
*/

rule Phishing_Credential_Harvester {
    meta:
        description = "Credential harvesting page"
        severity = "critical"
    strings:
        $form = "<form" ascii nocase
        $password = "password" ascii nocase
        $login = "login" ascii nocase
        $signin = "sign in" ascii nocase
        $submit = "submit" ascii nocase
        $email = "email" ascii nocase
        $username = "username" ascii nocase
        $action = "action=" ascii nocase
    condition:
        $form and ($password or any of ($login, $signin)) and (any of ($submit, $email, $username, $action))
}

rule Phishing_Kit_Generic {
    meta:
        description = "Generic phishing kit"
        severity = "critical"
    strings:
        $kit = "phishing" ascii nocase
        $panel = "panel" ascii nocase
        $results = "results" ascii nocase
        $victims = "victims" ascii nocase
        $logs = "logs" ascii nocase
        $admin = "admin" ascii nocase
        $mail = "mail" ascii nocase
        $telegram = "telegram" ascii nocase
    condition:
        ($kit or $panel) and (any of ($results, $victims, $logs)) and (any of ($admin, $mail, $telegram))
}

rule Phishing_Office365_Clone {
    meta:
        description = "Office 365 phishing page"
        severity = "critical"
    strings:
        $o365_1 = "office365" ascii nocase
        $o365_2 = "office.com" ascii nocase
        $o365_3 = "microsoftonline" ascii nocase
        $o365_4 = "outlook" ascii nocase
        $login = "login" ascii nocase
        $signin = "sign" ascii nocase
        $password = "password" ascii nocase
        $form = "<form" ascii nocase
    condition:
        (any of ($o365*)) and ($login or $signin) and $password and $form
}

rule Phishing_Google_Clone {
    meta:
        description = "Google phishing page"
        severity = "critical"
    strings:
        $google = "google" ascii nocase
        $gmail = "gmail" ascii nocase
        $gaia = "gaia" ascii nocase
        $accounts = "accounts.google" ascii nocase
        $signin = "signin" ascii nocase
        $password = "password" ascii nocase
        $form = "<form" ascii nocase
    condition:
        (any of ($google, $gmail, $gaia, $accounts)) and $signin and $password and $form
}

rule Phishing_Banking_Page {
    meta:
        description = "Banking phishing page"
        severity = "critical"
    strings:
        $bank = "bank" ascii nocase
        $account = "account" ascii nocase
        $login = "login" ascii nocase
        $secure = "secure" ascii nocase
        $verify = "verify" ascii nocase
        $card = "card" ascii nocase
        $cvv = "cvv" ascii nocase
        $pin = "pin" ascii nocase
        $ssn = "ssn" ascii nocase
    condition:
        $bank and ($login or $verify) and (any of ($card, $cvv, $pin, $ssn, $account))
}

rule Phishing_PayPal_Clone {
    meta:
        description = "PayPal phishing page"
        severity = "critical"
    strings:
        $paypal = "paypal" ascii nocase
        $login = "login" ascii nocase
        $password = "password" ascii nocase
        $card = "card" ascii nocase
        $verify = "verify" ascii nocase
        $account = "account" ascii nocase
        $form = "<form" ascii nocase
    condition:
        $paypal and ($login or $verify) and ($password or $card) and $form
}

rule Phishing_Amazon_Clone {
    meta:
        description = "Amazon phishing page"
        severity = "critical"
    strings:
        $amazon = "amazon" ascii nocase
        $signin = "sign" ascii nocase
        $password = "password" ascii nocase
        $email = "email" ascii nocase
        $account = "account" ascii nocase
        $prime = "prime" ascii nocase
        $form = "<form" ascii nocase
    condition:
        $amazon and $signin and ($password or $email) and $form
}

rule Phishing_Apple_Clone {
    meta:
        description = "Apple ID phishing page"
        severity = "critical"
    strings:
        $apple = "apple" ascii nocase
        $icloud = "icloud" ascii nocase
        $appleid = "appleid" ascii nocase
        $signin = "sign" ascii nocase
        $password = "password" ascii nocase
        $verify = "verify" ascii nocase
        $form = "<form" ascii nocase
    condition:
        (any of ($apple, $icloud, $appleid)) and $signin and $password and $form
}

rule Phishing_Facebook_Clone {
    meta:
        description = "Facebook phishing page"
        severity = "critical"
    strings:
        $facebook = "facebook" ascii nocase
        $fb = "fb.com" ascii nocase
        $login = "login" ascii nocase
        $password = "password" ascii nocase
        $email = "email" ascii nocase
        $form = "<form" ascii nocase
    condition:
        (any of ($facebook, $fb)) and $login and $password and $form
}

rule Phishing_LinkedIn_Clone {
    meta:
        description = "LinkedIn phishing page"
        severity = "critical"
    strings:
        $linkedin = "linkedin" ascii nocase
        $signin = "sign" ascii nocase
        $password = "password" ascii nocase
        $email = "email" ascii nocase
        $connect = "connect" ascii nocase
        $form = "<form" ascii nocase
    condition:
        $linkedin and $signin and $password and $form
}

rule Phishing_Telegram_Bot {
    meta:
        description = "Phishing with Telegram exfil"
        severity = "critical"
    strings:
        $telegram = "api.telegram.org" ascii
        $bot = "/bot" ascii
        $send = "sendMessage" ascii
        $chat = "chat_id" ascii
        $password = "password" ascii nocase
        $login = "login" ascii nocase
    condition:
        $telegram and $bot and ($send or $chat) and (any of ($password, $login))
}

rule Phishing_Discord_Webhook {
    meta:
        description = "Phishing with Discord exfil"
        severity = "critical"
    strings:
        $discord = "discord.com/api/webhooks" ascii
        $webhook = "webhook" ascii nocase
        $embed = "embeds" ascii
        $content = "content" ascii
        $password = "password" ascii nocase
        $stolen = "stolen" ascii nocase
    condition:
        $discord and ($embed or $content) and (any of ($password, $stolen))
}

rule Phishing_Email_Exfil {
    meta:
        description = "Phishing with email exfil"
        severity = "high"
    strings:
        $mail1 = "mail(" ascii
        $mail2 = "smtp" ascii nocase
        $mail3 = "PHPMailer" ascii
        $password = "password" ascii nocase
        $login = "login" ascii nocase
        $victim = "victim" ascii nocase
        $result = "result" ascii nocase
    condition:
        (any of ($mail*)) and (any of ($password, $login)) and (any of ($victim, $result))
}

rule Phishing_Base64_Obfuscation {
    meta:
        description = "Base64 obfuscated phishing"
        severity = "high"
    strings:
        $b64 = "base64" ascii nocase
        $atob = "atob(" ascii
        $btoa = "btoa(" ascii
        $decode = "decode" ascii nocase
        $eval = "eval(" ascii
        $document = "document.write" ascii
    condition:
        (any of ($b64, $atob, $btoa, $decode)) and (any of ($eval, $document))
}

rule Phishing_URL_Shortener_Abuse {
    meta:
        description = "URL shortener in phishing"
        severity = "medium"
    strings:
        $bit = "bit.ly" ascii nocase
        $tinyurl = "tinyurl" ascii nocase
        $goo = "goo.gl" ascii nocase
        $ow = "ow.ly" ascii nocase
        $is = "is.gd" ascii nocase
        $t = "t.co" ascii
        $redirect = "redirect" ascii nocase
        $login = "login" ascii nocase
    condition:
        (any of ($bit, $tinyurl, $goo, $ow, $is, $t)) and (any of ($redirect, $login))
}

rule Phishing_Data_URI_Attack {
    meta:
        description = "Data URI phishing attack"
        severity = "critical"
    strings:
        $data1 = "data:text/html" ascii
        $data2 = "data:application" ascii
        $base64 = "base64," ascii
        $script = "<script" ascii nocase
        $form = "<form" ascii nocase
        $password = "password" ascii nocase
    condition:
        (any of ($data1, $data2)) and $base64 and (any of ($script, $form, $password))
}

rule Phishing_Punycode_Domain {
    meta:
        description = "Punycode domain phishing"
        severity = "high"
    strings:
        $xn = "xn--" ascii
        $puny = "punycode" ascii nocase
        $idn = "IDN" ascii
        $login = "login" ascii nocase
        $password = "password" ascii nocase
    condition:
        $xn and (any of ($puny, $idn) or any of ($login, $password))
}

rule Phishing_Captcha_Bypass {
    meta:
        description = "CAPTCHA in phishing page"
        severity = "medium"
    strings:
        $captcha = "captcha" ascii nocase
        $recaptcha = "recaptcha" ascii nocase
        $verify = "verify" ascii nocase
        $human = "human" ascii nocase
        $robot = "robot" ascii nocase
        $form = "<form" ascii nocase
        $password = "password" ascii nocase
    condition:
        (any of ($captcha, $recaptcha)) and (any of ($verify, $human, $robot)) and $form
}

rule Phishing_QR_Code_Attack {
    meta:
        description = "QR code phishing (quishing)"
        severity = "high"
    strings:
        $qr = "qr" ascii nocase
        $code = "code" ascii nocase
        $scan = "scan" ascii nocase
        $camera = "camera" ascii nocase
        $redirect = "redirect" ascii nocase
        $login = "login" ascii nocase
        $verify = "verify" ascii nocase
    condition:
        ($qr and $code) and ($scan or $camera) and (any of ($redirect, $login, $verify))
}

rule Phishing_MFA_Bypass {
    meta:
        description = "MFA bypass phishing"
        severity = "critical"
    strings:
        $mfa = "MFA" ascii
        $2fa = "2FA" ascii
        $otp = "OTP" ascii
        $totp = "TOTP" ascii
        $authenticator = "authenticator" ascii nocase
        $code = "code" ascii nocase
        $verify = "verify" ascii nocase
        $proxy = "proxy" ascii nocase
    condition:
        (any of ($mfa, $2fa, $otp, $totp, $authenticator)) and ($code or $verify)
}

