/*
   YARA Rules for Email Threat Detection

   This file contains rules for detecting:
   - Malicious email attachments
   - Phishing emails
   - Business Email Compromise (BEC)
   - Spam indicators
   - Email-based malware delivery

   These rules target email-borne threats and indicators
*/

rule Email_Malicious_Macro_Attachment
{
    meta:
        description = "Detects malicious macro-enabled email attachments"
        severity = "high"
        category = "email_malware"
        author = "MalwareAnalyzer"
        date = "2024-01-01"

    strings:
        $office1 = { D0 CF 11 E0 A1 B1 1A E1 }
        $macro1 = "AutoOpen" ascii wide nocase
        $macro2 = "Auto_Open" ascii wide nocase
        $macro3 = "Document_Open" ascii wide nocase
        $macro4 = "Workbook_Open" ascii wide nocase
        $sus1 = "Shell" ascii wide
        $sus2 = "WScript" ascii wide
        $sus3 = "PowerShell" ascii wide nocase
        $sus4 = "cmd.exe" ascii wide nocase
        $download = "URLDownloadToFile" ascii wide

    condition:
        $office1 at 0 and
        (1 of ($macro*) and 2 of ($sus*)) or
        (1 of ($macro*) and $download)
}

rule Email_PDF_JavaScript_Exploit
{
    meta:
        description = "Detects PDF attachments with malicious JavaScript"
        severity = "high"
        category = "email_exploit"
        author = "MalwareAnalyzer"

    strings:
        $pdf = "%PDF-" ascii
        $js1 = "/JavaScript" ascii
        $js2 = "/JS" ascii
        $js3 = "/OpenAction" ascii
        $exploit1 = "eval(" ascii
        $exploit2 = "unescape(" ascii
        $exploit3 = "String.fromCharCode" ascii
        $shellcode = { 90 90 90 90 }
        $heap = "spray" ascii nocase

    condition:
        $pdf at 0 and
        (1 of ($js*) and 1 of ($exploit*)) or
        (1 of ($js*) and $shellcode)
}

rule Email_BEC_Impersonation
{
    meta:
        description = "Detects Business Email Compromise impersonation patterns"
        severity = "high"
        category = "email_bec"
        author = "MalwareAnalyzer"

    strings:
        $from1 = "From:" ascii
        $from2 = "Reply-To:" ascii
        $ceo1 = "CEO" ascii wide nocase
        $ceo2 = "CFO" ascii wide nocase
        $ceo3 = "President" ascii wide nocase
        $urgent1 = "URGENT" ascii wide nocase
        $urgent2 = "ASAP" ascii wide nocase
        $urgent3 = "immediately" ascii wide nocase
        $wire1 = "wire transfer" ascii wide nocase
        $wire2 = "bank account" ascii wide nocase
        $wire3 = "routing number" ascii wide nocase
        $confidential = "confidential" ascii wide nocase

    condition:
        (1 of ($from*) and 1 of ($ceo*) and 1 of ($urgent*) and 1 of ($wire*)) or
        (2 of ($urgent*) and 2 of ($wire*) and $confidential)
}

rule Email_Phishing_Credential_Harvest
{
    meta:
        description = "Detects credential harvesting phishing emails"
        severity = "high"
        category = "email_phishing"
        author = "MalwareAnalyzer"

    strings:
        $link1 = "href=" ascii
        $link2 = "click here" ascii wide nocase
        $link3 = "verify your" ascii wide nocase
        $brand1 = "Microsoft" ascii wide nocase
        $brand2 = "Office 365" ascii wide nocase
        $brand3 = "Google" ascii wide nocase
        $brand4 = "PayPal" ascii wide nocase
        $action1 = "password" ascii wide nocase
        $action2 = "account" ascii wide nocase
        $action3 = "suspended" ascii wide nocase
        $action4 = "verify" ascii wide nocase
        $urgency = "within 24 hours" ascii wide nocase

    condition:
        (1 of ($link*) and 1 of ($brand*) and 2 of ($action*)) or
        (2 of ($link*) and 2 of ($action*) and $urgency)
}

rule Email_Invoice_Scam
{
    meta:
        description = "Detects fake invoice email scams"
        severity = "medium"
        category = "email_scam"
        author = "MalwareAnalyzer"

    strings:
        $invoice1 = "invoice" ascii wide nocase
        $invoice2 = "payment" ascii wide nocase
        $invoice3 = "due" ascii wide nocase
        $amount1 = "$" ascii wide
        $amount2 = "USD" ascii wide
        $amount3 = "amount" ascii wide nocase
        $attach1 = ".zip" ascii wide nocase
        $attach2 = ".rar" ascii wide nocase
        $attach3 = ".iso" ascii wide nocase
        $action = "open the attached" ascii wide nocase
        $overdue = "overdue" ascii wide nocase

    condition:
        (2 of ($invoice*) and 1 of ($amount*) and 1 of ($attach*)) or
        ($action and $overdue and 1 of ($attach*))
}

rule Email_Malicious_HTML_Attachment
{
    meta:
        description = "Detects malicious HTML email attachments"
        severity = "high"
        category = "email_phishing"
        author = "MalwareAnalyzer"

    strings:
        $html1 = "<html" ascii nocase
        $html2 = "<body" ascii nocase
        $form1 = "<form" ascii nocase
        $form2 = "action=" ascii
        $input1 = "type=\"password\"" ascii nocase
        $input2 = "type=\"text\"" ascii nocase
        $js1 = "<script" ascii nocase
        $encode1 = "atob(" ascii
        $encode2 = "unescape(" ascii
        $redir = "window.location" ascii

    condition:
        (1 of ($html*) and $form1 and $input1) or
        ($js1 and 1 of ($encode*) and $redir)
}

rule Email_Spoofed_Headers
{
    meta:
        description = "Detects email header spoofing indicators"
        severity = "medium"
        category = "email_spoofing"
        author = "MalwareAnalyzer"

    strings:
        $header1 = "X-Mailer:" ascii
        $header2 = "Return-Path:" ascii
        $header3 = "Received:" ascii
        $spf_fail = "spf=fail" ascii nocase
        $dkim_fail = "dkim=fail" ascii nocase
        $dmarc_fail = "dmarc=fail" ascii nocase
        $mismatch1 = "envelope-from" ascii
        $mismatch2 = "header.from" ascii

    condition:
        (2 of ($header*) and 1 of ($spf_fail, $dkim_fail, $dmarc_fail)) or
        (all of ($mismatch*))
}

rule Email_Attachment_Double_Extension
{
    meta:
        description = "Detects attachments with double file extensions"
        severity = "high"
        category = "email_malware"
        author = "MalwareAnalyzer"

    strings:
        $ext1 = ".pdf.exe" ascii wide nocase
        $ext2 = ".doc.exe" ascii wide nocase
        $ext3 = ".jpg.exe" ascii wide nocase
        $ext4 = ".pdf.scr" ascii wide nocase
        $ext5 = ".doc.scr" ascii wide nocase
        $ext6 = ".xlsx.exe" ascii wide nocase
        $ext7 = ".docx.js" ascii wide nocase
        $ext8 = ".pdf.vbs" ascii wide nocase
        $content = "Content-Disposition: attachment" ascii

    condition:
        1 of ($ext*) or
        ($content and 1 of ($ext*))
}

rule Email_Encoded_Payload
{
    meta:
        description = "Detects base64 encoded payloads in emails"
        severity = "medium"
        category = "email_malware"
        author = "MalwareAnalyzer"

    strings:
        $b64_header = "Content-Transfer-Encoding: base64" ascii
        $b64_exe = "TVqQAAMAAAAEAAAA" ascii
        $b64_zip = "UEsDBBQA" ascii
        $b64_ps = "cG93ZXJzaGVsbC" ascii
        $b64_cmd = "Y21kLmV4ZQ" ascii
        $b64_vbs = "V0lORE9XUw" ascii

    condition:
        $b64_header and
        (1 of ($b64_exe, $b64_zip, $b64_ps, $b64_cmd, $b64_vbs))
}

rule Email_Sextortion_Scam
{
    meta:
        description = "Detects sextortion email scam patterns"
        severity = "low"
        category = "email_scam"
        author = "MalwareAnalyzer"

    strings:
        $threat1 = "webcam" ascii wide nocase
        $threat2 = "recorded you" ascii wide nocase
        $threat3 = "masturbating" ascii wide nocase
        $threat4 = "adult site" ascii wide nocase
        $btc1 = "bitcoin" ascii wide nocase
        $btc2 = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ ascii
        $btc3 = "BTC" ascii wide
        $deadline = "48 hours" ascii wide nocase
        $share = "share" ascii wide nocase

    condition:
        (2 of ($threat*) and 1 of ($btc*)) or
        (1 of ($threat*) and $btc2 and $deadline)
}

rule Email_Malware_Dropper_Link
{
    meta:
        description = "Detects emails with malware dropper links"
        severity = "high"
        category = "email_malware"
        author = "MalwareAnalyzer"

    strings:
        $url1 = "http://" ascii
        $url2 = "https://" ascii
        $drop1 = "/download" ascii nocase
        $drop2 = "/load" ascii nocase
        $drop3 = "/get" ascii nocase
        $ext1 = ".exe" ascii nocase
        $ext2 = ".dll" ascii nocase
        $ext3 = ".scr" ascii nocase
        $ext4 = ".bat" ascii nocase
        $shorten1 = "bit.ly" ascii nocase
        $shorten2 = "tinyurl" ascii nocase
        $shorten3 = "goo.gl" ascii nocase

    condition:
        (1 of ($url*) and 1 of ($drop*) and 1 of ($ext*)) or
        (1 of ($shorten*) and 1 of ($ext*))
}

rule Email_Lottery_Scam
{
    meta:
        description = "Detects lottery/advance fee fraud emails"
        severity = "low"
        category = "email_scam"
        author = "MalwareAnalyzer"

    strings:
        $lottery1 = "lottery" ascii wide nocase
        $lottery2 = "winner" ascii wide nocase
        $lottery3 = "prize" ascii wide nocase
        $lottery4 = "jackpot" ascii wide nocase
        $money1 = "million" ascii wide nocase
        $money2 = "$" ascii wide
        $money3 = "USD" ascii wide
        $action1 = "claim" ascii wide nocase
        $action2 = "fee" ascii wide nocase
        $action3 = "processing" ascii wide nocase
        $contact = "contact" ascii wide nocase

    condition:
        (2 of ($lottery*) and 1 of ($money*) and 1 of ($action*)) or
        (3 of ($lottery*) and $contact)
}

rule Email_ISO_Attachment_Malware
{
    meta:
        description = "Detects malicious ISO file email attachments"
        severity = "high"
        category = "email_malware"
        author = "MalwareAnalyzer"

    strings:
        $iso_header = "CD001" ascii
        $attach = "Content-Type: application/x-iso9660-image" ascii
        $filename = ".iso" ascii nocase
        $lnk = ".lnk" ascii wide nocase
        $exe = ".exe" ascii wide nocase
        $bat = ".bat" ascii wide nocase
        $ps1 = ".ps1" ascii wide nocase

    condition:
        ($iso_header or $attach) and
        ($filename and (1 of ($lnk, $exe, $bat, $ps1)))
}

rule Email_COVID_Phishing
{
    meta:
        description = "Detects COVID-19 themed phishing emails"
        severity = "medium"
        category = "email_phishing"
        author = "MalwareAnalyzer"

    strings:
        $covid1 = "COVID" ascii wide nocase
        $covid2 = "coronavirus" ascii wide nocase
        $covid3 = "vaccine" ascii wide nocase
        $covid4 = "pandemic" ascii wide nocase
        $org1 = "CDC" ascii wide
        $org2 = "WHO" ascii wide
        $org3 = "Health Department" ascii wide nocase
        $action1 = "click" ascii wide nocase
        $action2 = "download" ascii wide nocase
        $action3 = "verify" ascii wide nocase
        $attach = "attachment" ascii wide nocase

    condition:
        (2 of ($covid*) and 1 of ($org*) and 1 of ($action*)) or
        (2 of ($covid*) and $attach)
}

rule Email_Shipping_Notification_Scam
{
    meta:
        description = "Detects fake shipping notification phishing"
        severity = "medium"
        category = "email_phishing"
        author = "MalwareAnalyzer"

    strings:
        $ship1 = "shipping" ascii wide nocase
        $ship2 = "delivery" ascii wide nocase
        $ship3 = "tracking" ascii wide nocase
        $ship4 = "package" ascii wide nocase
        $brand1 = "FedEx" ascii wide nocase
        $brand2 = "UPS" ascii wide nocase
        $brand3 = "DHL" ascii wide nocase
        $brand4 = "USPS" ascii wide nocase
        $action1 = "track your" ascii wide nocase
        $action2 = "download" ascii wide nocase
        $fake = "tracking number" ascii wide nocase

    condition:
        (2 of ($ship*) and 1 of ($brand*) and 1 of ($action*)) or
        ($fake and 1 of ($brand*) and $action2)
}

rule Email_Tax_Scam
{
    meta:
        description = "Detects tax-themed phishing and scam emails"
        severity = "medium"
        category = "email_phishing"
        author = "MalwareAnalyzer"

    strings:
        $tax1 = "IRS" ascii wide
        $tax2 = "tax refund" ascii wide nocase
        $tax3 = "tax return" ascii wide nocase
        $tax4 = "W-2" ascii wide
        $urgent1 = "immediate" ascii wide nocase
        $urgent2 = "urgent" ascii wide nocase
        $action1 = "verify" ascii wide nocase
        $action2 = "SSN" ascii wide
        $action3 = "social security" ascii wide nocase
        $threat = "legal action" ascii wide nocase

    condition:
        (2 of ($tax*) and 1 of ($urgent*) and 1 of ($action*)) or
        (1 of ($tax*) and $threat)
}

rule Email_RTF_Exploit
{
    meta:
        description = "Detects malicious RTF email attachments"
        severity = "high"
        category = "email_exploit"
        author = "MalwareAnalyzer"

    strings:
        $rtf = "{\\rtf" ascii
        $obj1 = "\\objdata" ascii
        $obj2 = "\\objemb" ascii
        $obj3 = "\\objlink" ascii
        $ole1 = "d0cf11e0" ascii nocase
        $ole2 = "4d5a9000" ascii nocase
        $exploit1 = "\\object\\objocx" ascii
        $cve = "equation" ascii nocase

    condition:
        $rtf at 0 and
        (1 of ($obj*) and 1 of ($ole*)) or
        ($exploit1 or $cve)
}

rule Email_Vendor_Impersonation
{
    meta:
        description = "Detects vendor email impersonation attacks"
        severity = "high"
        category = "email_bec"
        author = "MalwareAnalyzer"

    strings:
        $vendor1 = "vendor" ascii wide nocase
        $vendor2 = "supplier" ascii wide nocase
        $vendor3 = "partner" ascii wide nocase
        $change1 = "bank details" ascii wide nocase
        $change2 = "account change" ascii wide nocase
        $change3 = "new account" ascii wide nocase
        $change4 = "updated bank" ascii wide nocase
        $payment1 = "payment" ascii wide nocase
        $payment2 = "invoice" ascii wide nocase
        $payment3 = "transfer" ascii wide nocase

    condition:
        (1 of ($vendor*) and 1 of ($change*) and 1 of ($payment*)) or
        (2 of ($change*) and 1 of ($payment*))
}

rule Email_QR_Code_Phishing
{
    meta:
        description = "Detects QR code phishing emails"
        severity = "medium"
        category = "email_phishing"
        author = "MalwareAnalyzer"

    strings:
        $qr1 = "QR code" ascii wide nocase
        $qr2 = "scan" ascii wide nocase
        $qr3 = "phone" ascii wide nocase
        $img1 = ".png" ascii nocase
        $img2 = ".jpg" ascii nocase
        $img3 = "data:image" ascii
        $action1 = "verify" ascii wide nocase
        $action2 = "authenticate" ascii wide nocase
        $action3 = "login" ascii wide nocase
        $mfa = "MFA" ascii wide

    condition:
        ($qr1 and $qr2 and 1 of ($action*)) or
        ($qr1 and $mfa and 1 of ($img*))
}

rule Email_Password_Protected_Attachment
{
    meta:
        description = "Detects password-protected malicious attachments"
        severity = "medium"
        category = "email_evasion"
        author = "MalwareAnalyzer"

    strings:
        $pwd1 = "password" ascii wide nocase
        $pwd2 = "passcode" ascii wide nocase
        $pwd3 = "protected" ascii wide nocase
        $open1 = "open" ascii wide nocase
        $open2 = "extract" ascii wide nocase
        $ext1 = ".zip" ascii wide nocase
        $ext2 = ".rar" ascii wide nocase
        $ext3 = ".7z" ascii wide nocase
        $pwd_is = /password\s*(is|:)\s*\w+/i ascii

    condition:
        (2 of ($pwd*) and 1 of ($open*) and 1 of ($ext*)) or
        ($pwd_is and 1 of ($ext*))
}
