/*
   Ransomware Detection Rules
   Patterns for detecting ransomware behavior
*/

rule Ransomware_Indicators {
    meta:
        description = "Generic ransomware behavior"
        author = "Malware Analyzer Team"
        date = "2025-01-15"
        severity = "critical"
        category = "ransomware"
    strings:
        $crypto1 = "CryptEncrypt" nocase
        $crypto2 = "CryptAcquireContext" nocase
        $crypto3 = "CryptGenKey" nocase
        $crypto4 = "BCryptEncrypt" nocase
        $file1 = "FindFirstFile" nocase
        $file2 = "FindNextFile" nocase
        $ext1 = ".encrypted"
        $ext2 = ".locked"
        $ext3 = ".crypto"
        $note1 = "README" nocase
        $note2 = "HOW_TO_DECRYPT" nocase
        $note3 = "YOUR_FILES_ARE_ENCRYPTED" nocase
        $bitcoin = "bitcoin" nocase
        $ransom = "ransom" nocase
    condition:
        (2 of ($crypto*) and 2 of ($file*)) or
        (any of ($crypto*) and any of ($ext*)) or
        (any of ($note*) and ($bitcoin or $ransom))
}

rule Crypto_Locker {
    meta:
        description = "Crypto-locker ransomware patterns"
        severity = "critical"
        category = "ransomware"
    strings:
        $rsa1 = "RSA" nocase
        $aes1 = "AES" nocase
        $crypt1 = "CryptEncrypt" nocase
        $crypt2 = "CryptGenRandom" nocase
        $shadow1 = "vssadmin" nocase
        $shadow2 = "delete shadows" nocase
        $bcdedit = "bcdedit" nocase
        $disable = "recoveryenabled no" nocase
    condition:
        (($rsa1 or $aes1) and any of ($crypt*)) and
        (($shadow1 and $shadow2) or ($bcdedit and $disable))
}

rule File_Encryptor {
    meta:
        description = "File encryption functionality"
        severity = "high"
        category = "crypto"
    strings:
        $enc1 = "CryptEncrypt" nocase
        $enc2 = "BCryptEncrypt" nocase
        $key1 = "CryptGenKey" nocase
        $key2 = "BCryptGenkey" nocase
        $rec1 = "DeleteFile" nocase
        $rec2 = "MoveFileEx" nocase
        $shadow = "vssadmin delete shadows" nocase
    condition:
        (any of ($enc*) and any of ($key*)) and
        (2 of ($rec*) or $shadow)
}

rule Ransom_Note {
    meta:
        description = "Ransom note patterns"
        severity = "high"
        category = "ransomware"
    strings:
        $pay1 = "pay" nocase
        $pay2 = "payment" nocase
        $decrypt1 = "decrypt" nocase
        $decrypt2 = "decryption key" nocase
        $bitcoin = "bitcoin" nocase
        $wallet = "wallet" nocase
        $contact1 = "@protonmail" nocase
        $contact2 = "@tutanota" nocase
        $deadline1 = "hours" nocase
        $deadline2 = "days" nocase
        $warning = "permanent" nocase
    condition:
        (any of ($pay*) and any of ($decrypt*)) and
        ($bitcoin or $wallet or any of ($contact*)) and
        (any of ($deadline*) and $warning)
}
