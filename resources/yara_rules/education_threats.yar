/*
   YARA Rules for Education Sector Threat Detection

   This file contains rules for detecting:
   - Education sector targeted threats
   - Research data theft
   - Student/staff data compromise
   - Academic credential theft
   - University network attacks

   These rules target threats specific to educational institutions
*/

rule Education_Ransomware_Targeting
{
    meta:
        description = "Detects ransomware specifically targeting education sector"
        severity = "critical"
        category = "education_ransomware"
        author = "MalwareAnalyzer"
        date = "2024-01-01"

    strings:
        $edu1 = "university" ascii wide nocase
        $edu2 = "college" ascii wide nocase
        $edu3 = "school" ascii wide nocase
        $edu4 = ".edu" ascii wide
        $ransom1 = "encrypted" ascii wide nocase
        $ransom2 = "bitcoin" ascii wide nocase
        $ransom3 = "decrypt" ascii wide nocase
        $ransom4 = "ransom" ascii wide nocase
        $domain = "edu" ascii

    condition:
        uint16(0) == 0x5A4D and
        (2 of ($edu*) and 2 of ($ransom*)) or
        ($domain and 2 of ($ransom*))
}

rule Education_Research_Data_Theft
{
    meta:
        description = "Detects malware stealing research data"
        severity = "critical"
        category = "education_espionage"
        author = "MalwareAnalyzer"

    strings:
        $research1 = "research" ascii wide nocase
        $research2 = "dissertation" ascii wide nocase
        $research3 = "thesis" ascii wide nocase
        $research4 = "publication" ascii wide nocase
        $data1 = "grant" ascii wide nocase
        $data2 = "proposal" ascii wide nocase
        $data3 = "patent" ascii wide nocase
        $exfil1 = "upload" ascii nocase
        $exfil2 = "POST" ascii
        $exfil3 = "ftp" ascii nocase

    condition:
        (2 of ($research*) and 1 of ($data*) and 1 of ($exfil*)) or
        (3 of ($research*) and 1 of ($exfil*))
}

rule Education_Student_Data_Stealer
{
    meta:
        description = "Detects malware targeting student information systems"
        severity = "high"
        category = "education_stealer"
        author = "MalwareAnalyzer"

    strings:
        $sis1 = "student information" ascii wide nocase
        $sis2 = "SIS" ascii wide
        $sis3 = "Banner" ascii wide
        $sis4 = "PowerSchool" ascii wide
        $sis5 = "Blackboard" ascii wide
        $data1 = "GPA" ascii wide
        $data2 = "transcript" ascii wide nocase
        $data3 = "enrollment" ascii wide nocase
        $data4 = "SSN" ascii wide
        $sql = "SELECT" ascii

    condition:
        (1 of ($sis*) and 2 of ($data*)) or
        (2 of ($sis*) and $sql)
}

rule Education_LMS_Credential_Theft
{
    meta:
        description = "Detects credential theft from Learning Management Systems"
        severity = "high"
        category = "education_stealer"
        author = "MalwareAnalyzer"

    strings:
        $lms1 = "Canvas" ascii wide nocase
        $lms2 = "Moodle" ascii wide nocase
        $lms3 = "Blackboard" ascii wide nocase
        $lms4 = "D2L" ascii wide
        $lms5 = "Brightspace" ascii wide
        $cred1 = "username" ascii nocase
        $cred2 = "password" ascii nocase
        $cred3 = "login" ascii nocase
        $hook1 = "keylogger" ascii nocase
        $hook2 = "form grabber" ascii nocase

    condition:
        (2 of ($lms*) and 1 of ($cred*) and 1 of ($hook*)) or
        (1 of ($lms*) and 2 of ($cred*))
}

rule Education_IP_Theft_University
{
    meta:
        description = "Detects intellectual property theft from universities"
        severity = "critical"
        category = "education_espionage"
        author = "MalwareAnalyzer"

    strings:
        $ip1 = "intellectual property" ascii wide nocase
        $ip2 = "patent" ascii wide nocase
        $ip3 = "proprietary" ascii wide nocase
        $ip4 = "trade secret" ascii wide nocase
        $dept1 = "engineering" ascii wide nocase
        $dept2 = "computer science" ascii wide nocase
        $dept3 = "physics" ascii wide nocase
        $dept4 = "chemistry" ascii wide nocase
        $exfil1 = "compress" ascii nocase
        $exfil2 = "encrypt" ascii nocase
        $exfil3 = "upload" ascii nocase

    condition:
        (2 of ($ip*) and 1 of ($dept*) and 1 of ($exfil*)) or
        (1 of ($ip*) and 2 of ($dept*) and 1 of ($exfil*))
}

rule Education_FERPA_Data_Breach
{
    meta:
        description = "Detects malware targeting FERPA protected data"
        severity = "critical"
        category = "education_data"
        author = "MalwareAnalyzer"

    strings:
        $ferpa1 = "FERPA" ascii wide
        $ferpa2 = "educational records" ascii wide nocase
        $ferpa3 = "student records" ascii wide nocase
        $pii1 = "date of birth" ascii wide nocase
        $pii2 = "SSN" ascii wide
        $pii3 = "social security" ascii wide nocase
        $pii4 = "address" ascii wide nocase
        $exfil1 = "HttpClient" ascii
        $exfil2 = "WebClient" ascii

    condition:
        (1 of ($ferpa*) and 2 of ($pii*)) or
        (2 of ($ferpa*) and 1 of ($exfil*))
}

rule Education_Grade_Manipulation
{
    meta:
        description = "Detects tools for grade manipulation"
        severity = "high"
        category = "education_fraud"
        author = "MalwareAnalyzer"

    strings:
        $grade1 = "grade" ascii wide nocase
        $grade2 = "GPA" ascii wide
        $grade3 = "transcript" ascii wide nocase
        $grade4 = "score" ascii wide nocase
        $action1 = "UPDATE" ascii
        $action2 = "modify" ascii nocase
        $action3 = "change" ascii nocase
        $db1 = "database" ascii nocase
        $db2 = "SQL" ascii

    condition:
        (2 of ($grade*) and 1 of ($action*) and 1 of ($db*)) or
        (3 of ($grade*) and 1 of ($action*))
}

rule Education_Exam_System_Attack
{
    meta:
        description = "Detects attacks on examination systems"
        severity = "high"
        category = "education_attack"
        author = "MalwareAnalyzer"

    strings:
        $exam1 = "exam" ascii wide nocase
        $exam2 = "test" ascii wide nocase
        $exam3 = "assessment" ascii wide nocase
        $exam4 = "proctoring" ascii wide nocase
        $cheat1 = "answer" ascii wide nocase
        $cheat2 = "leak" ascii wide nocase
        $cheat3 = "cheat" ascii wide nocase
        $sys1 = "ProctorU" ascii wide
        $sys2 = "ExamSoft" ascii wide
        $sys3 = "Respondus" ascii wide

    condition:
        (2 of ($exam*) and 1 of ($cheat*)) or
        (1 of ($sys*) and 1 of ($cheat*))
}

rule Education_Financial_Aid_Fraud
{
    meta:
        description = "Detects financial aid fraud malware"
        severity = "high"
        category = "education_fraud"
        author = "MalwareAnalyzer"

    strings:
        $aid1 = "financial aid" ascii wide nocase
        $aid2 = "FAFSA" ascii wide
        $aid3 = "scholarship" ascii wide nocase
        $aid4 = "Pell Grant" ascii wide nocase
        $fraud1 = "identity" ascii nocase
        $fraud2 = "impersonate" ascii nocase
        $fraud3 = "fake" ascii nocase
        $data1 = "EFC" ascii wide
        $data2 = "SAR" ascii wide

    condition:
        (2 of ($aid*) and 1 of ($fraud*)) or
        (1 of ($aid*) and 1 of ($data*) and 1 of ($fraud*))
}

rule Education_Campus_Network_Worm
{
    meta:
        description = "Detects worms spreading through campus networks"
        severity = "high"
        category = "education_worm"
        author = "MalwareAnalyzer"

    strings:
        $spread1 = "NetShareEnum" ascii
        $spread2 = "WNetOpenEnum" ascii
        $spread3 = "\\\\%s\\C$" ascii
        $campus1 = "campus" ascii nocase
        $campus2 = "dormitory" ascii nocase
        $campus3 = "library" ascii nocase
        $scan1 = "port scan" ascii nocase
        $scan2 = "445" ascii
        $scan3 = "139" ascii

    condition:
        uint16(0) == 0x5A4D and
        (2 of ($spread*) and 1 of ($campus*)) or
        (1 of ($campus*) and 2 of ($scan*))
}

rule Education_Library_System_Attack
{
    meta:
        description = "Detects attacks on library management systems"
        severity = "medium"
        category = "education_attack"
        author = "MalwareAnalyzer"

    strings:
        $lib1 = "library" ascii wide nocase
        $lib2 = "ILS" ascii wide
        $lib3 = "OPAC" ascii wide
        $lib4 = "circulation" ascii wide nocase
        $sys1 = "Alma" ascii wide
        $sys2 = "Sierra" ascii wide
        $sys3 = "Koha" ascii wide
        $attack1 = "SQL" ascii
        $attack2 = "injection" ascii nocase

    condition:
        (2 of ($lib*) and 1 of ($sys*)) or
        (1 of ($lib*) and 1 of ($attack*))
}

rule Education_Research_Lab_Espionage
{
    meta:
        description = "Detects espionage targeting university research labs"
        severity = "critical"
        category = "education_espionage"
        author = "MalwareAnalyzer"

    strings:
        $lab1 = "laboratory" ascii wide nocase
        $lab2 = "research lab" ascii wide nocase
        $lab3 = "lab data" ascii wide nocase
        $field1 = "biomedical" ascii wide nocase
        $field2 = "nanotechnology" ascii wide nocase
        $field3 = "artificial intelligence" ascii wide nocase
        $field4 = "quantum" ascii wide nocase
        $apt1 = "APT" ascii wide
        $apt2 = "nation-state" ascii wide nocase
        $exfil = "exfiltrate" ascii nocase

    condition:
        (1 of ($lab*) and 1 of ($field*) and $exfil) or
        (2 of ($field*) and 1 of ($apt*))
}

rule Education_Admissions_System_Attack
{
    meta:
        description = "Detects attacks on admissions systems"
        severity = "high"
        category = "education_attack"
        author = "MalwareAnalyzer"

    strings:
        $admit1 = "admission" ascii wide nocase
        $admit2 = "application" ascii wide nocase
        $admit3 = "applicant" ascii wide nocase
        $admit4 = "enrollment" ascii wide nocase
        $sys1 = "Slate" ascii wide
        $sys2 = "CommonApp" ascii wide
        $sys3 = "CollegeBoard" ascii wide
        $data1 = "SAT" ascii wide
        $data2 = "ACT" ascii wide
        $data3 = "essay" ascii wide nocase

    condition:
        (2 of ($admit*) and 1 of ($sys*)) or
        (1 of ($admit*) and 2 of ($data*))
}

rule Education_Faculty_Email_Compromise
{
    meta:
        description = "Detects BEC targeting faculty and staff"
        severity = "high"
        category = "education_bec"
        author = "MalwareAnalyzer"

    strings:
        $title1 = "professor" ascii wide nocase
        $title2 = "dean" ascii wide nocase
        $title3 = "provost" ascii wide nocase
        $title4 = "chancellor" ascii wide nocase
        $request1 = "wire transfer" ascii wide nocase
        $request2 = "gift card" ascii wide nocase
        $request3 = "urgent" ascii wide nocase
        $impersonate = "On behalf of" ascii wide nocase
        $domain = ".edu" ascii

    condition:
        (2 of ($title*) and 1 of ($request*)) or
        ($impersonate and $domain and 1 of ($request*))
}

rule Education_Online_Course_Platform_Attack
{
    meta:
        description = "Detects attacks on online learning platforms"
        severity = "medium"
        category = "education_attack"
        author = "MalwareAnalyzer"

    strings:
        $platform1 = "Coursera" ascii wide nocase
        $platform2 = "edX" ascii wide nocase
        $platform3 = "Udemy" ascii wide nocase
        $platform4 = "Khan Academy" ascii wide nocase
        $attack1 = "scrape" ascii nocase
        $attack2 = "download" ascii nocase
        $attack3 = "pirate" ascii nocase
        $content1 = "course" ascii wide nocase
        $content2 = "video" ascii wide nocase

    condition:
        (2 of ($platform*) and 1 of ($attack*)) or
        (1 of ($platform*) and 1 of ($content*) and 1 of ($attack*))
}

rule Education_Student_Loan_Fraud
{
    meta:
        description = "Detects student loan fraud malware"
        severity = "medium"
        category = "education_fraud"
        author = "MalwareAnalyzer"

    strings:
        $loan1 = "student loan" ascii wide nocase
        $loan2 = "loan servicer" ascii wide nocase
        $loan3 = "loan forgiveness" ascii wide nocase
        $loan4 = "NSLDS" ascii wide
        $fraud1 = "phishing" ascii nocase
        $fraud2 = "fake" ascii nocase
        $fraud3 = "impersonate" ascii nocase
        $servicer1 = "Navient" ascii wide
        $servicer2 = "Nelnet" ascii wide
        $servicer3 = "FedLoan" ascii wide

    condition:
        (2 of ($loan*) and 1 of ($fraud*)) or
        (1 of ($servicer*) and 1 of ($fraud*))
}

rule Education_WiFi_Attack_Campus
{
    meta:
        description = "Detects WiFi attacks on campus networks"
        severity = "high"
        category = "education_network"
        author = "MalwareAnalyzer"

    strings:
        $wifi1 = "eduroam" ascii wide nocase
        $wifi2 = "campus wifi" ascii wide nocase
        $wifi3 = "802.1X" ascii
        $attack1 = "evil twin" ascii nocase
        $attack2 = "deauth" ascii nocase
        $attack3 = "rogue AP" ascii nocase
        $tool1 = "aircrack" ascii nocase
        $tool2 = "hostapd" ascii nocase
        $cred = "credential" ascii nocase

    condition:
        (1 of ($wifi*) and 1 of ($attack*)) or
        (1 of ($wifi*) and 1 of ($tool*) and $cred)
}

rule Education_Research_Grant_Theft
{
    meta:
        description = "Detects theft of research grant information"
        severity = "high"
        category = "education_espionage"
        author = "MalwareAnalyzer"

    strings:
        $grant1 = "NSF" ascii wide
        $grant2 = "NIH" ascii wide
        $grant3 = "DARPA" ascii wide
        $grant4 = "DOE" ascii wide
        $doc1 = "proposal" ascii wide nocase
        $doc2 = "grant application" ascii wide nocase
        $doc3 = "funding" ascii wide nocase
        $steal1 = "keylog" ascii nocase
        $steal2 = "screenshot" ascii nocase
        $steal3 = "exfil" ascii nocase

    condition:
        (2 of ($grant*) and 1 of ($doc*) and 1 of ($steal*)) or
        (1 of ($grant*) and 2 of ($doc*))
}

rule Education_Plagiarism_Tool
{
    meta:
        description = "Detects academic plagiarism and cheating tools"
        severity = "low"
        category = "education_fraud"
        author = "MalwareAnalyzer"

    strings:
        $cheat1 = "plagiarism" ascii wide nocase
        $cheat2 = "essay mill" ascii wide nocase
        $cheat3 = "contract cheating" ascii wide nocase
        $cheat4 = "ghostwriter" ascii wide nocase
        $tool1 = "spinner" ascii nocase
        $tool2 = "paraphrase" ascii nocase
        $tool3 = "rewrite" ascii nocase
        $detect1 = "Turnitin" ascii wide
        $detect2 = "bypass" ascii nocase

    condition:
        (2 of ($cheat*) and 1 of ($tool*)) or
        ($detect1 and $detect2)
}

rule Education_Zoom_Attack_Classroom
{
    meta:
        description = "Detects Zoom-bombing and virtual classroom attacks"
        severity = "medium"
        category = "education_attack"
        author = "MalwareAnalyzer"

    strings:
        $zoom1 = "Zoom" ascii wide
        $zoom2 = "zoom.us" ascii
        $zoom3 = "meeting ID" ascii wide nocase
        $attack1 = "bomb" ascii nocase
        $attack2 = "disrupt" ascii nocase
        $attack3 = "hijack" ascii nocase
        $scrape1 = "scrape" ascii nocase
        $scrape2 = "enumerate" ascii nocase
        $class = "class" ascii wide nocase

    condition:
        (1 of ($zoom*) and 1 of ($attack*) and $class) or
        (2 of ($zoom*) and 1 of ($scrape*))
}
