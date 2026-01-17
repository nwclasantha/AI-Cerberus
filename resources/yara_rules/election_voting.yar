/*
    Election and Voting System Security
    Voting machine, election infrastructure, and ballot threats
*/

rule Election_Voting_Machine {
    meta:
        description = "Voting machine attack"
        severity = "critical"
    strings:
        $voting = "voting" ascii nocase
        $machine = "machine" ascii nocase
        $ballot = "ballot" ascii nocase
        $attack = "attack" ascii nocase
        $hack = "hack" ascii nocase
        $exploit = "exploit" ascii nocase
    condition:
        ($voting or $ballot) and $machine and any of ($attack, $hack, $exploit)
}

rule Election_Database_Attack {
    meta:
        description = "Voter database attack"
        severity = "critical"
    strings:
        $voter = "voter" ascii nocase
        $database = "database" ascii nocase
        $registration = "registration" ascii nocase
        $attack = "attack" ascii nocase
        $compromise = "compromise" ascii nocase
        $modify = "modify" ascii nocase
    condition:
        $voter and any of ($database, $registration) and any of ($attack, $compromise, $modify)
}

rule Election_Results_Manipulation {
    meta:
        description = "Election results manipulation"
        severity = "critical"
    strings:
        $election = "election" ascii nocase
        $results = "results" ascii nocase
        $tally = "tally" ascii nocase
        $count = "count" ascii nocase
        $manipulate = "manipulate" ascii nocase
        $alter = "alter" ascii nocase
    condition:
        $election and (any of ($results, $tally, $count)) and any of ($manipulate, $alter)
}

rule Election_Software_Attack {
    meta:
        description = "Election software attack"
        severity = "critical"
    strings:
        $election = "election" ascii nocase
        $software = "software" ascii nocase
        $dominion = "Dominion" ascii nocase
        $es_s = "ES&S" ascii
        $attack = "attack" ascii nocase
        $vulnerability = "vulnerability" ascii nocase
    condition:
        $election and any of ($software, $dominion, $es_s) and any of ($attack, $vulnerability)
}

rule Election_Network_Attack {
    meta:
        description = "Election network infrastructure attack"
        severity = "critical"
    strings:
        $election = "election" ascii nocase
        $network = "network" ascii nocase
        $infrastructure = "infrastructure" ascii nocase
        $attack = "attack" ascii nocase
        $penetrate = "penetrate" ascii nocase
    condition:
        $election and any of ($network, $infrastructure) and any of ($attack, $penetrate)
}

rule Election_Disinformation {
    meta:
        description = "Election disinformation campaign"
        severity = "high"
    strings:
        $election = "election" ascii nocase
        $disinformation = "disinformation" ascii nocase
        $fake = "fake" ascii nocase
        $spread = "spread" ascii nocase
        $campaign = "campaign" ascii nocase
        $social = "social media" ascii nocase
    condition:
        $election and (any of ($disinformation, $fake)) and any of ($spread, $campaign, $social)
}

rule Election_DDoS_Attack {
    meta:
        description = "Election website DDoS"
        severity = "high"
    strings:
        $election = "election" ascii nocase
        $ddos = "DDoS" ascii nocase
        $denial = "denial" ascii nocase
        $service = "service" ascii nocase
        $website = "website" ascii nocase
    condition:
        $election and ($ddos or ($denial and $service)) and $website
}

rule Election_Email_Compromise {
    meta:
        description = "Election official email compromise"
        severity = "critical"
    strings:
        $election = "election" ascii nocase
        $official = "official" ascii nocase
        $email = "email" ascii nocase
        $compromise = "compromise" ascii nocase
        $phish = "phish" ascii nocase
    condition:
        $election and $official and $email and any of ($compromise, $phish)
}

rule Election_Tabulation_Attack {
    meta:
        description = "Vote tabulation system attack"
        severity = "critical"
    strings:
        $tabulation = "tabulation" ascii nocase
        $vote = "vote" ascii nocase
        $count = "count" ascii nocase
        $system = "system" ascii nocase
        $attack = "attack" ascii nocase
        $alter = "alter" ascii nocase
    condition:
        $tabulation and any of ($vote, $count) and any of ($system, $attack, $alter)
}

rule Election_Poll_Book {
    meta:
        description = "Electronic poll book attack"
        severity = "high"
    strings:
        $poll = "poll" ascii nocase
        $book = "book" ascii nocase
        $epoll = "e-poll" ascii nocase
        $electronic = "electronic" ascii nocase
        $attack = "attack" ascii nocase
    condition:
        ($poll and $book) or $epoll and any of ($electronic, $attack)
}

rule Election_Ballot_Marking {
    meta:
        description = "Ballot marking device attack"
        severity = "critical"
    strings:
        $ballot = "ballot" ascii nocase
        $marking = "marking" ascii nocase
        $device = "device" ascii nocase
        $bmd = "BMD" ascii
        $attack = "attack" ascii nocase
        $manipulate = "manipulate" ascii nocase
    condition:
        $ballot and any of ($marking, $bmd) and any of ($device, $attack, $manipulate)
}

rule Election_Optical_Scan {
    meta:
        description = "Optical scanner attack"
        severity = "critical"
    strings:
        $optical = "optical" ascii nocase
        $scanner = "scanner" ascii nocase
        $scan = "scan" ascii nocase
        $ballot = "ballot" ascii nocase
        $attack = "attack" ascii nocase
    condition:
        $optical and any of ($scanner, $scan) and any of ($ballot, $attack)
}

rule Election_Remote_Access {
    meta:
        description = "Unauthorized election system access"
        severity = "critical"
    strings:
        $election = "election" ascii nocase
        $remote = "remote" ascii nocase
        $access = "access" ascii nocase
        $unauthorized = "unauthorized" ascii nocase
        $modem = "modem" ascii nocase
    condition:
        $election and $remote and $access and any of ($unauthorized, $modem)
}

rule Election_USB_Attack {
    meta:
        description = "Election system USB attack"
        severity = "critical"
    strings:
        $election = "election" ascii nocase
        $usb = "USB" ascii
        $voting = "voting" ascii nocase
        $malware = "malware" ascii nocase
        $inject = "inject" ascii nocase
    condition:
        $election and $usb and any of ($voting, $malware, $inject)
}

rule Election_Audit_Tampering {
    meta:
        description = "Election audit tampering"
        severity = "critical"
    strings:
        $election = "election" ascii nocase
        $audit = "audit" ascii nocase
        $log = "log" ascii nocase
        $tamper = "tamper" ascii nocase
        $delete = "delete" ascii nocase
        $modify = "modify" ascii nocase
    condition:
        $election and $audit and any of ($log, $tamper, $delete, $modify)
}

