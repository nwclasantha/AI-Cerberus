/*
    Space and Satellite System Security
    Satellite communication, GPS, and space infrastructure threats
*/

rule Space_Satellite_Attack {
    meta:
        description = "Satellite system attack indicators"
        severity = "critical"
    strings:
        $satellite = "satellite" ascii nocase
        $attack = "attack" ascii nocase
        $jamming = "jamming" ascii nocase
        $spoofing = "spoofing" ascii nocase
        $signal = "signal" ascii nocase
        $uplink = "uplink" ascii nocase
    condition:
        $satellite and any of ($attack, $jamming, $spoofing) and any of ($signal, $uplink)
}

rule Space_GPS_Spoofing {
    meta:
        description = "GPS spoofing attack"
        severity = "critical"
    strings:
        $gps = "GPS" ascii
        $gnss = "GNSS" ascii
        $spoof = "spoof" ascii nocase
        $fake = "fake" ascii nocase
        $location = "location" ascii nocase
        $timing = "timing" ascii nocase
    condition:
        (any of ($gps, $gnss)) and any of ($spoof, $fake) and any of ($location, $timing)
}

rule Space_VSAT_Attack {
    meta:
        description = "VSAT terminal attack"
        severity = "critical"
    strings:
        $vsat = "VSAT" ascii
        $terminal = "terminal" ascii nocase
        $modem = "modem" ascii nocase
        $exploit = "exploit" ascii nocase
        $firmware = "firmware" ascii nocase
    condition:
        $vsat and any of ($terminal, $modem) and any of ($exploit, $firmware)
}

rule Space_TLE_Manipulation {
    meta:
        description = "TLE data manipulation"
        severity = "high"
    strings:
        $tle = "TLE" ascii
        $two_line = "Two-Line Element" ascii nocase
        $orbit = "orbit" ascii nocase
        $track = "track" ascii nocase
        $manipulate = "manipulate" ascii nocase
        $false = "false" ascii nocase
    condition:
        ($tle or $two_line) and any of ($orbit, $track) and any of ($manipulate, $false)
}

rule Space_Ground_Station {
    meta:
        description = "Ground station attack"
        severity = "critical"
    strings:
        $ground = "ground station" ascii nocase
        $antenna = "antenna" ascii nocase
        $control = "control" ascii nocase
        $command = "command" ascii nocase
        $telemetry = "telemetry" ascii nocase
        $attack = "attack" ascii nocase
    condition:
        ($ground or $antenna) and any of ($control, $command, $telemetry) and $attack
}

rule Space_Link_Jamming {
    meta:
        description = "Satellite link jamming"
        severity = "critical"
    strings:
        $jam = "jam" ascii nocase
        $interference = "interference" ascii nocase
        $frequency = "frequency" ascii nocase
        $rf = "RF" ascii
        $band = "band" ascii nocase
        $satellite = "satellite" ascii nocase
    condition:
        (any of ($jam, $interference)) and any of ($frequency, $rf, $band) and $satellite
}

rule Space_Starlink_Attack {
    meta:
        description = "Starlink constellation attack"
        severity = "critical"
    strings:
        $starlink = "Starlink" ascii nocase
        $spacex = "SpaceX" ascii nocase
        $leo = "LEO" ascii
        $attack = "attack" ascii nocase
        $terminal = "terminal" ascii nocase
    condition:
        (any of ($starlink, $spacex, $leo)) and any of ($attack, $terminal)
}

rule Space_SDR_Satellite {
    meta:
        description = "SDR satellite signal interception"
        severity = "high"
    strings:
        $sdr = "SDR" ascii
        $software = "software defined" ascii nocase
        $satellite = "satellite" ascii nocase
        $receive = "receive" ascii nocase
        $intercept = "intercept" ascii nocase
    condition:
        $sdr and any of ($software, $satellite) and any of ($receive, $intercept)
}

rule Space_Encryption_Attack {
    meta:
        description = "Satellite encryption attack"
        severity = "critical"
    strings:
        $satellite = "satellite" ascii nocase
        $encrypt = "encrypt" ascii nocase
        $key = "key" ascii nocase
        $break = "break" ascii nocase
        $bypass = "bypass" ascii nocase
    condition:
        $satellite and $encrypt and any of ($key, $break, $bypass)
}

rule Space_Debris_Tracking {
    meta:
        description = "Space debris tracking manipulation"
        severity = "medium"
    strings:
        $debris = "debris" ascii nocase
        $tracking = "tracking" ascii nocase
        $collision = "collision" ascii nocase
        $warning = "warning" ascii nocase
        $false = "false" ascii nocase
    condition:
        $debris and $tracking and any of ($collision, $warning, $false)
}

rule Space_ISS_Systems {
    meta:
        description = "ISS system targeting"
        severity = "critical"
    strings:
        $iss = "ISS" ascii
        $space_station = "space station" ascii nocase
        $system = "system" ascii nocase
        $attack = "attack" ascii nocase
        $compromise = "compromise" ascii nocase
    condition:
        ($iss or $space_station) and any of ($system, $attack, $compromise)
}

rule Space_Weather_Satellite {
    meta:
        description = "Weather satellite interference"
        severity = "high"
    strings:
        $weather = "weather" ascii nocase
        $satellite = "satellite" ascii nocase
        $noaa = "NOAA" ascii
        $goes = "GOES" ascii
        $interfere = "interfere" ascii nocase
        $jam = "jam" ascii nocase
    condition:
        $weather and $satellite and (any of ($noaa, $goes) or any of ($interfere, $jam))
}

rule Space_Communication_Intercept {
    meta:
        description = "Satellite communication interception"
        severity = "critical"
    strings:
        $satellite = "satellite" ascii nocase
        $communication = "communication" ascii nocase
        $intercept = "intercept" ascii nocase
        $eavesdrop = "eavesdrop" ascii nocase
        $sigint = "SIGINT" ascii
    condition:
        $satellite and $communication and any of ($intercept, $eavesdrop, $sigint)
}

rule Space_ADS_B_Spoof {
    meta:
        description = "ADS-B spoofing"
        severity = "critical"
    strings:
        $adsb = "ADS-B" ascii
        $aircraft = "aircraft" ascii nocase
        $spoof = "spoof" ascii nocase
        $fake = "fake" ascii nocase
        $position = "position" ascii nocase
    condition:
        $adsb and any of ($aircraft, $spoof, $fake, $position)
}

rule Space_Launch_System {
    meta:
        description = "Launch system targeting"
        severity = "critical"
    strings:
        $launch = "launch" ascii nocase
        $rocket = "rocket" ascii nocase
        $system = "system" ascii nocase
        $control = "control" ascii nocase
        $attack = "attack" ascii nocase
        $sabotage = "sabotage" ascii nocase
    condition:
        ($launch or $rocket) and $system and any of ($control, $attack, $sabotage)
}

