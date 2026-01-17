/*
    Smart City Infrastructure Threats
    Smart grid, traffic systems, and urban infrastructure attacks
*/

rule SmartCity_Traffic_Attack {
    meta:
        description = "Traffic control system attack"
        severity = "critical"
    strings:
        $traffic = "traffic" ascii nocase
        $signal = "signal" ascii nocase
        $light = "light" ascii nocase
        $control = "control" ascii nocase
        $attack = "attack" ascii nocase
        $hack = "hack" ascii nocase
    condition:
        $traffic and (any of ($signal, $light)) and any of ($control, $attack, $hack)
}

rule SmartCity_Power_Grid {
    meta:
        description = "Smart grid attack"
        severity = "critical"
    strings:
        $smart = "smart" ascii nocase
        $grid = "grid" ascii nocase
        $power = "power" ascii nocase
        $scada = "SCADA" ascii
        $attack = "attack" ascii nocase
        $outage = "outage" ascii nocase
    condition:
        ($smart and $grid) or ($power and $scada) and any of ($attack, $outage)
}

rule SmartCity_Water_System {
    meta:
        description = "Water system attack"
        severity = "critical"
    strings:
        $water = "water" ascii nocase
        $treatment = "treatment" ascii nocase
        $pump = "pump" ascii nocase
        $scada = "SCADA" ascii
        $attack = "attack" ascii nocase
        $contaminate = "contaminate" ascii nocase
    condition:
        $water and (any of ($treatment, $pump, $scada)) and any of ($attack, $contaminate)
}

rule SmartCity_Surveillance {
    meta:
        description = "City surveillance system attack"
        severity = "critical"
    strings:
        $cctv = "CCTV" ascii
        $camera = "camera" ascii nocase
        $surveillance = "surveillance" ascii nocase
        $attack = "attack" ascii nocase
        $access = "access" ascii nocase
        $compromise = "compromise" ascii nocase
    condition:
        (any of ($cctv, $camera, $surveillance)) and any of ($attack, $access, $compromise)
}

rule SmartCity_Parking_System {
    meta:
        description = "Smart parking system attack"
        severity = "medium"
    strings:
        $parking = "parking" ascii nocase
        $smart = "smart" ascii nocase
        $meter = "meter" ascii nocase
        $attack = "attack" ascii nocase
        $bypass = "bypass" ascii nocase
    condition:
        $parking and any of ($smart, $meter) and any of ($attack, $bypass)
}

rule SmartCity_Street_Lighting {
    meta:
        description = "Street lighting system attack"
        severity = "medium"
    strings:
        $street = "street" ascii nocase
        $lighting = "lighting" ascii nocase
        $led = "LED" ascii
        $control = "control" ascii nocase
        $attack = "attack" ascii nocase
    condition:
        ($street and $lighting) and any of ($led, $control, $attack)
}

rule SmartCity_Waste_Management {
    meta:
        description = "Waste management system attack"
        severity = "low"
    strings:
        $waste = "waste" ascii nocase
        $bin = "bin" ascii nocase
        $sensor = "sensor" ascii nocase
        $iot = "IoT" ascii nocase
        $attack = "attack" ascii nocase
    condition:
        $waste and any of ($bin, $sensor, $iot) and $attack
}

rule SmartCity_Transit_System {
    meta:
        description = "Public transit system attack"
        severity = "critical"
    strings:
        $transit = "transit" ascii nocase
        $bus = "bus" ascii nocase
        $train = "train" ascii nocase
        $metro = "metro" ascii nocase
        $control = "control" ascii nocase
        $attack = "attack" ascii nocase
    condition:
        (any of ($transit, $bus, $train, $metro)) and any of ($control, $attack)
}

rule SmartCity_Emergency_System {
    meta:
        description = "Emergency system attack"
        severity = "critical"
    strings:
        $emergency = "emergency" ascii nocase
        $911 = "911" ascii
        $dispatch = "dispatch" ascii nocase
        $alert = "alert" ascii nocase
        $attack = "attack" ascii nocase
        $disrupt = "disrupt" ascii nocase
    condition:
        (any of ($emergency, $911, $dispatch)) and any of ($alert, $attack, $disrupt)
}

rule SmartCity_Building_Automation {
    meta:
        description = "Building automation attack"
        severity = "high"
    strings:
        $building = "building" ascii nocase
        $automation = "automation" ascii nocase
        $bms = "BMS" ascii
        $hvac = "HVAC" ascii
        $attack = "attack" ascii nocase
        $control = "control" ascii nocase
    condition:
        ($building and $automation) or (any of ($bms, $hvac)) and any of ($attack, $control)
}

rule SmartCity_Sensor_Network {
    meta:
        description = "City sensor network attack"
        severity = "high"
    strings:
        $sensor = "sensor" ascii nocase
        $network = "network" ascii nocase
        $city = "city" ascii nocase
        $iot = "IoT" ascii nocase
        $attack = "attack" ascii nocase
        $compromise = "compromise" ascii nocase
    condition:
        $sensor and $network and any of ($city, $iot) and any of ($attack, $compromise)
}

rule SmartCity_EV_Charging {
    meta:
        description = "EV charging infrastructure attack"
        severity = "high"
    strings:
        $ev = "EV" ascii
        $charging = "charging" ascii nocase
        $station = "station" ascii nocase
        $grid = "grid" ascii nocase
        $attack = "attack" ascii nocase
    condition:
        $ev and $charging and any of ($station, $grid, $attack)
}

rule SmartCity_Air_Quality {
    meta:
        description = "Air quality monitoring attack"
        severity = "medium"
    strings:
        $air = "air" ascii nocase
        $quality = "quality" ascii nocase
        $monitor = "monitor" ascii nocase
        $sensor = "sensor" ascii nocase
        $spoof = "spoof" ascii nocase
    condition:
        $air and $quality and any of ($monitor, $sensor, $spoof)
}

rule SmartCity_Bridge_Tunnel {
    meta:
        description = "Bridge/tunnel system attack"
        severity = "critical"
    strings:
        $bridge = "bridge" ascii nocase
        $tunnel = "tunnel" ascii nocase
        $control = "control" ascii nocase
        $system = "system" ascii nocase
        $attack = "attack" ascii nocase
    condition:
        (any of ($bridge, $tunnel)) and any of ($control, $system) and $attack
}

rule SmartCity_5G_Infrastructure {
    meta:
        description = "5G infrastructure attack"
        severity = "critical"
    strings:
        $5g = "5G" ascii
        $infrastructure = "infrastructure" ascii nocase
        $base = "base station" ascii nocase
        $attack = "attack" ascii nocase
        $exploit = "exploit" ascii nocase
    condition:
        $5g and any of ($infrastructure, $base) and any of ($attack, $exploit)
}

