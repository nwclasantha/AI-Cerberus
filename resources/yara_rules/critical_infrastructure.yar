/*
    Critical Infrastructure Threats
    Power plants, dams, nuclear facilities, and essential services
*/

rule CriticalInfra_Nuclear_Plant {
    meta:
        description = "Nuclear facility attack"
        severity = "critical"
    strings:
        $nuclear = "nuclear" ascii nocase
        $plant = "plant" ascii nocase
        $reactor = "reactor" ascii nocase
        $scada = "SCADA" ascii
        $attack = "attack" ascii nocase
        $stuxnet = "Stuxnet" ascii nocase
    condition:
        $nuclear and (any of ($plant, $reactor)) and any of ($scada, $attack, $stuxnet)
}

rule CriticalInfra_Power_Plant {
    meta:
        description = "Power plant attack"
        severity = "critical"
    strings:
        $power = "power" ascii nocase
        $plant = "plant" ascii nocase
        $generation = "generation" ascii nocase
        $scada = "SCADA" ascii
        $attack = "attack" ascii nocase
        $shutdown = "shutdown" ascii nocase
    condition:
        $power and (any of ($plant, $generation)) and any of ($scada, $attack, $shutdown)
}

rule CriticalInfra_Dam_Control {
    meta:
        description = "Dam control system attack"
        severity = "critical"
    strings:
        $dam = "dam" ascii nocase
        $control = "control" ascii nocase
        $gate = "gate" ascii nocase
        $flood = "flood" ascii nocase
        $attack = "attack" ascii nocase
        $scada = "SCADA" ascii
    condition:
        $dam and any of ($control, $gate, $scada) and any of ($flood, $attack)
}

rule CriticalInfra_Oil_Gas {
    meta:
        description = "Oil and gas infrastructure attack"
        severity = "critical"
    strings:
        $oil = "oil" ascii nocase
        $gas = "gas" ascii nocase
        $pipeline = "pipeline" ascii nocase
        $refinery = "refinery" ascii nocase
        $scada = "SCADA" ascii
        $attack = "attack" ascii nocase
    condition:
        (any of ($oil, $gas)) and (any of ($pipeline, $refinery, $scada)) and $attack
}

rule CriticalInfra_Chemical_Plant {
    meta:
        description = "Chemical plant attack"
        severity = "critical"
    strings:
        $chemical = "chemical" ascii nocase
        $plant = "plant" ascii nocase
        $process = "process" ascii nocase
        $ics = "ICS" ascii
        $attack = "attack" ascii nocase
        $sabotage = "sabotage" ascii nocase
    condition:
        $chemical and $plant and any of ($process, $ics, $attack, $sabotage)
}

rule CriticalInfra_Hospital {
    meta:
        description = "Hospital system attack"
        severity = "critical"
    strings:
        $hospital = "hospital" ascii nocase
        $medical = "medical" ascii nocase
        $healthcare = "healthcare" ascii nocase
        $device = "device" ascii nocase
        $attack = "attack" ascii nocase
        $ransom = "ransom" ascii nocase
    condition:
        (any of ($hospital, $medical, $healthcare)) and any of ($device, $attack, $ransom)
}

rule CriticalInfra_Airport {
    meta:
        description = "Airport system attack"
        severity = "critical"
    strings:
        $airport = "airport" ascii nocase
        $aviation = "aviation" ascii nocase
        $atc = "ATC" ascii
        $radar = "radar" ascii nocase
        $attack = "attack" ascii nocase
        $disrupt = "disrupt" ascii nocase
    condition:
        (any of ($airport, $aviation, $atc)) and any of ($radar, $attack, $disrupt)
}

rule CriticalInfra_Port_Maritime {
    meta:
        description = "Port/maritime system attack"
        severity = "critical"
    strings:
        $port = "port" ascii nocase
        $maritime = "maritime" ascii nocase
        $shipping = "shipping" ascii nocase
        $container = "container" ascii nocase
        $attack = "attack" ascii nocase
        $disruption = "disruption" ascii nocase
    condition:
        (any of ($port, $maritime, $shipping)) and any of ($container, $attack, $disruption)
}

rule CriticalInfra_Railway {
    meta:
        description = "Railway system attack"
        severity = "critical"
    strings:
        $railway = "railway" ascii nocase
        $train = "train" ascii nocase
        $signal = "signal" ascii nocase
        $control = "control" ascii nocase
        $attack = "attack" ascii nocase
        $derail = "derail" ascii nocase
    condition:
        (any of ($railway, $train)) and any of ($signal, $control) and any of ($attack, $derail)
}

rule CriticalInfra_Telecom {
    meta:
        description = "Telecommunications attack"
        severity = "critical"
    strings:
        $telecom = "telecom" ascii nocase
        $network = "network" ascii nocase
        $infrastructure = "infrastructure" ascii nocase
        $bgp = "BGP" ascii
        $attack = "attack" ascii nocase
        $outage = "outage" ascii nocase
    condition:
        $telecom and any of ($network, $infrastructure, $bgp) and any of ($attack, $outage)
}

rule CriticalInfra_Financial {
    meta:
        description = "Financial infrastructure attack"
        severity = "critical"
    strings:
        $financial = "financial" ascii nocase
        $bank = "bank" ascii nocase
        $swift = "SWIFT" ascii
        $trading = "trading" ascii nocase
        $attack = "attack" ascii nocase
        $fraud = "fraud" ascii nocase
    condition:
        (any of ($financial, $bank, $swift)) and any of ($trading, $attack, $fraud)
}

rule CriticalInfra_Emergency_Services {
    meta:
        description = "Emergency services attack"
        severity = "critical"
    strings:
        $emergency = "emergency" ascii nocase
        $911 = "911" ascii
        $dispatch = "dispatch" ascii nocase
        $cad = "CAD" ascii
        $attack = "attack" ascii nocase
        $disrupt = "disrupt" ascii nocase
    condition:
        (any of ($emergency, $911, $dispatch)) and any of ($cad, $attack, $disrupt)
}

rule CriticalInfra_Food_Supply {
    meta:
        description = "Food supply chain attack"
        severity = "high"
    strings:
        $food = "food" ascii nocase
        $supply = "supply" ascii nocase
        $processing = "processing" ascii nocase
        $scada = "SCADA" ascii
        $attack = "attack" ascii nocase
        $contaminate = "contaminate" ascii nocase
    condition:
        $food and any of ($supply, $processing, $scada) and any of ($attack, $contaminate)
}

rule CriticalInfra_Wastewater {
    meta:
        description = "Wastewater system attack"
        severity = "critical"
    strings:
        $wastewater = "wastewater" ascii nocase
        $sewage = "sewage" ascii nocase
        $treatment = "treatment" ascii nocase
        $scada = "SCADA" ascii
        $attack = "attack" ascii nocase
    condition:
        (any of ($wastewater, $sewage)) and any of ($treatment, $scada) and $attack
}

rule CriticalInfra_Natural_Gas {
    meta:
        description = "Natural gas distribution attack"
        severity = "critical"
    strings:
        $natural = "natural" ascii nocase
        $gas = "gas" ascii nocase
        $distribution = "distribution" ascii nocase
        $pipeline = "pipeline" ascii nocase
        $attack = "attack" ascii nocase
        $explosion = "explosion" ascii nocase
    condition:
        $natural and $gas and any of ($distribution, $pipeline) and any of ($attack, $explosion)
}

