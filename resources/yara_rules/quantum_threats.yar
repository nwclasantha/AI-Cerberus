/*
    Quantum Computing Threats Detection
    Post-quantum cryptography threats and quantum-related attacks
*/

rule Quantum_Harvest_Now {
    meta:
        description = "Harvest now decrypt later attack"
        severity = "critical"
    strings:
        $harvest = "harvest" ascii nocase
        $later = "later" ascii nocase
        $quantum = "quantum" ascii nocase
        $decrypt = "decrypt" ascii nocase
        $store = "store" ascii nocase
        $future = "future" ascii nocase
    condition:
        $harvest and (any of ($later, $future)) and any of ($quantum, $decrypt, $store)
}

rule Quantum_Crypto_Attack {
    meta:
        description = "Quantum cryptographic attack"
        severity = "critical"
    strings:
        $quantum = "quantum" ascii nocase
        $crypto = "crypto" ascii nocase
        $rsa = "RSA" ascii
        $ecc = "ECC" ascii
        $break = "break" ascii nocase
        $factor = "factor" ascii nocase
    condition:
        $quantum and any of ($crypto, $rsa, $ecc) and any of ($break, $factor)
}

rule Quantum_Key_Distribution {
    meta:
        description = "QKD attack"
        severity = "critical"
    strings:
        $qkd = "QKD" ascii
        $quantum = "quantum" ascii nocase
        $key = "key" ascii nocase
        $distribution = "distribution" ascii nocase
        $attack = "attack" ascii nocase
        $intercept = "intercept" ascii nocase
    condition:
        ($qkd or ($quantum and $key and $distribution)) and any of ($attack, $intercept)
}

rule Quantum_Shor_Algorithm {
    meta:
        description = "Shor's algorithm implementation"
        severity = "high"
    strings:
        $shor = "Shor" ascii nocase
        $algorithm = "algorithm" ascii nocase
        $factor = "factor" ascii nocase
        $quantum = "quantum" ascii nocase
        $integer = "integer" ascii nocase
    condition:
        $shor and any of ($algorithm, $factor, $quantum, $integer)
}

rule Quantum_Grover_Attack {
    meta:
        description = "Grover's algorithm attack"
        severity = "high"
    strings:
        $grover = "Grover" ascii nocase
        $search = "search" ascii nocase
        $quantum = "quantum" ascii nocase
        $speedup = "speedup" ascii nocase
        $symmetric = "symmetric" ascii nocase
    condition:
        $grover and any of ($search, $quantum, $speedup, $symmetric)
}

rule Quantum_RNG_Attack {
    meta:
        description = "Quantum RNG attack"
        severity = "high"
    strings:
        $qrng = "QRNG" ascii
        $quantum = "quantum" ascii nocase
        $random = "random" ascii nocase
        $generator = "generator" ascii nocase
        $attack = "attack" ascii nocase
        $predict = "predict" ascii nocase
    condition:
        ($qrng or ($quantum and $random and $generator)) and any of ($attack, $predict)
}

rule Quantum_Side_Channel {
    meta:
        description = "Quantum side channel attack"
        severity = "critical"
    strings:
        $quantum = "quantum" ascii nocase
        $side = "side channel" ascii nocase
        $timing = "timing" ascii nocase
        $power = "power" ascii nocase
        $leak = "leak" ascii nocase
    condition:
        $quantum and $side and any of ($timing, $power, $leak)
}

rule Quantum_Post_Crypto {
    meta:
        description = "Post-quantum crypto attack"
        severity = "high"
    strings:
        $post = "post-quantum" ascii nocase
        $lattice = "lattice" ascii nocase
        $ntru = "NTRU" ascii
        $kyber = "Kyber" ascii
        $dilithium = "Dilithium" ascii
        $attack = "attack" ascii nocase
    condition:
        ($post or any of ($lattice, $ntru, $kyber, $dilithium)) and $attack
}

rule Quantum_Entanglement_Exploit {
    meta:
        description = "Quantum entanglement exploitation"
        severity = "critical"
    strings:
        $entangle = "entangle" ascii nocase
        $quantum = "quantum" ascii nocase
        $exploit = "exploit" ascii nocase
        $pair = "pair" ascii nocase
        $qubit = "qubit" ascii nocase
    condition:
        $entangle and $quantum and any of ($exploit, $pair, $qubit)
}

rule Quantum_Computer_Access {
    meta:
        description = "Unauthorized quantum computer access"
        severity = "critical"
    strings:
        $quantum = "quantum" ascii nocase
        $computer = "computer" ascii nocase
        $access = "access" ascii nocase
        $ibm = "IBM" ascii
        $google = "Google" ascii
        $qiskit = "Qiskit" ascii
    condition:
        $quantum and $computer and any of ($access, $ibm, $google, $qiskit)
}

rule Quantum_Algorithm_Theft {
    meta:
        description = "Quantum algorithm theft"
        severity = "high"
    strings:
        $quantum = "quantum" ascii nocase
        $algorithm = "algorithm" ascii nocase
        $steal = "steal" ascii nocase
        $theft = "theft" ascii nocase
        $proprietary = "proprietary" ascii nocase
    condition:
        $quantum and $algorithm and any of ($steal, $theft, $proprietary)
}

rule Quantum_Supremacy_Attack {
    meta:
        description = "Quantum supremacy attack"
        severity = "critical"
    strings:
        $supremacy = "supremacy" ascii nocase
        $advantage = "advantage" ascii nocase
        $quantum = "quantum" ascii nocase
        $classical = "classical" ascii nocase
        $break = "break" ascii nocase
    condition:
        (any of ($supremacy, $advantage)) and $quantum and any of ($classical, $break)
}

rule Quantum_Error_Exploit {
    meta:
        description = "Quantum error exploitation"
        severity = "medium"
    strings:
        $quantum = "quantum" ascii nocase
        $error = "error" ascii nocase
        $correction = "correction" ascii nocase
        $exploit = "exploit" ascii nocase
        $noise = "noise" ascii nocase
    condition:
        $quantum and $error and any of ($correction, $exploit, $noise)
}

rule Quantum_Network_Attack {
    meta:
        description = "Quantum network attack"
        severity = "critical"
    strings:
        $quantum = "quantum" ascii nocase
        $network = "network" ascii nocase
        $internet = "internet" ascii nocase
        $attack = "attack" ascii nocase
        $repeater = "repeater" ascii nocase
    condition:
        $quantum and (any of ($network, $internet)) and any of ($attack, $repeater)
}

rule Quantum_Simulation_Attack {
    meta:
        description = "Quantum simulation attack"
        severity = "medium"
    strings:
        $quantum = "quantum" ascii nocase
        $simulation = "simulation" ascii nocase
        $emulator = "emulator" ascii nocase
        $attack = "attack" ascii nocase
        $fake = "fake" ascii nocase
    condition:
        $quantum and any of ($simulation, $emulator) and any of ($attack, $fake)
}

