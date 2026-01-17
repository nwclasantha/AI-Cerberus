/*
    Obfuscation Techniques Detection
    Code obfuscation, encoding, and anti-analysis patterns
*/

rule Obfuscation_String_Encryption {
    meta:
        description = "String encryption/obfuscation"
        severity = "medium"
    strings:
        $xor = { 32 ?? 88 }
        $rol = { C0 C? ?? }
        $ror = { C0 C? ?? }
        $add = { 80 ?? ?? 88 }
        $decrypt = "decrypt" ascii nocase
        $deobfuscate = "deobfuscate" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (2 of ($xor, $rol, $ror, $add) or any of ($decrypt, $deobfuscate))
}

rule Obfuscation_API_Hashing {
    meta:
        description = "API hashing technique"
        severity = "high"
    strings:
        $hash1 = { 33 C0 AC 3C 00 74 }  // Common hash loop
        $hash2 = { 85 C0 74 ?? 8B ?? }  // Hash comparison
        $ror13 = "ror" ascii nocase
        $djb2 = "djb2" ascii nocase
        $crc32 = "crc32" ascii nocase
        $sdbm = "sdbm" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($hash*) or any of ($ror13, $djb2, $crc32, $sdbm))
}

rule Obfuscation_Control_Flow {
    meta:
        description = "Control flow obfuscation"
        severity = "medium"
    strings:
        $jmp1 = { E9 ?? ?? ?? ?? E9 }
        $jmp2 = { EB ?? EB ?? EB }
        $opaque = "opaque predicate" ascii nocase
        $flat = "flatten" ascii nocase
        $bogus = "bogus" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($jmp*) or any of ($opaque, $flat, $bogus))
}

rule Obfuscation_Dead_Code {
    meta:
        description = "Dead code insertion"
        severity = "low"
    strings:
        $nop1 = { 90 90 90 90 90 }
        $nop2 = { 66 90 66 90 66 90 }
        $xchg = { 87 C0 87 C0 }
        $push_pop = { 50 58 50 58 }
        $mov_self = { 8B C0 8B C0 }
    condition:
        uint16(0) == 0x5A4D and (2 of them)
}

rule Obfuscation_Base64_Multi {
    meta:
        description = "Multiple Base64 encoding"
        severity = "medium"
    strings:
        $b64 = "base64" ascii nocase
        $encode = "encode" ascii nocase
        $decode = "decode" ascii nocase
        $nested = "nested" ascii nocase
        $multi = "multi" ascii nocase
        $layer = "layer" ascii nocase
    condition:
        $b64 and (any of ($encode, $decode)) and any of ($nested, $multi, $layer)
}

rule Obfuscation_XOR_Single_Byte {
    meta:
        description = "Single-byte XOR encoding"
        severity = "medium"
    strings:
        $xor_pattern = { 80 3? ?? 74 ?? 80 3? ?? }
        $xor_loop = { 30 ?? 4? 75 }
        $key = "key" ascii nocase
        $xor = "xor" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($xor_pattern, $xor_loop) or ($key and $xor))
}

rule Obfuscation_XOR_Rolling {
    meta:
        description = "Rolling XOR encoding"
        severity = "high"
    strings:
        $rolling = "rolling" ascii nocase
        $xor = "xor" ascii nocase
        $previous = "previous" ascii nocase
        $chain = "chain" ascii nocase
        $loop = { 32 ?? ?? 88 ?? 4? 75 }
    condition:
        uint16(0) == 0x5A4D and (($rolling and $xor) or any of ($previous, $chain)) or $loop
}

rule Obfuscation_RC4 {
    meta:
        description = "RC4 encryption usage"
        severity = "high"
    strings:
        $rc4 = "RC4" ascii
        $arcfour = "ARCFOUR" ascii
        $sbox = { 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F }
        $ksa = "KSA" ascii
        $prga = "PRGA" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($rc4, $arcfour) or $sbox or any of ($ksa, $prga))
}

rule Obfuscation_Custom_Encoding {
    meta:
        description = "Custom encoding scheme"
        severity = "high"
    strings:
        $custom = "custom" ascii nocase
        $encode = "encode" ascii nocase
        $table = "table" ascii nocase
        $substitute = "substit" ascii nocase
        $transform = "transform" ascii nocase
    condition:
        uint16(0) == 0x5A4D and $custom and (any of ($encode, $table, $substitute, $transform))
}

rule Obfuscation_Stack_Strings {
    meta:
        description = "Stack-based string construction"
        severity = "high"
    strings:
        $mov_byte1 = { C6 45 ?? ?? C6 45 ?? ?? C6 45 ?? ?? }
        $mov_byte2 = { C6 44 24 ?? ?? C6 44 24 ?? ?? }
        $push_str = { 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? }
    condition:
        uint16(0) == 0x5A4D and (any of them)
}

rule Obfuscation_Indirect_Call {
    meta:
        description = "Indirect function calls"
        severity = "medium"
    strings:
        $call_reg1 = { FF D0 }  // call eax
        $call_reg2 = { FF D1 }  // call ecx
        $call_reg3 = { FF D2 }  // call edx
        $call_mem = { FF 15 ?? ?? ?? ?? }  // call [mem]
        $jmp_reg = { FF E0 }  // jmp eax
    condition:
        uint16(0) == 0x5A4D and (3 of them)
}

rule Obfuscation_Self_Modifying {
    meta:
        description = "Self-modifying code"
        severity = "critical"
    strings:
        $self = "self" ascii nocase
        $modify = "modify" ascii nocase
        $patch = "patch" ascii nocase
        $runtime = "runtime" ascii nocase
        $virtualprotect = "VirtualProtect" ascii
        $rwx = { C7 ?? ?? ?? ?? 40 }  // PAGE_EXECUTE_READWRITE
    condition:
        uint16(0) == 0x5A4D and (($self and $modify) or ($patch and $runtime) or ($virtualprotect and $rwx))
}

rule Obfuscation_Import_Reconstruction {
    meta:
        description = "Dynamic import reconstruction"
        severity = "high"
    strings:
        $loadlib = "LoadLibrary" ascii
        $getproc = "GetProcAddress" ascii
        $ldr = "LdrGetProcedureAddress" ascii
        $ntdll = "ntdll" ascii nocase
        $kernel32 = "kernel32" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($loadlib and $getproc) and any of ($ldr, $ntdll, $kernel32)
}

rule Obfuscation_Metamorphic {
    meta:
        description = "Metamorphic code indicators"
        severity = "critical"
    strings:
        $meta = "metamorphic" ascii nocase
        $morph = "morph" ascii nocase
        $mutate = "mutate" ascii nocase
        $evolve = "evolve" ascii nocase
        $generation = "generation" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (2 of them)
}

rule Obfuscation_Polymorphic {
    meta:
        description = "Polymorphic code indicators"
        severity = "critical"
    strings:
        $poly = "polymorphic" ascii nocase
        $decrypt = "decrypt" ascii nocase
        $stub = "stub" ascii nocase
        $engine = "engine" ascii nocase
        $generator = "generator" ascii nocase
    condition:
        uint16(0) == 0x5A4D and $poly and any of ($decrypt, $stub, $engine, $generator)
}

rule Obfuscation_Garbage_Bytes {
    meta:
        description = "Garbage byte insertion"
        severity = "low"
    strings:
        $garbage = { E8 ?? ?? ?? ?? EB ?? }
        $jump_over = { EB 02 ?? ?? }
        $call_pop = { E8 00 00 00 00 58 }
    condition:
        uint16(0) == 0x5A4D and (any of them)
}

rule Obfuscation_Stealth_Loader {
    meta:
        description = "Stealth loading technique"
        severity = "high"
    strings:
        $stealth = "stealth" ascii nocase
        $loader = "loader" ascii nocase
        $reflective = "reflective" ascii nocase
        $manual = "manual" ascii nocase
        $map = "map" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (($stealth and $loader) or ($reflective and any of ($manual, $map)))
}

rule Obfuscation_Time_Based {
    meta:
        description = "Time-based obfuscation"
        severity = "medium"
    strings:
        $sleep = "Sleep" ascii
        $delay = "delay" ascii nocase
        $time = "GetTickCount" ascii
        $rdtsc = { 0F 31 }  // rdtsc instruction
        $check = "check" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (2 of ($sleep, $delay, $time, $rdtsc)) and $check
}

rule Obfuscation_Environment_Keyed {
    meta:
        description = "Environment-keyed decryption"
        severity = "high"
    strings:
        $env = "environment" ascii nocase
        $host = "hostname" ascii nocase
        $user = "username" ascii nocase
        $machine = "machine" ascii nocase
        $key = "key" ascii nocase
        $decrypt = "decrypt" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($env, $host, $user, $machine)) and $key and $decrypt
}

