/*
    Cryptominer Detection Rules
    Covers: XMRig, Monero miners, coin miners, etc.
*/

rule XMRig_Miner {
    meta:
        description = "XMRig cryptocurrency miner"
        severity = "high"
    strings:
        $s1 = "xmrig" nocase
        $s2 = "stratum+tcp://" ascii
        $s3 = "stratum+ssl://" ascii
        $s4 = "pool.minexmr.com" ascii
        $s5 = "donate-level" ascii
        $s6 = "--coin=" ascii
    condition:
        2 of them
}

rule XMRig_Config {
    meta:
        description = "XMRig miner configuration"
        severity = "high"
    strings:
        $s1 = "\"algo\"" ascii
        $s2 = "\"url\"" ascii
        $s3 = "\"user\"" ascii
        $s4 = "\"pass\"" ascii
        $s5 = "randomx" ascii
        $s6 = "rx/0" ascii
    condition:
        3 of them
}

rule Monero_Miner_Generic {
    meta:
        description = "Generic Monero miner"
        severity = "high"
    strings:
        $s1 = "monero" nocase
        $s2 = "xmr" nocase
        $s3 = "cryptonight" ascii
        $s4 = "hashrate" ascii
        $s5 = "accepted" ascii
        $pool1 = "pool.supportxmr.com" ascii
        $pool2 = "xmr.nanopool.org" ascii
    condition:
        2 of ($s*) or any of ($pool*)
}

rule CoinHive_Miner {
    meta:
        description = "CoinHive browser miner"
        severity = "high"
    strings:
        $s1 = "CoinHive" ascii
        $s2 = "coinhive.com" ascii
        $s3 = "coinhive.min.js" ascii
        $s4 = "CoinHive.Anonymous" ascii
    condition:
        any of them
}

rule JSCoinMiner {
    meta:
        description = "JavaScript coin miner"
        severity = "high"
    strings:
        $s1 = "Cryptonight" ascii
        $s2 = "CryptoNight" ascii
        $s3 = "miner.start" ascii
        $s4 = "miner.stop" ascii
        $s5 = "wasm" ascii
    condition:
        2 of them
}

rule WannaMine {
    meta:
        description = "WannaMine cryptominer"
        severity = "high"
    strings:
        $s1 = "WannaMine" ascii
        $s2 = "EternalBlue" ascii
        $s3 = "DoublePulsar" ascii
        $ps = "powershell" nocase
    condition:
        any of ($s*) or $ps
}

rule PowerGhost_Miner {
    meta:
        description = "PowerGhost cryptominer"
        severity = "high"
    strings:
        $s1 = "PowerGhost" ascii
        $s2 = "YOURFILEISSTILLHERE" ascii
        $ps1 = "Invoke-Expression" ascii
        $ps2 = "downloadstring" nocase
    condition:
        any of ($s*) or all of ($ps*)
}

rule Adylkuzz_Miner {
    meta:
        description = "Adylkuzz cryptominer"
        severity = "high"
    strings:
        $s1 = "adylkuzz" nocase
        $s2 = "xmr-stak" ascii
        $s3 = "cryptonight" ascii
    condition:
        any of them
}

rule Outlaw_Miner {
    meta:
        description = "Outlaw cryptomining botnet"
        severity = "high"
    strings:
        $s1 = "outlaw" nocase
        $s2 = "/tmp/.X11-unix" ascii
        $s3 = "cron" ascii
        $s4 = "xmrig" ascii
    condition:
        2 of them
}

rule Lemon_Duck_Miner {
    meta:
        description = "Lemon Duck cryptominer"
        severity = "high"
    strings:
        $s1 = "lemon_duck" ascii
        $s2 = "LemonDuck" ascii
        $ps = "Invoke-MSSqlQuery" ascii
        $ssh = "plink" ascii
    condition:
        any of ($s*) or ($ps and $ssh)
}

rule Kinsing_Miner {
    meta:
        description = "Kinsing cryptominer"
        severity = "high"
    strings:
        $s1 = "kinsing" nocase
        $s2 = "kdevtmpfsi" ascii
        $s3 = "/tmp/kinsing" ascii
        $s4 = "masscan" ascii
    condition:
        any of them
}

rule TeamTNT_Miner {
    meta:
        description = "TeamTNT cryptominer"
        severity = "high"
    strings:
        $s1 = "TeamTNT" ascii
        $s2 = "teamtnt" ascii
        $s3 = "chimaera" ascii
        $s4 = "masscan" ascii
        $s5 = "grabAWScreds" ascii
    condition:
        2 of them
}

rule Rocke_Miner {
    meta:
        description = "Rocke Group cryptominer"
        severity = "high"
    strings:
        $s1 = "rocke" nocase
        $s2 = "kerberods" ascii
        $s3 = "ld.so.preload" ascii
        $cron = "cron" ascii
    condition:
        any of ($s*) or $cron
}

rule Hidden_Miner {
    meta:
        description = "Hidden cryptominer indicators"
        severity = "high"
    strings:
        $s1 = "NiceHash" ascii
        $s2 = "nicehash" ascii
        $s3 = "cpuminer" ascii
        $s4 = "minerd" ascii
        $s5 = "bfgminer" ascii
        $s6 = "cgminer" ascii
    condition:
        any of them
}

rule Browser_Mining_Script {
    meta:
        description = "Browser-based mining script"
        severity = "medium"
    strings:
        $s1 = "crypto-loot.com" ascii
        $s2 = "webmine.pro" ascii
        $s3 = "authedmine.com" ascii
        $s4 = "mineralt.io" ascii
        $s5 = "webminepool.com" ascii
    condition:
        any of them
}

rule Claymore_Miner {
    meta:
        description = "Claymore cryptocurrency miner"
        severity = "high"
    strings:
        $s1 = "Claymore" ascii
        $s2 = "ETH:" ascii
        $s3 = "GPU0" ascii
        $s4 = "epools.txt" ascii
    condition:
        2 of them
}

rule NBMiner {
    meta:
        description = "NBMiner cryptocurrency miner"
        severity = "high"
    strings:
        $s1 = "NBMiner" ascii
        $s2 = "nbminer" ascii
        $s3 = "kawpow" ascii
        $s4 = "octopus" ascii
    condition:
        any of them
}

rule T_Rex_Miner {
    meta:
        description = "T-Rex cryptocurrency miner"
        severity = "high"
    strings:
        $s1 = "t-rex" ascii
        $s2 = "T-Rex" ascii
        $s3 = "GPU #" ascii
        $algo = "ethash" ascii
    condition:
        any of ($s*) or $algo
}

rule PhoenixMiner {
    meta:
        description = "Phoenix Miner"
        severity = "high"
    strings:
        $s1 = "PhoenixMiner" ascii
        $s2 = "phoenixminer" ascii
        $s3 = "Dual Mining" ascii
    condition:
        any of them
}

rule Crypto_Pool_Generic {
    meta:
        description = "Generic cryptocurrency mining pool connection"
        severity = "medium"
    strings:
        $pool1 = "nanopool.org" ascii
        $pool2 = "f2pool.com" ascii
        $pool3 = "antpool.com" ascii
        $pool4 = "slushpool.com" ascii
        $pool5 = "ethermine.org" ascii
        $pool6 = "2miners.com" ascii
        $pool7 = "sparkpool.com" ascii
        $pool8 = "poolin.com" ascii
    condition:
        any of them
}
