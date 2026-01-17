/*
    AI/ML Attack Detection
    Adversarial machine learning and AI security threats
*/

rule AIML_Adversarial_Example {
    meta:
        description = "Adversarial example generation"
        severity = "high"
    strings:
        $adversarial = "adversarial" ascii nocase
        $example = "example" ascii nocase
        $perturbation = "perturbation" ascii nocase
        $fgsm = "FGSM" ascii
        $pgd = "PGD" ascii
        $carlini = "Carlini" ascii
    condition:
        ($adversarial and $example) or any of ($perturbation, $fgsm, $pgd, $carlini)
}

rule AIML_Model_Poisoning {
    meta:
        description = "ML model poisoning attack"
        severity = "critical"
    strings:
        $model = "model" ascii nocase
        $poison = "poison" ascii nocase
        $backdoor = "backdoor" ascii nocase
        $training = "training" ascii nocase
        $data = "data" ascii nocase
        $trojan = "trojan" ascii nocase
    condition:
        $model and (any of ($poison, $backdoor, $trojan)) and any of ($training, $data)
}

rule AIML_Model_Extraction {
    meta:
        description = "ML model extraction attack"
        severity = "critical"
    strings:
        $model = "model" ascii nocase
        $extract = "extract" ascii nocase
        $steal = "steal" ascii nocase
        $query = "query" ascii nocase
        $api = "API" ascii
        $reverse = "reverse" ascii nocase
    condition:
        $model and (any of ($extract, $steal)) and any of ($query, $api, $reverse)
}

rule AIML_Membership_Inference {
    meta:
        description = "Membership inference attack"
        severity = "high"
    strings:
        $membership = "membership" ascii nocase
        $inference = "inference" ascii nocase
        $attack = "attack" ascii nocase
        $training = "training" ascii nocase
        $data = "data" ascii nocase
    condition:
        $membership and $inference and any of ($attack, $training, $data)
}

rule AIML_Model_Inversion {
    meta:
        description = "Model inversion attack"
        severity = "high"
    strings:
        $model = "model" ascii nocase
        $inversion = "inversion" ascii nocase
        $reconstruct = "reconstruct" ascii nocase
        $private = "private" ascii nocase
        $data = "data" ascii nocase
    condition:
        $model and $inversion and any of ($reconstruct, $private, $data)
}

rule AIML_Evasion_Attack {
    meta:
        description = "ML evasion attack"
        severity = "high"
    strings:
        $evasion = "evasion" ascii nocase
        $classifier = "classifier" ascii nocase
        $bypass = "bypass" ascii nocase
        $detection = "detection" ascii nocase
        $ml = "machine learning" ascii nocase
    condition:
        $evasion and any of ($classifier, $bypass, $detection, $ml)
}

rule AIML_Data_Poisoning {
    meta:
        description = "Training data poisoning"
        severity = "critical"
    strings:
        $data = "data" ascii nocase
        $poison = "poison" ascii nocase
        $training = "training" ascii nocase
        $dataset = "dataset" ascii nocase
        $inject = "inject" ascii nocase
    condition:
        $data and $poison and any of ($training, $dataset, $inject)
}

rule AIML_Prompt_Injection {
    meta:
        description = "LLM prompt injection"
        severity = "critical"
    strings:
        $prompt = "prompt" ascii nocase
        $injection = "injection" ascii nocase
        $llm = "LLM" ascii
        $gpt = "GPT" ascii
        $jailbreak = "jailbreak" ascii nocase
        $bypass = "bypass" ascii nocase
    condition:
        $prompt and $injection and any of ($llm, $gpt, $jailbreak, $bypass)
}

rule AIML_Deepfake {
    meta:
        description = "Deepfake generation tool"
        severity = "high"
    strings:
        $deepfake = "deepfake" ascii nocase
        $gan = "GAN" ascii
        $face = "face" ascii nocase
        $swap = "swap" ascii nocase
        $synthesis = "synthesis" ascii nocase
        $fake = "fake" ascii nocase
    condition:
        $deepfake or ($gan and any of ($face, $swap, $synthesis, $fake))
}

rule AIML_Voice_Clone {
    meta:
        description = "Voice cloning tool"
        severity = "high"
    strings:
        $voice = "voice" ascii nocase
        $clone = "clone" ascii nocase
        $synthesis = "synthesis" ascii nocase
        $tts = "TTS" ascii
        $deepfake = "deepfake" ascii nocase
    condition:
        $voice and ($clone or $synthesis) and any of ($tts, $deepfake)
}

rule AIML_Trojan_Model {
    meta:
        description = "Trojaned ML model"
        severity = "critical"
    strings:
        $trojan = "trojan" ascii nocase
        $model = "model" ascii nocase
        $backdoor = "backdoor" ascii nocase
        $trigger = "trigger" ascii nocase
        $hidden = "hidden" ascii nocase
    condition:
        ($trojan or $backdoor) and $model and any of ($trigger, $hidden)
}

rule AIML_Watermark_Removal {
    meta:
        description = "ML watermark removal"
        severity = "high"
    strings:
        $watermark = "watermark" ascii nocase
        $remove = "remove" ascii nocase
        $model = "model" ascii nocase
        $ip = "intellectual property" ascii nocase
        $ownership = "ownership" ascii nocase
    condition:
        $watermark and $remove and any of ($model, $ip, $ownership)
}

rule AIML_Gradient_Attack {
    meta:
        description = "Gradient-based attack"
        severity = "high"
    strings:
        $gradient = "gradient" ascii nocase
        $attack = "attack" ascii nocase
        $descent = "descent" ascii nocase
        $loss = "loss" ascii nocase
        $optimize = "optimize" ascii nocase
    condition:
        $gradient and $attack and any of ($descent, $loss, $optimize)
}

rule AIML_Neural_Trojan {
    meta:
        description = "Neural network trojan"
        severity = "critical"
    strings:
        $neural = "neural" ascii nocase
        $network = "network" ascii nocase
        $trojan = "trojan" ascii nocase
        $backdoor = "backdoor" ascii nocase
        $weight = "weight" ascii nocase
    condition:
        $neural and $network and (any of ($trojan, $backdoor)) and $weight
}

rule AIML_Federated_Attack {
    meta:
        description = "Federated learning attack"
        severity = "critical"
    strings:
        $federated = "federated" ascii nocase
        $learning = "learning" ascii nocase
        $attack = "attack" ascii nocase
        $poison = "poison" ascii nocase
        $byzantine = "byzantine" ascii nocase
    condition:
        $federated and $learning and any of ($attack, $poison, $byzantine)
}

rule AIML_Sponge_Attack {
    meta:
        description = "Sponge energy-latency attack"
        severity = "medium"
    strings:
        $sponge = "sponge" ascii nocase
        $energy = "energy" ascii nocase
        $latency = "latency" ascii nocase
        $attack = "attack" ascii nocase
        $model = "model" ascii nocase
    condition:
        $sponge and any of ($energy, $latency) and any of ($attack, $model)
}

rule AIML_Transferability {
    meta:
        description = "Adversarial transferability"
        severity = "high"
    strings:
        $transfer = "transfer" ascii nocase
        $adversarial = "adversarial" ascii nocase
        $attack = "attack" ascii nocase
        $black = "black-box" ascii nocase
        $surrogate = "surrogate" ascii nocase
    condition:
        ($transfer and $adversarial) and any of ($attack, $black, $surrogate)
}

rule AIML_Supply_Chain {
    meta:
        description = "ML supply chain attack"
        severity = "critical"
    strings:
        $supply = "supply chain" ascii nocase
        $model = "model" ascii nocase
        $pretrained = "pretrained" ascii nocase
        $huggingface = "huggingface" ascii nocase
        $malicious = "malicious" ascii nocase
    condition:
        ($supply or $pretrained or $huggingface) and any of ($model, $malicious)
}

rule AIML_Dataset_Attack {
    meta:
        description = "Dataset manipulation attack"
        severity = "high"
    strings:
        $dataset = "dataset" ascii nocase
        $manipulation = "manipulation" ascii nocase
        $corrupt = "corrupt" ascii nocase
        $bias = "bias" ascii nocase
        $inject = "inject" ascii nocase
    condition:
        $dataset and any of ($manipulation, $corrupt, $bias, $inject)
}

rule AIML_Inference_Leak {
    meta:
        description = "Model inference leakage"
        severity = "high"
    strings:
        $inference = "inference" ascii nocase
        $leak = "leak" ascii nocase
        $privacy = "privacy" ascii nocase
        $information = "information" ascii nocase
        $model = "model" ascii nocase
    condition:
        $inference and $leak and any of ($privacy, $information, $model)
}

