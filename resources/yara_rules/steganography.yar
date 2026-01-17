/*
    Steganography Detection
    Data hiding in images, audio, and other media
*/

rule Stego_Generic_Image {
    meta:
        description = "Generic image steganography"
        severity = "high"
    strings:
        $stego = "stego" ascii nocase
        $hide = "hide" ascii nocase
        $embed = "embed" ascii nocase
        $image = "image" ascii nocase
        $png = "PNG" ascii
        $jpg = "JPEG" ascii
        $bmp = "BMP" ascii
        $lsb = "LSB" ascii
    condition:
        (any of ($stego, $lsb)) or ($hide and $embed and any of ($image, $png, $jpg, $bmp))
}

rule Stego_LSB_Technique {
    meta:
        description = "LSB steganography technique"
        severity = "high"
    strings:
        $lsb = "LSB" ascii
        $least = "least significant" ascii nocase
        $bit = "bit" ascii nocase
        $pixel = "pixel" ascii nocase
        $embed = "embed" ascii nocase
        $extract = "extract" ascii nocase
    condition:
        ($lsb or $least) and ($bit or $pixel) and any of ($embed, $extract)
}

rule Stego_OpenStego {
    meta:
        description = "OpenStego tool"
        severity = "high"
    strings:
        $s1 = "OpenStego" ascii nocase
        $s2 = "openstego" ascii nocase
        $algo = "RandomLSB" ascii
        $sig = { 4F 70 53 74 65 67 6F }
    condition:
        (any of ($s*)) or $algo or $sig
}

rule Stego_SilentEye {
    meta:
        description = "SilentEye steganography"
        severity = "high"
    strings:
        $s1 = "SilentEye" ascii nocase
        $s2 = "silenteye" ascii nocase
        $encode = "encode" ascii nocase
        $decode = "decode" ascii nocase
    condition:
        (any of ($s*)) or ($encode and $decode)
}

rule Stego_Steghide {
    meta:
        description = "Steghide tool"
        severity = "high"
    strings:
        $s1 = "steghide" ascii nocase
        $s2 = "Steghide" ascii
        $embed = "embed" ascii nocase
        $extract = "extract" ascii nocase
        $passphrase = "passphrase" ascii nocase
    condition:
        (any of ($s*)) and any of ($embed, $extract, $passphrase)
}

rule Stego_Snow_Whitespace {
    meta:
        description = "Snow whitespace steganography"
        severity = "medium"
    strings:
        $snow = "snow" ascii nocase
        $whitespace = "whitespace" ascii nocase
        $space = "space" ascii nocase
        $tab = "tab" ascii nocase
        $hide = "hide" ascii nocase
    condition:
        $snow and ($whitespace or $space or $tab) and $hide
}

rule Stego_Audio_Spectrum {
    meta:
        description = "Audio spectrum steganography"
        severity = "high"
    strings:
        $audio = "audio" ascii nocase
        $wav = "WAV" ascii
        $mp3 = "MP3" ascii
        $spectrum = "spectrum" ascii nocase
        $frequency = "frequency" ascii nocase
        $hide = "hide" ascii nocase
        $embed = "embed" ascii nocase
    condition:
        (any of ($audio, $wav, $mp3)) and (any of ($spectrum, $frequency)) and any of ($hide, $embed)
}

rule Stego_MP3Stego {
    meta:
        description = "MP3Stego tool"
        severity = "high"
    strings:
        $s1 = "MP3Stego" ascii nocase
        $s2 = "mp3stego" ascii nocase
        $encode = "encode" ascii nocase
        $decode = "decode" ascii nocase
        $mp3 = ".mp3" ascii nocase
    condition:
        (any of ($s*)) or ($encode and $decode and $mp3)
}

rule Stego_DeepSound {
    meta:
        description = "DeepSound audio steganography"
        severity = "high"
    strings:
        $s1 = "DeepSound" ascii nocase
        $s2 = "deepsound" ascii nocase
        $audio = "audio" ascii nocase
        $carrier = "carrier" ascii nocase
        $aes = "AES" ascii
    condition:
        (any of ($s*)) or ($audio and $carrier and $aes)
}

rule Stego_Outguess {
    meta:
        description = "Outguess steganography"
        severity = "high"
    strings:
        $s1 = "OutGuess" ascii nocase
        $s2 = "outguess" ascii nocase
        $jpeg = "JPEG" ascii nocase
        $dct = "DCT" ascii
        $embed = "embed" ascii nocase
    condition:
        (any of ($s*)) or ($jpeg and $dct and $embed)
}

rule Stego_F5_Algorithm {
    meta:
        description = "F5 steganography algorithm"
        severity = "high"
    strings:
        $f5 = "F5" ascii
        $algo = "algorithm" ascii nocase
        $jpeg = "JPEG" ascii
        $dct = "DCT" ascii
        $matrix = "matrix" ascii nocase
        $embed = "embed" ascii nocase
    condition:
        $f5 and ($algo or $jpeg or $dct) and any of ($matrix, $embed)
}

rule Stego_JSteg {
    meta:
        description = "JSteg steganography"
        severity = "high"
    strings:
        $jsteg = "JSteg" ascii nocase
        $jpeg = "JPEG" ascii
        $coefficient = "coefficient" ascii nocase
        $lsb = "LSB" ascii
        $hide = "hide" ascii nocase
    condition:
        $jsteg or ($jpeg and $coefficient and any of ($lsb, $hide))
}

rule Stego_PNG_Chunk {
    meta:
        description = "PNG chunk steganography"
        severity = "high"
    strings:
        $png = { 89 50 4E 47 0D 0A 1A 0A }
        $chunk = "chunk" ascii nocase
        $ancillary = "ancillary" ascii nocase
        $text = "tEXt" ascii
        $itxt = "iTXt" ascii
        $hide = "hide" ascii nocase
    condition:
        $png and ($chunk or any of ($ancillary, $text, $itxt)) and $hide
}

rule Stego_EXIF_Metadata {
    meta:
        description = "EXIF metadata steganography"
        severity = "medium"
    strings:
        $exif = "EXIF" ascii
        $metadata = "metadata" ascii nocase
        $comment = "comment" ascii nocase
        $maker = "MakerNote" ascii
        $hide = "hide" ascii nocase
        $embed = "embed" ascii nocase
    condition:
        $exif and ($metadata or any of ($comment, $maker)) and any of ($hide, $embed)
}

rule Stego_PDF_Hidden {
    meta:
        description = "PDF steganography"
        severity = "high"
    strings:
        $pdf = "%PDF" ascii
        $stream = "stream" ascii
        $hide = "hide" ascii nocase
        $embed = "embed" ascii nocase
        $object = "obj" ascii
        $endobj = "endobj" ascii
    condition:
        $pdf and ($stream and $object and $endobj) and any of ($hide, $embed)
}

rule Stego_Network_Protocol {
    meta:
        description = "Network protocol steganography"
        severity = "high"
    strings:
        $network = "network" ascii nocase
        $protocol = "protocol" ascii nocase
        $tcp = "TCP" ascii
        $icmp = "ICMP" ascii
        $dns = "DNS" ascii
        $covert = "covert" ascii nocase
        $channel = "channel" ascii nocase
    condition:
        ($network or any of ($tcp, $icmp, $dns)) and ($protocol or any of ($covert, $channel))
}

rule Stego_ICMP_Tunnel {
    meta:
        description = "ICMP steganography tunnel"
        severity = "critical"
    strings:
        $icmp = "ICMP" ascii
        $ping = "ping" ascii nocase
        $tunnel = "tunnel" ascii nocase
        $covert = "covert" ascii nocase
        $data = "data" ascii nocase
        $payload = "payload" ascii nocase
    condition:
        $icmp and ($ping or $tunnel) and any of ($covert, $data, $payload)
}

rule Stego_TCP_Steganography {
    meta:
        description = "TCP header steganography"
        severity = "high"
    strings:
        $tcp = "TCP" ascii
        $header = "header" ascii nocase
        $sequence = "sequence" ascii nocase
        $urgent = "urgent" ascii nocase
        $covert = "covert" ascii nocase
        $hide = "hide" ascii nocase
    condition:
        $tcp and $header and (any of ($sequence, $urgent)) and any of ($covert, $hide)
}

rule Stego_Covert_Channel {
    meta:
        description = "Generic covert channel"
        severity = "high"
    strings:
        $covert = "covert" ascii nocase
        $channel = "channel" ascii nocase
        $hide = "hide" ascii nocase
        $secret = "secret" ascii nocase
        $timing = "timing" ascii nocase
        $storage = "storage" ascii nocase
    condition:
        $covert and $channel and any of ($hide, $secret, $timing, $storage)
}

rule Stego_Text_Zero_Width {
    meta:
        description = "Zero-width character steganography"
        severity = "medium"
    strings:
        $zero = "zero" ascii nocase
        $width = "width" ascii nocase
        $unicode = "unicode" ascii nocase
        $invisible = "invisible" ascii nocase
        $zwsp = { E2 80 8B }
        $zwnj = { E2 80 8C }
    condition:
        (($zero and $width) or $unicode) and ($invisible or any of ($zwsp, $zwnj))
}

