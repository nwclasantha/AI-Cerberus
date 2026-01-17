/*
    Zero-Day and Advanced Exploit Indicators
    Generic patterns for detecting novel attack techniques
*/

rule ZeroDay_Memory_Corruption {
    meta:
        description = "Memory corruption exploit indicators"
        severity = "critical"
    strings:
        $heap = "heap" ascii nocase
        $overflow = "overflow" ascii nocase
        $corrupt = "corrupt" ascii nocase
        $spray = "spray" ascii nocase
        $uaf = "use-after-free" ascii nocase
        $oob = "out-of-bounds" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (3 of ($heap, $overflow, $corrupt, $spray, $uaf, $oob))
}

rule ZeroDay_Type_Confusion {
    meta:
        description = "Type confusion exploit"
        severity = "critical"
    strings:
        $type = "type" ascii nocase
        $confusion = "confusion" ascii nocase
        $cast = "cast" ascii nocase
        $vtable = "vtable" ascii nocase
        $object = "object" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($type and $confusion) or ($cast and any of ($vtable, $object))
}

rule ZeroDay_Race_Condition {
    meta:
        description = "Race condition exploit"
        severity = "critical"
    strings:
        $race = "race" ascii nocase
        $condition = "condition" ascii nocase
        $toctou = "TOCTOU" ascii
        $thread = "thread" ascii nocase
        $timing = "timing" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (($race and $condition) or $toctou or ($thread and $timing))
}

rule ZeroDay_Integer_Overflow {
    meta:
        description = "Integer overflow exploit"
        severity = "critical"
    strings:
        $integer = "integer" ascii nocase
        $overflow = "overflow" ascii nocase
        $underflow = "underflow" ascii nocase
        $wrap = "wrap" ascii nocase
        $truncate = "truncate" ascii nocase
    condition:
        uint16(0) == 0x5A4D and $integer and any of ($overflow, $underflow, $wrap, $truncate)
}

rule ZeroDay_Buffer_Overflow {
    meta:
        description = "Buffer overflow exploit"
        severity = "critical"
    strings:
        $buffer = "buffer" ascii nocase
        $overflow = "overflow" ascii nocase
        $stack = "stack" ascii nocase
        $smash = "smash" ascii nocase
        $canary = "canary" ascii nocase
        $bypass = "bypass" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($buffer and $overflow) and any of ($stack, $smash, $canary, $bypass)
}

rule ZeroDay_Format_String {
    meta:
        description = "Format string exploit"
        severity = "critical"
    strings:
        $format = "format" ascii nocase
        $string = "string" ascii nocase
        $printf = "printf" ascii nocase
        $percent_n = "%n" ascii
        $percent_s = "%s" ascii
    condition:
        uint16(0) == 0x5A4D and ($format and $string) and any of ($printf, $percent_n, $percent_s)
}

rule ZeroDay_Deserialization {
    meta:
        description = "Deserialization exploit"
        severity = "critical"
    strings:
        $deserial = "deserializ" ascii nocase
        $gadget = "gadget" ascii nocase
        $chain = "chain" ascii nocase
        $java = "ObjectInputStream" ascii
        $dotnet = "BinaryFormatter" ascii
        $pickle = "pickle" ascii
    condition:
        $deserial and any of ($gadget, $chain, $java, $dotnet, $pickle)
}

rule ZeroDay_XXE {
    meta:
        description = "XML External Entity exploit"
        severity = "critical"
    strings:
        $xxe = "XXE" ascii
        $xml = "XML" ascii
        $entity = "ENTITY" ascii
        $doctype = "DOCTYPE" ascii
        $external = "external" ascii nocase
        $file = "file://" ascii
    condition:
        ($xxe or ($xml and $entity)) and any of ($doctype, $external, $file)
}

rule ZeroDay_SSRF {
    meta:
        description = "Server-Side Request Forgery"
        severity = "critical"
    strings:
        $ssrf = "SSRF" ascii
        $server = "server" ascii nocase
        $side = "side" ascii nocase
        $request = "request" ascii nocase
        $forge = "forg" ascii nocase
        $internal = "internal" ascii nocase
        $localhost = "localhost" ascii
    condition:
        $ssrf or (($server and $side and $request) and any of ($forge, $internal, $localhost))
}

rule ZeroDay_Prototype_Pollution {
    meta:
        description = "Prototype pollution attack"
        severity = "high"
    strings:
        $proto = "__proto__" ascii
        $prototype = "prototype" ascii
        $pollution = "pollution" ascii nocase
        $constructor = "constructor" ascii
        $object = "Object" ascii
    condition:
        ($proto or $prototype) and any of ($pollution, $constructor, $object)
}

rule ZeroDay_Template_Injection {
    meta:
        description = "Template injection exploit"
        severity = "critical"
    strings:
        $template = "template" ascii nocase
        $injection = "injection" ascii nocase
        $ssti = "SSTI" ascii
        $jinja = "jinja" ascii nocase
        $twig = "twig" ascii nocase
        $freemarker = "FreeMarker" ascii nocase
    condition:
        ($template and $injection) or $ssti or any of ($jinja, $twig, $freemarker)
}

rule ZeroDay_Path_Traversal {
    meta:
        description = "Path traversal exploit"
        severity = "high"
    strings:
        $path = "path" ascii nocase
        $traversal = "traversal" ascii nocase
        $dotdot = ".." ascii
        $lfi = "LFI" ascii
        $directory = "directory" ascii nocase
    condition:
        (($path and $traversal) or $lfi) and any of ($dotdot, $directory)
}

rule ZeroDay_Command_Injection {
    meta:
        description = "Command injection exploit"
        severity = "critical"
    strings:
        $command = "command" ascii nocase
        $injection = "injection" ascii nocase
        $shell = "shell" ascii nocase
        $exec = "exec" ascii nocase
        $pipe = "|" ascii
        $semicolon = ";" ascii
    condition:
        ($command and $injection) or ($shell and $exec and any of ($pipe, $semicolon))
}

rule ZeroDay_LDAP_Injection {
    meta:
        description = "LDAP injection exploit"
        severity = "critical"
    strings:
        $ldap = "LDAP" ascii
        $injection = "injection" ascii nocase
        $filter = "filter" ascii nocase
        $bind = "bind" ascii nocase
        $wildcard = "*" ascii
    condition:
        $ldap and $injection and any of ($filter, $bind, $wildcard)
}

rule ZeroDay_NoSQL_Injection {
    meta:
        description = "NoSQL injection exploit"
        severity = "critical"
    strings:
        $nosql = "NoSQL" ascii nocase
        $injection = "injection" ascii nocase
        $mongo = "MongoDB" ascii nocase
        $where = "$where" ascii
        $regex = "$regex" ascii
    condition:
        ($nosql and $injection) or ($mongo and any of ($where, $regex))
}

rule ZeroDay_JWT_Attack {
    meta:
        description = "JWT token attack"
        severity = "high"
    strings:
        $jwt = "JWT" ascii
        $token = "token" ascii nocase
        $none = "\"alg\":\"none\"" ascii
        $forge = "forge" ascii nocase
        $secret = "secret" ascii nocase
    condition:
        $jwt and ($token or $none) and any of ($forge, $secret)
}

rule ZeroDay_OAuth_Attack {
    meta:
        description = "OAuth attack indicators"
        severity = "high"
    strings:
        $oauth = "OAuth" ascii nocase
        $redirect = "redirect_uri" ascii
        $code = "authorization_code" ascii
        $token = "access_token" ascii
        $steal = "steal" ascii nocase
        $bypass = "bypass" ascii nocase
    condition:
        $oauth and (any of ($redirect, $code, $token)) and any of ($steal, $bypass)
}

rule ZeroDay_WebSocket_Attack {
    meta:
        description = "WebSocket attack"
        severity = "high"
    strings:
        $websocket = "WebSocket" ascii nocase
        $ws = "ws://" ascii
        $wss = "wss://" ascii
        $hijack = "hijack" ascii nocase
        $inject = "inject" ascii nocase
    condition:
        ($websocket or any of ($ws, $wss)) and any of ($hijack, $inject)
}

rule ZeroDay_GraphQL_Attack {
    meta:
        description = "GraphQL attack"
        severity = "high"
    strings:
        $graphql = "GraphQL" ascii nocase
        $introspection = "introspection" ascii nocase
        $query = "query" ascii nocase
        $mutation = "mutation" ascii nocase
        $dos = "DoS" ascii
        $bypass = "bypass" ascii nocase
    condition:
        $graphql and any of ($introspection, $query, $mutation) and any of ($dos, $bypass)
}

rule ZeroDay_CORS_Bypass {
    meta:
        description = "CORS bypass attack"
        severity = "high"
    strings:
        $cors = "CORS" ascii
        $origin = "Origin" ascii
        $bypass = "bypass" ascii nocase
        $null = "null" ascii
        $wildcard = "*" ascii
    condition:
        $cors and ($origin or any of ($bypass, $null, $wildcard))
}

