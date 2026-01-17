/*
    Memory-Based Attack Detection
    In-memory attacks, injection, and exploitation patterns
*/

rule Memory_Process_Injection {
    meta:
        description = "Classic process injection"
        severity = "critical"
    strings:
        $api1 = "VirtualAllocEx" ascii
        $api2 = "WriteProcessMemory" ascii
        $api3 = "CreateRemoteThread" ascii
        $api4 = "OpenProcess" ascii
        $api5 = "NtCreateThreadEx" ascii
    condition:
        uint16(0) == 0x5A4D and ($api4 and $api1 and $api2 and any of ($api3, $api5))
}

rule Memory_APC_Injection {
    meta:
        description = "APC injection technique"
        severity = "critical"
    strings:
        $api1 = "QueueUserAPC" ascii
        $api2 = "NtQueueApcThread" ascii
        $api3 = "OpenThread" ascii
        $api4 = "SuspendThread" ascii
        $api5 = "ResumeThread" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($api1, $api2)) and any of ($api3, $api4, $api5)
}

rule Memory_DLL_Injection {
    meta:
        description = "DLL injection technique"
        severity = "critical"
    strings:
        $api1 = "LoadLibraryA" ascii
        $api2 = "LoadLibraryW" ascii
        $api3 = "LdrLoadDll" ascii
        $remote = "CreateRemoteThread" ascii
        $alloc = "VirtualAllocEx" ascii
        $write = "WriteProcessMemory" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($api1, $api2, $api3)) and $remote and any of ($alloc, $write)
}

rule Memory_Reflective_DLL {
    meta:
        description = "Reflective DLL injection"
        severity = "critical"
    strings:
        $reflective = "ReflectiveLoader" ascii
        $dos = "DOS" ascii
        $header = "header" ascii nocase
        $reloc = "relocation" ascii nocase
        $manual = "manual" ascii nocase
        $map = "map" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($reflective or (($dos and $header) and any of ($reloc, $manual, $map)))
}

rule Memory_Process_Hollowing {
    meta:
        description = "Process hollowing technique"
        severity = "critical"
    strings:
        $api1 = "NtUnmapViewOfSection" ascii
        $api2 = "ZwUnmapViewOfSection" ascii
        $api3 = "CreateProcessA" ascii
        $api4 = "CreateProcessW" ascii
        $api5 = "SetThreadContext" ascii
        $api6 = "ResumeThread" ascii
        $suspend = "CREATE_SUSPENDED" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($api1, $api2)) and (any of ($api3, $api4)) and any of ($api5, $api6, $suspend)
}

rule Memory_Process_Doppelganging {
    meta:
        description = "Process doppelgänging technique"
        severity = "critical"
    strings:
        $api1 = "NtCreateTransaction" ascii
        $api2 = "NtCreateSection" ascii
        $api3 = "NtRollbackTransaction" ascii
        $api4 = "NtCreateProcessEx" ascii
        $transact = "transact" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (3 of ($api*)) or ($transact and any of ($api*))
}

rule Memory_AtomBombing {
    meta:
        description = "AtomBombing injection"
        severity = "critical"
    strings:
        $api1 = "GlobalAddAtom" ascii
        $api2 = "GlobalGetAtomName" ascii
        $api3 = "NtQueueApcThread" ascii
        $api4 = "QueueUserAPC" ascii
        $atom = "Atom" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($api1, $api2)) and any of ($api3, $api4, $atom)
}

rule Memory_Heap_Spray {
    meta:
        description = "Heap spray attack"
        severity = "critical"
    strings:
        $heap = "heap" ascii nocase
        $spray = "spray" ascii nocase
        $nop = { 90 90 90 90 90 90 90 90 }
        $sled = "sled" ascii nocase
        $shellcode = "shellcode" ascii nocase
        $alloc = "HeapAlloc" ascii
    condition:
        uint16(0) == 0x5A4D and (($heap and $spray) or $nop) and any of ($sled, $shellcode, $alloc)
}

rule Memory_Stack_Pivot {
    meta:
        description = "Stack pivot technique"
        severity = "critical"
    strings:
        $pivot = "pivot" ascii nocase
        $stack = "stack" ascii nocase
        $xchg = { 94 }  // xchg eax, esp
        $mov_esp = { 8B E? }  // mov esp, reg
        $rop = "ROP" ascii
    condition:
        uint16(0) == 0x5A4D and (($pivot and $stack) or any of ($xchg, $mov_esp, $rop))
}

rule Memory_ROP_Chain {
    meta:
        description = "ROP chain indicators"
        severity = "critical"
    strings:
        $rop = "ROP" ascii
        $gadget = "gadget" ascii nocase
        $chain = "chain" ascii nocase
        $ret = { C3 }  // ret instruction
        $pop_ret = { 5? C3 }  // pop reg; ret
    condition:
        uint16(0) == 0x5A4D and (($rop and any of ($gadget, $chain)) or (3 of ($ret, $pop_ret)))
}

rule Memory_JIT_Spray {
    meta:
        description = "JIT spray attack"
        severity = "critical"
    strings:
        $jit = "JIT" ascii
        $spray = "spray" ascii nocase
        $javascript = "JavaScript" ascii nocase
        $flash = "Flash" ascii nocase
        $actionscript = "ActionScript" ascii nocase
    condition:
        $jit and $spray and any of ($javascript, $flash, $actionscript)
}

rule Memory_EggHunter {
    meta:
        description = "Egg hunter shellcode"
        severity = "critical"
    strings:
        $egg = "egg" ascii nocase
        $hunter = "hunter" ascii nocase
        $tag = { B8 ?? ?? ?? ?? }  // mov eax, tag
        $scasd = { AF }  // scasd instruction
        $search = "search" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (($egg and $hunter) or ($tag and $scasd) or ($search and $egg))
}

rule Memory_Module_Stomping {
    meta:
        description = "Module stomping technique"
        severity = "critical"
    strings:
        $stomp = "stomp" ascii nocase
        $module = "module" ascii nocase
        $overwrite = "overwrite" ascii nocase
        $dll = ".dll" ascii nocase
        $section = ".text" ascii
    condition:
        uint16(0) == 0x5A4D and ($stomp and $module) or (($overwrite and $dll) and $section)
}

rule Memory_Thread_Hijacking {
    meta:
        description = "Thread hijacking technique"
        severity = "critical"
    strings:
        $api1 = "SuspendThread" ascii
        $api2 = "GetThreadContext" ascii
        $api3 = "SetThreadContext" ascii
        $api4 = "ResumeThread" ascii
        $hijack = "hijack" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (all of ($api*) or ($hijack and any of ($api*)))
}

rule Memory_Early_Bird {
    meta:
        description = "Early bird injection"
        severity = "critical"
    strings:
        $early = "early" ascii nocase
        $bird = "bird" ascii nocase
        $api1 = "QueueUserAPC" ascii
        $api2 = "NtTestAlert" ascii
        $suspend = "CREATE_SUSPENDED" ascii
    condition:
        uint16(0) == 0x5A4D and (($early and $bird) or ($api1 and any of ($api2, $suspend)))
}

rule Memory_Gargoyle {
    meta:
        description = "Gargoyle memory technique"
        severity = "critical"
    strings:
        $gargoyle = "Gargoyle" ascii nocase
        $timer = "CreateTimerQueueTimer" ascii
        $rop = "ROP" ascii
        $non_exec = "non-executable" ascii nocase
        $mark = "VirtualProtect" ascii
    condition:
        uint16(0) == 0x5A4D and ($gargoyle or ($timer and any of ($rop, $non_exec, $mark)))
}

rule Memory_Shim_Injection {
    meta:
        description = "Application shimming injection"
        severity = "high"
    strings:
        $shim = "shim" ascii nocase
        $appcompat = "AppCompat" ascii
        $sdb = ".sdb" ascii nocase
        $sdbinst = "sdbinst" ascii nocase
        $compat = "compatibility" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($shim or $appcompat) and any of ($sdb, $sdbinst, $compat)
}

rule Memory_NTDLL_Unhooking {
    meta:
        description = "NTDLL unhooking technique"
        severity = "critical"
    strings:
        $ntdll = "ntdll" ascii nocase
        $unhook = "unhook" ascii nocase
        $fresh = "fresh" ascii nocase
        $copy = "copy" ascii nocase
        $map = "NtMapViewOfSection" ascii
        $syscall = "syscall" ascii nocase
    condition:
        uint16(0) == 0x5A4D and $ntdll and any of ($unhook, $fresh, $copy, $map, $syscall)
}

rule Memory_Direct_Syscall {
    meta:
        description = "Direct syscall usage"
        severity = "critical"
    strings:
        $syscall = "syscall" ascii nocase
        $sysenter = { 0F 05 }  // syscall instruction
        $int2e = { CD 2E }  // int 2e
        $ssn = "syscall number" ascii nocase
        $direct = "direct" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (($syscall and $direct) or any of ($sysenter, $int2e, $ssn))
}

rule Memory_Callback_Overwrite {
    meta:
        description = "Callback function overwrite"
        severity = "critical"
    strings:
        $callback = "callback" ascii nocase
        $overwrite = "overwrite" ascii nocase
        $function = "function" ascii nocase
        $hook = "hook" ascii nocase
        $replace = "replace" ascii nocase
    condition:
        uint16(0) == 0x5A4D and $callback and any of ($overwrite, $hook, $replace) and $function
}

