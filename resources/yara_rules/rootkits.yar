/*
    Rootkit Detection Rules
    Covers: Kernel rootkits, bootkits, userland rootkits
*/

rule Rootkit_Generic {
    meta:
        description = "Generic rootkit indicators"
        severity = "critical"
    strings:
        $s1 = "rootkit" nocase
        $s2 = "hideproc" nocase
        $s3 = "hideport" nocase
        $s4 = "hidefile" nocase
        $hook = "hook" nocase
    condition:
        any of ($s*) or $hook
}

rule Rootkit_SSDT_Hook {
    meta:
        description = "SSDT hooking rootkit"
        severity = "critical"
    strings:
        $s1 = "KeServiceDescriptorTable" ascii
        $s2 = "KiServiceTable" ascii
        $s3 = "ZwQuerySystemInformation" ascii
    condition:
        any of them
}

rule Rootkit_IDT_Hook {
    meta:
        description = "IDT hooking rootkit"
        severity = "critical"
    strings:
        $s1 = "IDTR" ascii
        $s2 = "sidt" ascii
        $s3 = {0F 01 ?? ?? 8B}
    condition:
        any of them
}

rule Rootkit_DKOM {
    meta:
        description = "Direct Kernel Object Manipulation rootkit"
        severity = "critical"
    strings:
        $s1 = "EPROCESS" ascii
        $s2 = "ActiveProcessLinks" ascii
        $s3 = "PsActiveProcessHead" ascii
        $s4 = "PsGetCurrentProcess" ascii
    condition:
        2 of them
}

rule Rootkit_IRP_Hook {
    meta:
        description = "IRP hooking rootkit"
        severity = "critical"
    strings:
        $s1 = "IRP_MJ_CREATE" ascii
        $s2 = "IRP_MJ_READ" ascii
        $s3 = "MajorFunction" ascii
        $driver = "DriverObject" ascii
    condition:
        2 of ($s*) or $driver
}

rule Rootkit_Filter_Driver {
    meta:
        description = "Filter driver rootkit"
        severity = "critical"
    strings:
        $s1 = "IoAttachDevice" ascii
        $s2 = "IoAttachDeviceToDeviceStack" ascii
        $s3 = "FltRegisterFilter" ascii
    condition:
        any of them
}

rule Bootkit_MBR {
    meta:
        description = "MBR bootkit"
        severity = "critical"
    strings:
        $mbr = {EB ?? 90 ?? ?? ?? ?? ?? ?? ?? ?? 00 02}
        $s1 = "bootkit" nocase
        $s2 = "MBR" ascii
        $hook = {FA 33 C0 8E D0}
    condition:
        $mbr at 0 or any of ($s*) or $hook
}

rule Bootkit_VBR {
    meta:
        description = "VBR bootkit"
        severity = "critical"
    strings:
        $vbr = "NTFS" ascii
        $s1 = "bootmgr" nocase
        $s2 = "bootloader" nocase
    condition:
        $vbr and any of ($s*)
}

rule Bootkit_UEFI {
    meta:
        description = "UEFI bootkit"
        severity = "critical"
    strings:
        $s1 = "EFI" ascii
        $s2 = "UEFI" ascii
        $s3 = "bootx64.efi" nocase
        $s4 = "bootmgfw.efi" nocase
    condition:
        2 of them
}

rule Rootkit_TDL4 {
    meta:
        description = "TDL4/TDSS rootkit"
        severity = "critical"
    strings:
        $s1 = "TDL" ascii
        $s2 = "TDSS" ascii
        $s3 = "tdl4" nocase
        $cfg = "cfg.ini" ascii
    condition:
        any of ($s*) or $cfg
}

rule Rootkit_ZeroAccess {
    meta:
        description = "ZeroAccess/Sirefef rootkit"
        severity = "critical"
    strings:
        $s1 = "ZeroAccess" ascii
        $s2 = "sirefef" nocase
        $s3 = "max++" ascii
        $p2p = "p2p" ascii
    condition:
        any of ($s*) or $p2p
}

rule Rootkit_Necurs {
    meta:
        description = "Necurs rootkit"
        severity = "critical"
    strings:
        $s1 = "necurs" nocase
        $driver = ".sys" ascii
        $hook = "NtOpenProcess" ascii
    condition:
        $s1 or ($driver and $hook)
}

rule Rootkit_EquationDrug {
    meta:
        description = "EquationDrug rootkit"
        severity = "critical"
    strings:
        $s1 = "EquationDrug" ascii
        $s2 = "equation" nocase
        $driver = "DriverEntry" ascii
    condition:
        any of ($s*) or $driver
}

rule Rootkit_Uroburos {
    meta:
        description = "Uroburos/Snake rootkit"
        severity = "critical"
    strings:
        $s1 = "Ur0bUr()s" ascii
        $s2 = "uroburos" nocase
        $s3 = "snake" nocase
        $driver = {49 B8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89}
    condition:
        any of ($s*) or $driver
}

rule Rootkit_Regin {
    meta:
        description = "Regin rootkit"
        severity = "critical"
    strings:
        $s1 = "regin" nocase
        $s2 = "prax" ascii
        $vfs = "vfs" ascii
    condition:
        any of ($s*) or $vfs
}

rule Rootkit_Hacking_Team {
    meta:
        description = "Hacking Team rootkit"
        severity = "critical"
    strings:
        $s1 = "HackingTeam" ascii
        $s2 = "RCS" ascii
        $s3 = "Galileo" ascii
    condition:
        any of them
}

rule Rootkit_FinFisher {
    meta:
        description = "FinFisher/FinSpy rootkit"
        severity = "critical"
    strings:
        $s1 = "FinFisher" ascii
        $s2 = "FinSpy" ascii
        $s3 = "Gamma" ascii
    condition:
        any of them
}

rule Userland_Rootkit_LD_PRELOAD {
    meta:
        description = "LD_PRELOAD userland rootkit"
        severity = "critical"
    strings:
        $s1 = "ld.so.preload" ascii
        $s2 = "LD_PRELOAD" ascii
        $s3 = "dlsym" ascii
        $hook = "readdir" ascii
    condition:
        2 of ($s*) or ($s3 and $hook)
}

rule Kernel_Module_Rootkit {
    meta:
        description = "Linux kernel module rootkit"
        severity = "critical"
    strings:
        $s1 = "module_init" ascii
        $s2 = "sys_call_table" ascii
        $s3 = "hide_pid" ascii
        $s4 = "insmod" ascii
    condition:
        2 of them
}

rule Rootkit_Hiding_Technique {
    meta:
        description = "Process/file hiding technique"
        severity = "high"
    strings:
        $s1 = "NtQueryDirectoryFile" ascii
        $s2 = "NtQuerySystemInformation" ascii
        $s3 = "ZwQueryDirectoryFile" ascii
        $s4 = "ZwQuerySystemInformation" ascii
    condition:
        2 of them
}

rule Rootkit_Callback_Registration {
    meta:
        description = "Rootkit callback registration"
        severity = "high"
    strings:
        $s1 = "PsSetCreateProcessNotifyRoutine" ascii
        $s2 = "PsSetLoadImageNotifyRoutine" ascii
        $s3 = "CmRegisterCallback" ascii
        $s4 = "ObRegisterCallbacks" ascii
    condition:
        any of them
}

rule Hypervisor_Rootkit {
    meta:
        description = "Hypervisor-based rootkit"
        severity = "critical"
    strings:
        $s1 = "vmxon" ascii
        $s2 = "vmxoff" ascii
        $s3 = "vmcall" ascii
        $s4 = "Blue Pill" ascii
        $vmx = {0F 01 C4}
    condition:
        2 of ($s*) or $vmx
}

rule Firmware_Rootkit {
    meta:
        description = "Firmware rootkit"
        severity = "critical"
    strings:
        $s1 = "SMM" ascii
        $s2 = "BIOS" ascii
        $s3 = "firmware" nocase
        $s4 = "flash" nocase
        $smi = {CD ?? 0F 01}
    condition:
        2 of ($s*) or $smi
}
