/*
    Virtualization and Container Escape Detection
    VM escapes, container breakouts, and sandbox evasion
*/

rule VM_Escape_Generic {
    meta:
        description = "Generic VM escape attempt"
        severity = "critical"
    strings:
        $vm = "VM" ascii
        $escape = "escape" ascii nocase
        $breakout = "breakout" ascii nocase
        $hypervisor = "hypervisor" ascii nocase
        $guest = "guest" ascii nocase
        $host = "host" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($vm or $hypervisor) and any of ($escape, $breakout) and any of ($guest, $host)
}

rule VM_VMware_Escape {
    meta:
        description = "VMware escape attempt"
        severity = "critical"
    strings:
        $vmware = "VMware" ascii nocase
        $vmx = "vmx" ascii nocase
        $backdoor = "backdoor" ascii nocase
        $rpc = "VMware RPC" ascii
        // UNUSED: $tools = "vmtools" ascii nocase
        $exploit = "exploit" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($vmware or $vmx) and any of ($backdoor, $rpc, $exploit)
}

rule VM_VirtualBox_Escape {
    meta:
        description = "VirtualBox escape attempt"
        severity = "critical"
    strings:
        $vbox = "VirtualBox" ascii nocase
        $vboxsf = "VBoxSF" ascii
        $vboxguest = "VBoxGuest" ascii
        $escape = "escape" ascii nocase
        $exploit = "exploit" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($vbox or any of ($vboxsf, $vboxguest)) and any of ($escape, $exploit)
}

rule VM_HyperV_Escape {
    meta:
        description = "Hyper-V escape attempt"
        severity = "critical"
    strings:
        $hyperv = "Hyper-V" ascii nocase
        $vmbus = "vmbus" ascii nocase
        $hypercall = "hypercall" ascii nocase
        $escape = "escape" ascii nocase
        $enlightenment = "enlightenment" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($hyperv or any of ($vmbus, $hypercall, $enlightenment)) and $escape
}

rule VM_QEMU_Escape {
    meta:
        description = "QEMU/KVM escape attempt"
        severity = "critical"
    strings:
        $qemu = "QEMU" ascii nocase
        $kvm = "KVM" ascii
        $virtio = "virtio" ascii nocase
        $escape = "escape" ascii nocase
        $venom = "VENOM" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($qemu, $kvm, $virtio, $venom)) and $escape
}

rule Container_Docker_Escape {
    meta:
        description = "Docker container escape"
        severity = "critical"
    strings:
        $docker = "Docker" ascii nocase
        $sock = "docker.sock" ascii
        $escape = "escape" ascii nocase
        $breakout = "breakout" ascii nocase
        $host = "host" ascii nocase
        $mount = "mount" ascii nocase
    condition:
        ($docker or $sock) and any of ($escape, $breakout) and any of ($host, $mount)
}

rule Container_Kubernetes_Escape {
    meta:
        description = "Kubernetes container escape"
        severity = "critical"
    strings:
        $k8s = "Kubernetes" ascii nocase
        $kubectl = "kubectl" ascii nocase
        $pod = "pod" ascii nocase
        $escape = "escape" ascii nocase
        $privilege = "privileged" ascii nocase
        $host = "hostPID" ascii
    condition:
        (any of ($k8s, $kubectl, $pod)) and any of ($escape, $privilege, $host)
}

rule Container_CGroup_Escape {
    meta:
        description = "CGroup container escape"
        severity = "critical"
    strings:
        $cgroup = "cgroup" ascii nocase
        $escape = "escape" ascii nocase
        $release = "release_agent" ascii
        $notify = "notify_on_release" ascii
        $proc = "/proc/" ascii
    condition:
        $cgroup and ($escape or any of ($release, $notify, $proc))
}

rule Sandbox_Detection {
    meta:
        description = "Sandbox detection technique"
        severity = "high"
    strings:
        $sandbox = "sandbox" ascii nocase
        $detect = "detect" ascii nocase
        $vmware = "VMware" ascii nocase
        $vbox = "VirtualBox" ascii nocase
        $analysis = "analysis" ascii nocase
        $evade = "evade" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($sandbox and $detect) or (any of ($vmware, $vbox) and any of ($analysis, $evade))
}

rule Sandbox_Evasion_Sleep {
    meta:
        description = "Sleep-based sandbox evasion"
        severity = "high"
    strings:
        $sleep = "Sleep" ascii
        $wait = "WaitForSingleObject" ascii
        $delay = "delay" ascii nocase
        $evade = "evade" ascii nocase
        $sandbox = "sandbox" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($sleep, $wait)) and any of ($delay, $evade, $sandbox)
}

rule Sandbox_Evasion_CPU {
    meta:
        description = "CPU-based sandbox detection"
        severity = "high"
    strings:
        $cpuid = "cpuid" ascii nocase
        $rdtsc = { 0F 31 }
        $hypervisor = "hypervisor" ascii nocase
        $timing = "timing" ascii nocase
        $check = "check" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($cpuid, $rdtsc)) and any of ($hypervisor, $timing, $check)
}

rule Sandbox_Evasion_Artifacts {
    meta:
        description = "Sandbox artifact detection"
        severity = "high"
    strings:
        $process1 = "vmtoolsd.exe" ascii nocase
        $process2 = "vmwaretray.exe" ascii nocase
        $process3 = "VBoxService.exe" ascii nocase
        $reg = "HARDWARE\\DEVICEMAP" ascii
        $mac = "00:0C:29" ascii
        $mac2 = "00:50:56" ascii
    condition:
        uint16(0) == 0x5A4D and (2 of ($process1, $process2, $process3, $reg, $mac, $mac2))
}

rule Container_RunC_Escape {
    meta:
        description = "runC container escape"
        severity = "critical"
    strings:
        $runc = "runc" ascii nocase
        $cve = "CVE-2019-5736" ascii
        $escape = "escape" ascii nocase
        $overwrite = "overwrite" ascii nocase
        $binary = "binary" ascii nocase
    condition:
        ($runc and $escape) or $cve or ($overwrite and $binary)
}

rule Container_Privileged_Escape {
    meta:
        description = "Privileged container escape"
        severity = "critical"
    strings:
        $privileged = "privileged" ascii nocase
        $container = "container" ascii nocase
        $escape = "escape" ascii nocase
        $cap = "CAP_SYS_ADMIN" ascii
        $mount = "mount" ascii nocase
        $proc = "/proc" ascii
    condition:
        ($privileged and $container and $escape) or ($cap and any of ($mount, $proc))
}

rule VM_Xen_Escape {
    meta:
        description = "Xen hypervisor escape"
        severity = "critical"
    strings:
        $xen = "Xen" ascii nocase
        $xenstore = "xenstore" ascii nocase
        $hypercall = "hypercall" ascii nocase
        $escape = "escape" ascii nocase
        $exploit = "exploit" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($xen, $xenstore, $hypercall)) and any of ($escape, $exploit)
}

rule Sandbox_User_Interaction {
    meta:
        description = "User interaction sandbox check"
        severity = "medium"
    strings:
        $mouse = "GetCursorPos" ascii
        $keyboard = "GetAsyncKeyState" ascii
        $click = "GetLastInputInfo" ascii
        $idle = "idle" ascii nocase
        $activity = "activity" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (2 of ($mouse, $keyboard, $click)) and any of ($idle, $activity)
}

rule Container_Namespace_Escape {
    meta:
        description = "Namespace escape attempt"
        severity = "critical"
    strings:
        $ns = "namespace" ascii nocase
        $setns = "setns" ascii
        $unshare = "unshare" ascii
        $escape = "escape" ascii nocase
        $host = "host" ascii nocase
        $root = "root" ascii nocase
    condition:
        $ns and (any of ($setns, $unshare)) and any of ($escape, $host, $root)
}

rule VM_VENOM_CVE {
    meta:
        description = "VENOM vulnerability exploit"
        severity = "critical"
    strings:
        $venom = "VENOM" ascii
        $cve = "CVE-2015-3456" ascii
        $floppy = "floppy" ascii nocase
        $fdc = "FDC" ascii
        $escape = "escape" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($venom or $cve or ($floppy and any of ($fdc, $escape)))
}

rule Container_SYS_PTRACE {
    meta:
        description = "Container ptrace escape"
        severity = "critical"
    strings:
        $ptrace = "SYS_PTRACE" ascii
        $cap = "CAP_" ascii
        $process = "process" ascii nocase
        $inject = "inject" ascii nocase
        $escape = "escape" ascii nocase
    condition:
        $ptrace and any of ($cap, $process, $inject, $escape)
}

