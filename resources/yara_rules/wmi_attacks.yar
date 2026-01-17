/*
    WMI Attack Detection
    WMI-based persistence, lateral movement, and attacks
*/

rule WMI_Event_Subscription {
    meta:
        description = "WMI event subscription persistence"
        severity = "critical"
    strings:
        $filter = "__EventFilter" ascii
        $consumer = "__EventConsumer" ascii
        $binding = "__FilterToConsumerBinding" ascii
        $command = "CommandLineEventConsumer" ascii
        $script = "ActiveScriptEventConsumer" ascii
        $wql = "SELECT * FROM" ascii
    condition:
        ($filter and $consumer and $binding) or (any of ($command, $script) and $wql)
}

rule WMI_Process_Creation {
    meta:
        description = "WMI process creation"
        severity = "high"
    strings:
        $wmi1 = "Win32_Process" ascii
        $wmi2 = "Create" ascii
        $wmic = "wmic" ascii nocase
        $process = "process" ascii nocase
        $call = "call" ascii nocase
        $cmd = "cmd.exe" ascii nocase
        $ps = "powershell" ascii nocase
    condition:
        ($wmi1 and $wmi2) or ($wmic and $process and $call and any of ($cmd, $ps))
}

rule WMI_Remote_Execution {
    meta:
        description = "WMI remote execution"
        severity = "critical"
    strings:
        $wmi = "wmic" ascii nocase
        $node = "/node:" ascii nocase
        $remote = "\\\\*" ascii
        $process = "process" ascii nocase
        $call = "call" ascii nocase
        $create = "create" ascii nocase
        $user = "/user:" ascii nocase
        $password = "/password:" ascii nocase
    condition:
        $wmi and (any of ($node, $remote)) and ($process and any of ($call, $create))
}

rule WMI_WMIC_XSL {
    meta:
        description = "WMIC XSL script execution"
        severity = "critical"
    strings:
        $wmic = "wmic" ascii nocase
        $format = "/format:" ascii nocase
        $xsl = ".xsl" ascii nocase
        $http = "http" ascii nocase
        $script = "<script" ascii nocase
    condition:
        $wmic and $format and ($xsl or $http)
}

rule WMI_Lateral_Movement {
    meta:
        description = "WMI lateral movement"
        severity = "critical"
    strings:
        $wmi = "WMI" ascii
        $win32 = "Win32_" ascii
        $connect = "ConnectServer" ascii
        $impersonate = "impersonationLevel" ascii
        $auth = "authenticationLevel" ascii
        $remote = "\\\\*" ascii
    condition:
        $wmi and $win32 and ($connect or any of ($impersonate, $auth, $remote))
}

rule WMI_Persistence_Timer {
    meta:
        description = "WMI timer-based persistence"
        severity = "critical"
    strings:
        $timer = "__IntervalTimerInstruction" ascii
        $timer2 = "Win32_LocalTime" ascii
        $filter = "__EventFilter" ascii
        $consumer = "EventConsumer" ascii
        $interval = "IntervalBetweenEvents" ascii
    condition:
        (any of ($timer, $timer2)) and ($filter or $consumer or $interval)
}

rule WMI_Exfiltration {
    meta:
        description = "WMI-based data exfiltration"
        severity = "high"
    strings:
        $wmi = "WMI" ascii
        $namespace = "root\\" ascii nocase
        $query = "ExecQuery" ascii
        $select = "SELECT" ascii
        $dns = "Win32_PingStatus" ascii
        $http = "Win32_Process" ascii
    condition:
        $wmi and ($namespace or $query) and $select
}

rule WMI_Startup_Persistence {
    meta:
        description = "WMI startup persistence"
        severity = "critical"
    strings:
        $startup = "__InstanceCreationEvent" ascii
        $win32 = "Win32_ProcessStartup" ascii
        $logon = "Win32_LogonSession" ascii
        $filter = "__EventFilter" ascii
        $consumer = "CommandLineEventConsumer" ascii
    condition:
        (any of ($startup, $logon)) and ($filter or $consumer)
}

rule WMI_Registry_Operations {
    meta:
        description = "WMI registry operations"
        severity = "high"
    strings:
        $stdregprov = "StdRegProv" ascii
        $getstringvalue = "GetStringValue" ascii
        $setstringvalue = "SetStringValue" ascii
        $createkey = "CreateKey" ascii
        $deletekey = "DeleteKey" ascii
        $enumkey = "EnumKey" ascii
        $hklm = "2147483650" ascii  // HKLM constant
    condition:
        $stdregprov and (any of ($getstringvalue, $setstringvalue, $createkey, $deletekey, $enumkey))
}

rule WMI_Service_Manipulation {
    meta:
        description = "WMI service manipulation"
        severity = "high"
    strings:
        $service = "Win32_Service" ascii
        $change = "Change" ascii
        $create = "Create" ascii
        $delete = "Delete" ascii
        $start = "StartService" ascii
        $stop = "StopService" ascii
        $path = "PathName" ascii
    condition:
        $service and (2 of ($change, $create, $delete, $start, $stop, $path))
}

rule WMI_Shadow_Copy_Delete {
    meta:
        description = "WMI shadow copy deletion"
        severity = "critical"
    strings:
        $shadow = "Win32_ShadowCopy" ascii
        $delete = "Delete" ascii
        $wmic = "wmic" ascii nocase
        $shadowcopy = "shadowcopy" ascii nocase
        $all = "/all" ascii nocase
    condition:
        ($shadow and $delete) or ($wmic and $shadowcopy and $delete)
}

rule WMI_AntiVirus_Query {
    meta:
        description = "WMI antivirus detection query"
        severity = "medium"
    strings:
        $av1 = "AntiVirusProduct" ascii
        $av2 = "AntiSpywareProduct" ascii
        $av3 = "FirewallProduct" ascii
        $security = "SecurityCenter" ascii
        $select = "SELECT" ascii
    condition:
        (any of ($av*)) and ($security or $select)
}

rule WMI_System_Info_Gather {
    meta:
        description = "WMI system information gathering"
        severity = "medium"
    strings:
        $os = "Win32_OperatingSystem" ascii
        $cs = "Win32_ComputerSystem" ascii
        $bios = "Win32_BIOS" ascii
        $cpu = "Win32_Processor" ascii
        $disk = "Win32_DiskDrive" ascii
        $network = "Win32_NetworkAdapter" ascii
        $select = "SELECT" ascii
    condition:
        (3 of ($os, $cs, $bios, $cpu, $disk, $network)) and $select
}

rule WMI_Credential_Theft {
    meta:
        description = "WMI credential theft"
        severity = "critical"
    strings:
        $process = "Win32_Process" ascii
        $lsass = "lsass" ascii nocase
        $dump = "comsvcs" ascii
        $mini = "MiniDump" ascii
        $debug = "SeDebugPrivilege" ascii
    condition:
        $process and ($lsass or any of ($dump, $mini, $debug))
}

rule WMI_Defender_Disable {
    meta:
        description = "WMI Windows Defender disable"
        severity = "critical"
    strings:
        $wmi = "wmic" ascii nocase
        $defender = "defender" ascii nocase
        $antivirus = "AntiVirusProduct" ascii
        $disable = "disable" ascii nocase
        $remove = "remove" ascii nocase
        $set = "Set-MpPreference" ascii
    condition:
        $wmi and ($defender or $antivirus) and (any of ($disable, $remove, $set))
}

rule WMI_Namespace_Backdoor {
    meta:
        description = "WMI namespace backdoor"
        severity = "critical"
    strings:
        $namespace = "root\\default" ascii nocase
        $namespace2 = "root\\subscription" ascii nocase
        $class = "__NAMESPACE" ascii
        $new = "new" ascii nocase
        $create = "SpawnInstance" ascii
        $put = "Put_" ascii
    condition:
        (any of ($namespace, $namespace2)) and ($class or any of ($new, $create, $put))
}

rule WMI_Volume_Enumeration {
    meta:
        description = "WMI volume enumeration"
        severity = "medium"
    strings:
        $volume = "Win32_Volume" ascii
        $logical = "Win32_LogicalDisk" ascii
        $share = "Win32_Share" ascii
        $mapped = "Win32_MappedLogicalDisk" ascii
        $select = "SELECT" ascii
    condition:
        (2 of ($volume, $logical, $share, $mapped)) and $select
}

rule WMI_User_Account_Enum {
    meta:
        description = "WMI user account enumeration"
        severity = "medium"
    strings:
        $user = "Win32_UserAccount" ascii
        $group = "Win32_Group" ascii
        $member = "Win32_GroupUser" ascii
        $logon = "Win32_LogonSession" ascii
        $select = "SELECT" ascii
    condition:
        (2 of ($user, $group, $member, $logon)) and $select
}

rule WMI_MOF_Compilation {
    meta:
        description = "WMI MOF file compilation"
        severity = "critical"
    strings:
        $mofcomp = "mofcomp" ascii nocase
        $mof = ".mof" ascii nocase
        $pragma = "#pragma" ascii
        $class = "class " ascii
        $instance = "instance of" ascii nocase
        $event = "EventFilter" ascii
    condition:
        ($mofcomp and $mof) or ($pragma and $class and any of ($instance, $event))
}

rule WMI_CIM_Session {
    meta:
        description = "WMI CIM session abuse"
        severity = "high"
    strings:
        $cim1 = "New-CimSession" ascii
        $cim2 = "Get-CimInstance" ascii
        $cim3 = "Invoke-CimMethod" ascii
        $cim4 = "Set-CimInstance" ascii
        $remote = "-ComputerName" ascii
        $cred = "-Credential" ascii
    condition:
        (any of ($cim*)) and (any of ($remote, $cred))
}

