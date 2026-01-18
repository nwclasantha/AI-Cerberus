/*
    Living Off The Land Binaries (LOLBins)
    Legitimate Windows binaries abused for malicious purposes
*/

rule LOLBin_Certutil {
    meta:
        description = "Certutil abuse"
        severity = "high"
    strings:
        $certutil = "certutil" ascii nocase
        $url = "-urlcache" ascii nocase
        $split = "-split" ascii nocase
        // UNUSED: $f = "-f" ascii
        $decode = "-decode" ascii nocase
        $encode = "-encode" ascii nocase
        $http = "http" ascii nocase
    condition:
        $certutil and (any of ($url, $split, $decode, $encode) or $http)
}

rule LOLBin_Mshta {
    meta:
        description = "MSHTA abuse"
        severity = "critical"
    strings:
        $mshta = "mshta" ascii nocase
        $vbscript = "vbscript" ascii nocase
        $javascript = "javascript" ascii nocase
        $http = "http" ascii nocase
        $hta = ".hta" ascii nocase
        $inline = "Execute" ascii
    condition:
        $mshta and (any of ($vbscript, $javascript, $http, $hta, $inline))
}

rule LOLBin_Regsvr32 {
    meta:
        description = "Regsvr32 abuse (Squiblydoo)"
        severity = "critical"
    strings:
        $regsvr32 = "regsvr32" ascii nocase
        $scrobj = "scrobj.dll" ascii nocase
        $http = "http" ascii nocase
        $i = "/i:" ascii nocase
        $s = "/s" ascii
        $n = "/n" ascii
        // UNUSED: $u = "/u" ascii
    condition:
        $regsvr32 and ($scrobj or $http or ($i and ($s or $n)))
}

rule LOLBin_Rundll32 {
    meta:
        description = "Rundll32 abuse"
        severity = "high"
    strings:
        $rundll32 = "rundll32" ascii nocase
        $javascript = "javascript" ascii nocase
        // UNUSED: $shell32 = "shell32.dll" ascii nocase
        $advpack = "advpack.dll" ascii nocase
        $url = "url.dll" ascii nocase
        $ieframe = "ieframe.dll" ascii nocase
        $comsvcs = "comsvcs.dll" ascii
        $minidump = "MiniDump" ascii
    condition:
        $rundll32 and (any of ($javascript, $advpack, $url, $ieframe) or ($comsvcs and $minidump))
}

rule LOLBin_Wscript_Cscript {
    meta:
        description = "Wscript/Cscript abuse"
        severity = "high"
    strings:
        $wscript = "wscript" ascii nocase
        $cscript = "cscript" ascii nocase
        $e = "//e:" ascii nocase
        $b = "//b" ascii nocase
        $vbs = ".vbs" ascii nocase
        $js = ".js" ascii nocase
        $jse = ".jse" ascii nocase
        $wsf = ".wsf" ascii nocase
    condition:
        (any of ($wscript, $cscript)) and (any of ($e, $b, $vbs, $js, $jse, $wsf))
}

rule LOLBin_Msiexec {
    meta:
        description = "Msiexec abuse"
        severity = "high"
    strings:
        $msiexec = "msiexec" ascii nocase
        $q = "/q" ascii nocase
        $quiet = "/quiet" ascii nocase
        // UNUSED: $i = "/i" ascii nocase
        $http = "http" ascii nocase
        $y = "/y" ascii nocase
        $dll = ".dll" ascii nocase
    condition:
        $msiexec and (any of ($q, $quiet)) and ($http or ($y and $dll))
}

rule LOLBin_Cmstp {
    meta:
        description = "CMSTP abuse"
        severity = "critical"
    strings:
        $cmstp = "cmstp" ascii nocase
        $inf = ".inf" ascii nocase
        $au = "/au" ascii nocase
        $s = "/s" ascii
        $ni = "/ni" ascii nocase
        $runpresetup = "RunPreSetupCommands" ascii
    condition:
        $cmstp and ($inf and (any of ($au, $s, $ni)) or $runpresetup)
}

rule LOLBin_Bitsadmin {
    meta:
        description = "Bitsadmin abuse"
        severity = "high"
    strings:
        $bitsadmin = "bitsadmin" ascii nocase
        $transfer = "/transfer" ascii nocase
        $create = "/create" ascii nocase
        $addfile = "/addfile" ascii nocase
        $setnotifycmdline = "/SetNotifyCmdLine" ascii nocase
        // UNUSED: $resume = "/resume" ascii nocase
        $http = "http" ascii nocase
    condition:
        $bitsadmin and (($transfer and $http) or $setnotifycmdline or ($create and $addfile))
}

rule LOLBin_Forfiles {
    meta:
        description = "Forfiles abuse"
        severity = "medium"
    strings:
        $forfiles = "forfiles" ascii nocase
        // UNUSED: $p = "/p" ascii nocase
        // UNUSED: $s = "/s" ascii nocase
        $c = "/c" ascii nocase
        $cmd = "cmd" ascii nocase
        $exec = "0x" ascii
    condition:
        $forfiles and $c and ($cmd or $exec)
}

rule LOLBin_Pcalua {
    meta:
        description = "Pcalua abuse"
        severity = "high"
    strings:
        $pcalua = "pcalua" ascii nocase
        $a = "-a" ascii
        $c = "-c" ascii
        $d = "-d" ascii
        $exe = ".exe" ascii nocase
    condition:
        $pcalua and $a and (any of ($c, $d, $exe))
}

rule LOLBin_Ieexec {
    meta:
        description = "IEExec abuse"
        severity = "high"
    strings:
        $ieexec = "ieexec" ascii nocase
        $http = "http" ascii nocase
        // UNUSED: $exe = ".exe" ascii nocase
        // UNUSED: $framework = "Framework" ascii nocase
    condition:
        $ieexec and $http
}

rule LOLBin_Installutil {
    meta:
        description = "InstallUtil abuse"
        severity = "critical"
    strings:
        $installutil = "InstallUtil" ascii nocase
        $logfile = "/logfile=" ascii nocase
        $logtoconsole = "/LogToConsole=" ascii nocase
        $u = "/u" ascii
        $exe = ".exe" ascii nocase
        $dll = ".dll" ascii nocase
    condition:
        $installutil and (any of ($logfile, $logtoconsole, $u)) and (any of ($exe, $dll))
}

rule LOLBin_Regasm_Regsvcs {
    meta:
        description = "Regasm/Regsvcs abuse"
        severity = "critical"
    strings:
        $regasm = "regasm" ascii nocase
        $regsvcs = "regsvcs" ascii nocase
        $u = "/u" ascii
        $dll = ".dll" ascii nocase
        $tlb = "/tlb:" ascii nocase
    condition:
        (any of ($regasm, $regsvcs)) and (any of ($u, $dll, $tlb))
}

rule LOLBin_MSBuild {
    meta:
        description = "MSBuild abuse"
        severity = "critical"
    strings:
        $msbuild = "MSBuild" ascii nocase
        $csproj = ".csproj" ascii nocase
        $xml = ".xml" ascii nocase
        $proj = ".proj" ascii nocase
        $inline = "InlineTask" ascii
        $csharp = "CSharp" ascii
    condition:
        $msbuild and (any of ($csproj, $xml, $proj) or any of ($inline, $csharp))
}

rule LOLBin_Xwizard {
    meta:
        description = "Xwizard abuse"
        severity = "high"
    strings:
        $xwizard = "xwizard" ascii nocase
        $runwizard = "RunWizard" ascii nocase
        $guid = "{" ascii
        $clsid = "CLSID" ascii nocase
    condition:
        $xwizard and ($runwizard or ($guid and $clsid))
}

rule LOLBin_Syncappvpublishingserver {
    meta:
        description = "SyncAppvPublishingServer abuse"
        severity = "high"
    strings:
        $sync = "SyncAppvPublishingServer" ascii nocase
        $ps = "powershell" ascii nocase
        $n = "-n" ascii
        $script = "script" ascii nocase
    condition:
        $sync and ($ps or any of ($n, $script))
}

rule LOLBin_Odbcconf {
    meta:
        description = "Odbcconf abuse"
        severity = "high"
    strings:
        $odbcconf = "odbcconf" ascii nocase
        $a = "/a" ascii nocase
        $regsvr = "REGSVR" ascii nocase
        $dll = ".dll" ascii nocase
        $f = "/f" ascii nocase
        $rsp = ".rsp" ascii nocase
    condition:
        $odbcconf and (($a and $regsvr and $dll) or ($f and $rsp))
}

rule LOLBin_Dnscmd {
    meta:
        description = "Dnscmd abuse"
        severity = "critical"
    strings:
        $dnscmd = "dnscmd" ascii nocase
        $serverlevelplugin = "/ServerLevelPluginDll" ascii nocase
        $config = "/config" ascii nocase
        $dll = ".dll" ascii nocase
        // UNUSED: $unc = "\\\\" ascii
    condition:
        $dnscmd and ($serverlevelplugin or ($config and $dll))
}

rule LOLBin_Mavinject {
    meta:
        description = "Mavinject abuse"
        severity = "critical"
    strings:
        $mavinject = "mavinject" ascii nocase
        $injectrunning = "/INJECTRUNNING" ascii nocase
        $pid = "/PID" ascii nocase
        $dll = ".dll" ascii nocase
    condition:
        $mavinject and $injectrunning and (any of ($pid, $dll))
}

rule LOLBin_Ftp_exe {
    meta:
        description = "FTP.exe abuse"
        severity = "medium"
    strings:
        $ftp = "ftp.exe" ascii nocase
        $s = "-s:" ascii nocase
        $script = "script" ascii nocase
        $open = "open" ascii nocase
        $get = "get" ascii nocase
        $lcd = "lcd" ascii nocase
    condition:
        $ftp and $s and (2 of ($open, $get, $lcd, $script))
}

rule LOLBin_Diskshadow {
    meta:
        description = "Diskshadow abuse"
        severity = "high"
    strings:
        $diskshadow = "diskshadow" ascii nocase
        $s = "/s" ascii nocase
        $dsh = ".dsh" ascii nocase
        $txt = ".txt" ascii nocase
        $exec = "exec" ascii nocase
        $set = "set" ascii nocase
    condition:
        $diskshadow and $s and (any of ($dsh, $txt) or any of ($exec, $set))
}

rule LOLBin_Control_Panel {
    meta:
        description = "Control Panel item abuse"
        severity = "high"
    strings:
        $control = "control.exe" ascii nocase
        $cpl = ".cpl" ascii nocase
        $dll = ".dll" ascii nocase
        $http = "http" ascii nocase
        $unc = "\\\\" ascii
    condition:
        $control and (any of ($cpl, $dll)) and (any of ($http, $unc))
}

