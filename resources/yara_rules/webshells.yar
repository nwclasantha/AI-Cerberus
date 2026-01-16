/*
    Webshell Detection Rules
    Covers: PHP, ASP, JSP, and other web shells
*/

rule PHP_WebShell_Generic {
    meta:
        description = "Generic PHP webshell"
        severity = "critical"
    strings:
        $php = "<?php" nocase
        $eval1 = "eval(" ascii
        $eval2 = "assert(" ascii
        $eval3 = "preg_replace" ascii
        $b64 = "base64_decode" ascii
        $exec1 = "system(" ascii
        $exec2 = "exec(" ascii
        $exec3 = "shell_exec(" ascii
        $exec4 = "passthru(" ascii
        $exec5 = "popen(" ascii
    condition:
        $php and (any of ($eval*) or any of ($exec*) or $b64)
}

rule PHP_WebShell_C99 {
    meta:
        description = "C99 PHP webshell"
        severity = "critical"
    strings:
        $s1 = "c99shell" nocase
        $s2 = "c99" nocase
        $s3 = "r57shell" nocase
        $s4 = "phpinfo()" ascii
        $s5 = "$GLOBALS" ascii
    condition:
        2 of them
}

rule PHP_WebShell_WSO {
    meta:
        description = "WSO PHP webshell"
        severity = "critical"
    strings:
        $s1 = "WSO" ascii
        $s2 = "Web Shell by oRb" ascii
        $s3 = "wso.php" ascii
        $s4 = "FilesMan" ascii
    condition:
        any of them
}

rule PHP_WebShell_B374K {
    meta:
        description = "B374K PHP webshell"
        severity = "critical"
    strings:
        $s1 = "b374k" nocase
        $s2 = "b374k shell" nocase
        $s3 = "password" ascii
        $auth = "md5(" ascii
    condition:
        any of ($s*) or $auth
}

rule PHP_WebShell_Weevely {
    meta:
        description = "Weevely PHP webshell"
        severity = "critical"
    strings:
        $s1 = "weevely" nocase
        $s2 = "str_replace" ascii
        $s3 = "strrev" ascii
        $obf = "gzinflate" ascii
    condition:
        2 of ($s*) or $obf
}

rule ASP_WebShell_Generic {
    meta:
        description = "Generic ASP webshell"
        severity = "critical"
    strings:
        $asp1 = "<%@" nocase
        $asp2 = "<%=" nocase
        $asp3 = "Response.Write" nocase
        $exec1 = "WScript.Shell" nocase
        $exec2 = "Shell.Application" nocase
        $exec3 = "Scripting.FileSystemObject" nocase
        $cmd = "cmd.exe" nocase
    condition:
        (any of ($asp*)) and (any of ($exec*) or $cmd)
}

rule ASPX_WebShell_Generic {
    meta:
        description = "Generic ASPX webshell"
        severity = "critical"
    strings:
        $aspx1 = "<%@ Page" nocase
        $aspx2 = "<%@ WebService" nocase
        $exec1 = "Process.Start" nocase
        $exec2 = "ProcessStartInfo" nocase
        $exec3 = "cmd.exe" nocase
        $exec4 = "powershell" nocase
    condition:
        (any of ($aspx*)) and (any of ($exec*))
}

rule ASPX_China_Chopper {
    meta:
        description = "China Chopper ASPX webshell"
        severity = "critical"
    strings:
        $s1 = "<%@Page Language=" ascii
        $s2 = "eval(Request" nocase
        $s3 = "unsafe" ascii
        $s4 = "Request.Item" nocase
    condition:
        $s1 and any of ($s2, $s3, $s4)
}

rule JSP_WebShell_Generic {
    meta:
        description = "Generic JSP webshell"
        severity = "critical"
    strings:
        $jsp1 = "<%@page" nocase
        $jsp2 = "<%=" nocase
        $exec1 = "Runtime.getRuntime()" nocase
        $exec2 = "ProcessBuilder" nocase
        $exec3 = "exec(" ascii
        $cmd = "/bin/sh" ascii
    condition:
        (any of ($jsp*)) and (any of ($exec*) or $cmd)
}

rule JSP_Webshell_JspSpy {
    meta:
        description = "JspSpy webshell"
        severity = "critical"
    strings:
        $s1 = "JspSpy" ascii
        $s2 = "jspspy" ascii
        $s3 = "request.getParameter" ascii
        $s4 = "FileOutputStream" ascii
    condition:
        2 of them
}

rule PHP_Obfuscated_Shell {
    meta:
        description = "Obfuscated PHP shell"
        severity = "critical"
    strings:
        $obf1 = "\\x" ascii
        $obf2 = "chr(" ascii
        $obf3 = "ord(" ascii
        $obf4 = "pack(" ascii
        $decode = "base64_decode" ascii
        $eval = "eval(" ascii
    condition:
        3 of ($obf*) or ($decode and $eval)
}

rule WebShell_Upload_Script {
    meta:
        description = "File upload webshell"
        severity = "critical"
    strings:
        $s1 = "move_uploaded_file" ascii
        $s2 = "$_FILES" ascii
        $s3 = "enctype=\"multipart" ascii
        $s4 = "tmp_name" ascii
    condition:
        2 of them
}

rule Python_WebShell {
    meta:
        description = "Python webshell"
        severity = "critical"
    strings:
        $s1 = "os.system" ascii
        $s2 = "subprocess" ascii
        $s3 = "exec(" ascii
        $s4 = "import os" ascii
        $s5 = "os.popen" ascii
    condition:
        2 of them
}

rule Perl_WebShell {
    meta:
        description = "Perl webshell"
        severity = "critical"
    strings:
        $perl1 = "#!/usr/bin/perl" ascii
        $perl2 = "#!/usr/local/bin/perl" ascii
        $exec1 = "system(" ascii
        $exec2 = "exec(" ascii
        $exec3 = "`" ascii
    condition:
        (any of ($perl*)) and (any of ($exec*))
}

rule WebShell_Reverse_Shell {
    meta:
        description = "Reverse shell webshell"
        severity = "critical"
    strings:
        $s1 = "fsockopen" ascii
        $s2 = "socket_create" ascii
        $s3 = "stream_socket_client" ascii
        $s4 = "/dev/tcp/" ascii
        $s5 = "nc -e" ascii
        $bash = "bash -i" ascii
    condition:
        any of them
}

rule ColdFusion_WebShell {
    meta:
        description = "ColdFusion webshell"
        severity = "critical"
    strings:
        $cf1 = "<cfexecute" nocase
        $cf2 = "<cffile" nocase
        $cf3 = "name=\"cmd\"" nocase
        $cmd = "cmd.exe" nocase
    condition:
        any of ($cf*) or $cmd
}

rule Exchange_ProxyShell {
    meta:
        description = "Exchange ProxyShell webshell"
        severity = "critical"
    strings:
        $s1 = "ProxyShell" ascii
        $s2 = "autodiscover" nocase
        $s3 = "mapi/nspi" nocase
        $s4 = "X-BEResource" nocase
    condition:
        2 of them
}

rule WebShell_FileBrowser {
    meta:
        description = "File browser webshell"
        severity = "high"
    strings:
        $s1 = "scandir" ascii
        $s2 = "opendir" ascii
        $s3 = "readdir" ascii
        $s4 = "file_get_contents" ascii
        $s5 = "file_put_contents" ascii
        $delete = "unlink(" ascii
    condition:
        3 of ($s*) or $delete
}

rule WebShell_Database_Access {
    meta:
        description = "Database access webshell"
        severity = "high"
    strings:
        $s1 = "mysql_connect" ascii
        $s2 = "mysqli_connect" ascii
        $s3 = "pg_connect" ascii
        $s4 = "mssql_connect" ascii
        $s5 = "oci_connect" ascii
    condition:
        any of them
}

rule Godzilla_WebShell {
    meta:
        description = "Godzilla webshell"
        severity = "critical"
    strings:
        $s1 = "Godzilla" ascii
        $s2 = "godzilla" ascii
        $s3 = "AES" ascii
        $s4 = "pass=" ascii
    condition:
        2 of them
}

rule Behinder_WebShell {
    meta:
        description = "Behinder/Rebeyond webshell"
        severity = "critical"
    strings:
        $s1 = "Behinder" ascii
        $s2 = "rebeyond" ascii
        $s3 = "e45e329feb5d925b" ascii
        $aes = "AES/CBC" ascii
    condition:
        any of ($s*) or $aes
}

rule AntSword_WebShell {
    meta:
        description = "AntSword webshell"
        severity = "critical"
    strings:
        $s1 = "AntSword" ascii
        $s2 = "antsword" ascii
        $s3 = "ant_" ascii
        $encoder = "chr(rand" ascii
    condition:
        any of them
}
