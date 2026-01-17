/*
    Supply Chain Attack Detection
    Package managers, build systems, and dependency attacks
*/

rule SupplyChain_NPM_Malicious {
    meta:
        description = "Malicious NPM package indicators"
        severity = "critical"
    strings:
        $npm = "package.json" ascii
        $scripts1 = "preinstall" ascii
        $scripts2 = "postinstall" ascii
        $scripts3 = "preuninstall" ascii
        $exec1 = "child_process" ascii
        $exec2 = "exec(" ascii
        $exec3 = "spawn(" ascii
        $net1 = "http.request" ascii
        $net2 = "https.request" ascii
        $net3 = "net.connect" ascii
        $fs = "fs.writeFile" ascii
        $env = "process.env" ascii
    condition:
        $npm and (any of ($scripts*)) and (any of ($exec*) or any of ($net*)) and ($fs or $env)
}

rule SupplyChain_PyPI_Malicious {
    meta:
        description = "Malicious PyPI package indicators"
        severity = "critical"
    strings:
        $setup = "setup.py" ascii
        $setup2 = "setup.cfg" ascii
        $cmd1 = "cmdclass" ascii
        $cmd2 = "install" ascii
        $exec1 = "subprocess" ascii
        $exec2 = "os.system" ascii
        $exec3 = "exec(" ascii
        $exec4 = "eval(" ascii
        $net = "urllib" ascii
        $net2 = "requests" ascii
        $b64 = "base64" ascii
    condition:
        (any of ($setup*)) and ($cmd1 and $cmd2) and (any of ($exec*)) and (any of ($net, $net2, $b64))
}

rule SupplyChain_RubyGems_Malicious {
    meta:
        description = "Malicious RubyGems package"
        severity = "critical"
    strings:
        $gem = ".gemspec" ascii
        $ext = "extensions" ascii
        $hook1 = "post_install" ascii
        $hook2 = "pre_install" ascii
        $exec1 = "system(" ascii
        $exec2 = "exec(" ascii
        $exec3 = "backtick" ascii
        $net = "Net::HTTP" ascii
        $open = "open-uri" ascii
    condition:
        $gem and (any of ($hook*)) and (any of ($exec*) or any of ($net, $open))
}

rule SupplyChain_Maven_Malicious {
    meta:
        description = "Malicious Maven artifact"
        severity = "critical"
    strings:
        $pom = "pom.xml" ascii
        $plugin = "<plugin>" ascii
        $exec1 = "exec-maven-plugin" ascii
        $exec2 = "Runtime.getRuntime" ascii
        $exec3 = "ProcessBuilder" ascii
        $net = "URLConnection" ascii
        $phase = "<phase>compile</phase>" ascii
    condition:
        $pom and $plugin and (any of ($exec*) or $net)
}

rule SupplyChain_Gradle_Malicious {
    meta:
        description = "Malicious Gradle build script"
        severity = "critical"
    strings:
        $gradle = "build.gradle" ascii
        $task = "task " ascii
        $exec1 = "exec {" ascii
        $exec2 = "commandLine" ascii
        $exec3 = "Runtime.getRuntime" ascii
        $net = "URL(" ascii
        $download = "download" ascii nocase
    condition:
        $gradle and $task and (any of ($exec*) or ($net and $download))
}

rule SupplyChain_Docker_Malicious {
    meta:
        description = "Malicious Dockerfile"
        severity = "high"
    strings:
        $docker = "Dockerfile" ascii
        $from = "FROM" ascii
        $run = "RUN" ascii
        $curl = "curl" ascii
        $wget = "wget" ascii
        $pipe = "| sh" ascii
        $pipe2 = "| bash" ascii
        $crypto = "crypto" ascii nocase
        $miner = "miner" ascii nocase
    condition:
        $docker and $from and $run and (($curl or $wget) and any of ($pipe, $pipe2)) or any of ($crypto, $miner)
}

rule SupplyChain_GitHub_Actions_Malicious {
    meta:
        description = "Malicious GitHub Actions workflow"
        severity = "high"
    strings:
        $workflow = ".github/workflows" ascii
        $yaml = ".yml" ascii
        $run = "run:" ascii
        $secret = "secrets." ascii
        $env = "${{" ascii
        $curl = "curl" ascii
        $exfil = "pastebin" ascii nocase
        $exfil2 = "discord" ascii nocase
    condition:
        ($workflow or $yaml) and $run and ($secret or $env) and ($curl and any of ($exfil, $exfil2))
}

rule SupplyChain_CI_CD_Compromise {
    meta:
        description = "CI/CD pipeline compromise indicators"
        severity = "critical"
    strings:
        $jenkins = "Jenkinsfile" ascii
        $gitlab = ".gitlab-ci.yml" ascii
        $travis = ".travis.yml" ascii
        $circle = "circleci" ascii nocase
        $secret1 = "AWS_SECRET" ascii
        $secret2 = "API_KEY" ascii
        $secret3 = "PASSWORD" ascii
        $exfil = "curl" ascii
        $env = "printenv" ascii
    condition:
        (any of ($jenkins, $gitlab, $travis, $circle)) and (any of ($secret*)) and ($exfil or $env)
}

rule SupplyChain_Build_System_Tamper {
    meta:
        description = "Build system tampering"
        severity = "critical"
    strings:
        $make = "Makefile" ascii
        $cmake = "CMakeLists.txt" ascii
        $msbuild = ".csproj" ascii
        $inject1 = "curl" ascii
        $inject2 = "wget" ascii
        $inject3 = "powershell" ascii nocase
        $compile = "gcc" ascii
        $compile2 = "clang" ascii
        $backdoor = "backdoor" ascii nocase
    condition:
        (any of ($make, $cmake, $msbuild)) and (any of ($inject*)) and any of ($compile, $compile2, $backdoor)
}

rule SupplyChain_Dependency_Confusion {
    meta:
        description = "Dependency confusion attack"
        severity = "critical"
    strings:
        $npm = "package.json" ascii
        $pypi = "requirements.txt" ascii
        $pip = "pip install" ascii
        $private = "private" ascii nocase
        $internal = "internal" ascii nocase
        $corp = "corp" ascii nocase
        $version = "9999" ascii
        $version2 = "99.99" ascii
    condition:
        (any of ($npm, $pypi, $pip)) and (any of ($private, $internal, $corp)) and any of ($version, $version2)
}

rule SupplyChain_Typosquatting {
    meta:
        description = "Typosquatting package indicators"
        severity = "high"
    strings:
        // Common typosquat patterns
        $typo1 = "loadsh" ascii  // lodash
        $typo2 = "requets" ascii  // requests
        $typo3 = "djang" ascii  // django
        $typo4 = "coloura" ascii  // colorama
        $typo5 = "crypt0" ascii  // crypto
        $malicious = "malicious" ascii nocase
        $backdoor = "backdoor" ascii nocase
    condition:
        (any of ($typo*)) or (any of ($malicious, $backdoor))
}

rule SupplyChain_Composer_Malicious {
    meta:
        description = "Malicious PHP Composer package"
        severity = "critical"
    strings:
        $composer = "composer.json" ascii
        $scripts = "\"scripts\"" ascii
        $post = "post-install-cmd" ascii
        $post2 = "post-update-cmd" ascii
        $exec1 = "exec(" ascii
        $exec2 = "shell_exec(" ascii
        $exec3 = "system(" ascii
        $eval = "eval(" ascii
    condition:
        $composer and $scripts and (any of ($post, $post2)) and (any of ($exec*) or $eval)
}

rule SupplyChain_Cargo_Malicious {
    meta:
        description = "Malicious Rust Cargo package"
        severity = "critical"
    strings:
        $cargo = "Cargo.toml" ascii
        $build = "build.rs" ascii
        $script = "[build-dependencies]" ascii
        $exec1 = "Command::new" ascii
        $exec2 = "std::process" ascii
        $net = "reqwest" ascii
        $net2 = "hyper" ascii
    condition:
        $cargo and ($build or $script) and (any of ($exec*)) and (any of ($net, $net2))
}

rule SupplyChain_NuGet_Malicious {
    meta:
        description = "Malicious NuGet package"
        severity = "critical"
    strings:
        $nuget = ".nuspec" ascii
        $nuget2 = "packages.config" ascii
        $ps = "install.ps1" ascii
        $ps2 = "init.ps1" ascii
        $exec = "Start-Process" ascii
        $exec2 = "Invoke-Expression" ascii
        $net = "Invoke-WebRequest" ascii
        $net2 = "DownloadString" ascii
    condition:
        (any of ($nuget*)) and (any of ($ps, $ps2)) and (any of ($exec, $exec2) or any of ($net, $net2))
}

rule SupplyChain_Go_Malicious {
    meta:
        description = "Malicious Go module"
        severity = "critical"
    strings:
        $go_mod = "go.mod" ascii
        $go_sum = "go.sum" ascii
        $init = "func init()" ascii
        $exec1 = "exec.Command" ascii
        $exec2 = "os/exec" ascii
        $net = "net/http" ascii
        $backdoor = "backdoor" ascii nocase
    condition:
        (any of ($go_mod, $go_sum)) and $init and (any of ($exec*)) and ($net or $backdoor)
}

rule SupplyChain_Homebrew_Malicious {
    meta:
        description = "Malicious Homebrew formula"
        severity = "high"
    strings:
        $formula = "Formula" ascii
        $brew = "Homebrew" ascii
        $install = "def install" ascii
        $system = "system " ascii
        $curl = "curl" ascii
        $wget = "wget" ascii
        $pipe = "| sh" ascii
        $pipe2 = "| bash" ascii
    condition:
        (any of ($formula, $brew)) and $install and ($system or ($curl or $wget) and any of ($pipe, $pipe2))
}

rule SupplyChain_APT_Repository {
    meta:
        description = "Malicious APT repository package"
        severity = "critical"
    strings:
        $control = "DEBIAN/control" ascii
        $postinst = "postinst" ascii
        $preinst = "preinst" ascii
        $postrm = "postrm" ascii
        $exec = "#!/bin/bash" ascii
        $curl = "curl" ascii
        $wget = "wget" ascii
        $nc = "nc " ascii
        $reverse = "reverse" ascii nocase
    condition:
        $control and (any of ($postinst, $preinst, $postrm)) and $exec and (any of ($curl, $wget, $nc) or $reverse)
}

rule SupplyChain_RPM_Malicious {
    meta:
        description = "Malicious RPM package"
        severity = "critical"
    strings:
        $spec = ".spec" ascii
        $pre = "%pre" ascii
        $post = "%post" ascii
        $preun = "%preun" ascii
        $exec = "/bin/sh" ascii
        $curl = "curl" ascii
        $wget = "wget" ascii
        $backdoor = "backdoor" ascii nocase
    condition:
        $spec and (any of ($pre, $post, $preun)) and $exec and (any of ($curl, $wget) or $backdoor)
}

rule SupplyChain_VS_Extension_Malicious {
    meta:
        description = "Malicious Visual Studio extension"
        severity = "high"
    strings:
        $vsix = ".vsix" ascii
        $manifest = "extension.vsixmanifest" ascii
        $js = ".js" ascii
        $exec1 = "child_process" ascii
        $exec2 = "exec(" ascii
        $net = "http.request" ascii
        $telemetry = "telemetry" ascii nocase
    condition:
        ($vsix or $manifest) and $js and (any of ($exec*) or $net)
}

rule SupplyChain_VSCode_Extension_Malicious {
    meta:
        description = "Malicious VS Code extension"
        severity = "high"
    strings:
        $package = "package.json" ascii
        $vscode = "vscode" ascii
        $activate = "activate" ascii
        $exec1 = "child_process" ascii
        $exec2 = "spawn" ascii
        $net = "https.request" ascii
        $fs = "fs.writeFile" ascii
        $env = "process.env" ascii
    condition:
        $package and $vscode and $activate and (any of ($exec*) or $net) and ($fs or $env)
}

rule SupplyChain_Browser_Extension_Malicious {
    meta:
        description = "Malicious browser extension"
        severity = "high"
    strings:
        $manifest = "manifest.json" ascii
        $content = "content_scripts" ascii
        $background = "background" ascii
        $perm1 = "tabs" ascii
        $perm2 = "webRequest" ascii
        $perm3 = "cookies" ascii
        $inject = "executeScript" ascii
        $storage = "storage" ascii
        $remote = "remote" ascii nocase
    condition:
        $manifest and ($content or $background) and (2 of ($perm*)) and ($inject or $storage)
}

