/*
    Container and Cloud Attack Detection
    Docker, Kubernetes, cloud platform attacks
*/

rule Container_Escape_Generic {
    meta:
        description = "Container escape indicators"
        severity = "critical"
    strings:
        $docker = "docker" ascii nocase
        $escape = "escape" ascii nocase
        $cgroup = "cgroup" ascii
        $release = "release_agent" ascii
        $notify = "notify_on_release" ascii
        $socket = "docker.sock" ascii
        $ns = "setns" ascii
    condition:
        uint32(0) == 0x464C457F and (($cgroup and any of ($release, $notify)) or $socket or $escape)
}

rule Container_Docker_Socket_Abuse {
    meta:
        description = "Docker socket abuse"
        severity = "critical"
    strings:
        $socket1 = "/var/run/docker.sock" ascii
        $socket2 = "docker.sock" ascii
        $api1 = "containers/create" ascii
        $api2 = "exec/create" ascii
        $api3 = "/images" ascii
        $curl = "curl" ascii
        $privileged = "Privileged" ascii
    condition:
        (any of ($socket*)) and (any of ($api*) or $privileged)
}

rule Container_Kubernetes_Attack {
    meta:
        description = "Kubernetes attack indicators"
        severity = "critical"
    strings:
        $k8s = "kubernetes" ascii nocase
        $kubectl = "kubectl" ascii
        $kubelet = "kubelet" ascii
        $api = "/api/v1" ascii
        $secret = "secrets" ascii
        $pod = "pods" ascii
        $exec = "exec" ascii
        $token = "serviceaccount" ascii
    condition:
        (any of ($k8s, $kubectl, $kubelet)) and (any of ($api, $secret, $pod, $exec, $token))
}

rule Container_Kubernetes_RBAC_Abuse {
    meta:
        description = "Kubernetes RBAC abuse"
        severity = "critical"
    strings:
        $rbac = "rbac" ascii nocase
        $role = "ClusterRole" ascii
        $binding = "RoleBinding" ascii
        $admin = "cluster-admin" ascii
        $create = "create" ascii
        $escalate = "escalate" ascii
        $impersonate = "impersonate" ascii
    condition:
        $rbac and ($role or $binding) and (any of ($admin, $create, $escalate, $impersonate))
}

rule Container_Cryptominer {
    meta:
        description = "Container cryptominer"
        severity = "high"
    strings:
        $docker = "docker" ascii nocase
        $k8s = "kubernetes" ascii nocase
        $xmrig = "xmrig" ascii nocase
        $monero = "monero" ascii nocase
        $stratum = "stratum" ascii
        $miner = "miner" ascii nocase
        $pool = "pool" ascii nocase
    condition:
        (any of ($docker, $k8s)) and (any of ($xmrig, $monero, $miner) and any of ($stratum, $pool))
}

rule Cloud_AWS_Credential_Theft {
    meta:
        description = "AWS credential theft"
        severity = "critical"
    strings:
        $aws = "AWS" ascii
        $cred1 = ".aws/credentials" ascii
        $cred2 = "aws_access_key_id" ascii
        $cred3 = "aws_secret_access_key" ascii
        $meta = "169.254.169.254" ascii
        $iam = "iam/security-credentials" ascii
        $env = "AWS_ACCESS_KEY" ascii
    condition:
        $aws and (any of ($cred*) or $meta or $iam or $env)
}

rule Cloud_AWS_S3_Abuse {
    meta:
        description = "AWS S3 bucket abuse"
        severity = "high"
    strings:
        $s3 = "s3.amazonaws.com" ascii
        $bucket = "bucket" ascii nocase
        $list = "ListBucket" ascii
        $get = "GetObject" ascii
        $put = "PutObject" ascii
        $public = "public" ascii nocase
        $acl = "ACL" ascii
    condition:
        $s3 and (any of ($list, $get, $put) or any of ($public, $acl))
}

rule Cloud_AWS_Lambda_Backdoor {
    meta:
        description = "AWS Lambda backdoor"
        severity = "critical"
    strings:
        $lambda = "lambda" ascii nocase
        $aws = "AWS" ascii
        $handler = "handler" ascii
        $invoke = "Invoke" ascii
        $create = "CreateFunction" ascii
        $layer = "Layer" ascii
        $runtime = "runtime" ascii
    condition:
        $lambda and $aws and (any of ($handler, $invoke, $create, $layer))
}

rule Cloud_Azure_Credential_Theft {
    meta:
        description = "Azure credential theft"
        severity = "critical"
    strings:
        $azure = "azure" ascii nocase
        $tenant = "tenant" ascii nocase
        $client = "client_id" ascii
        $secret = "client_secret" ascii
        $token = "access_token" ascii
        $meta = "169.254.169.254" ascii
        $imds = "metadata/identity" ascii
    condition:
        $azure and (any of ($tenant, $client, $secret, $token) or ($meta and $imds))
}

rule Cloud_Azure_RunCommand {
    meta:
        description = "Azure RunCommand abuse"
        severity = "critical"
    strings:
        $azure = "azure" ascii nocase
        $run = "RunCommand" ascii
        $compute = "compute" ascii nocase
        $vm = "virtualMachines" ascii
        $shell = "RunShellScript" ascii
        $powershell = "RunPowerShellScript" ascii
    condition:
        $azure and $run and (any of ($compute, $vm, $shell, $powershell))
}

rule Cloud_GCP_Credential_Theft {
    meta:
        description = "GCP credential theft"
        severity = "critical"
    strings:
        $gcp = "google" ascii nocase
        $gcloud = "gcloud" ascii
        $cred = "application_default_credentials" ascii
        $service = "service_account" ascii
        $key = "private_key" ascii
        $meta = "metadata.google.internal" ascii
        $token = "access_token" ascii
    condition:
        (any of ($gcp, $gcloud)) and (any of ($cred, $service, $key) or ($meta and $token))
}

rule Cloud_GCP_Service_Account_Abuse {
    meta:
        description = "GCP service account abuse"
        severity = "critical"
    strings:
        $gcp = "google" ascii nocase
        $sa = "service_account" ascii
        $iam = "iam" ascii nocase
        $generate = "generateAccessToken" ascii
        $impersonate = "impersonate" ascii nocase
        $key = "createKey" ascii
    condition:
        $gcp and $sa and (any of ($generate, $impersonate, $key))
}

rule Cloud_Metadata_Service_Abuse {
    meta:
        description = "Cloud metadata service abuse"
        severity = "critical"
    strings:
        $meta_ip = "169.254.169.254" ascii
        $aws_meta = "latest/meta-data" ascii
        $azure_meta = "metadata/instance" ascii
        $gcp_meta = "computeMetadata" ascii
        $token = "token" ascii nocase
        $cred = "credential" ascii nocase
        $curl = "curl" ascii
        $wget = "wget" ascii
    condition:
        $meta_ip and (any of ($aws_meta, $azure_meta, $gcp_meta)) and (any of ($token, $cred) or any of ($curl, $wget))
}

rule Container_Privileged_Mode {
    meta:
        description = "Privileged container abuse"
        severity = "critical"
    strings:
        $privileged = "privileged" ascii nocase
        $cap_add = "cap_add" ascii nocase
        $sys_admin = "SYS_ADMIN" ascii
        $sys_ptrace = "SYS_PTRACE" ascii
        $all_caps = "ALL" ascii
        $docker = "docker" ascii nocase
    condition:
        $docker and ($privileged or (any of ($cap_add, $sys_admin, $sys_ptrace, $all_caps)))
}

rule Container_Host_Mount {
    meta:
        description = "Container host mount abuse"
        severity = "critical"
    strings:
        $mount = "mount" ascii nocase
        $volume = "volume" ascii nocase
        $hostpath = "hostPath" ascii
        $host_root = ":/:" ascii
        $proc = "/proc" ascii
        $sys = "/sys" ascii
        $dev = "/dev" ascii
    condition:
        (any of ($mount, $volume, $hostpath)) and (any of ($host_root, $proc, $sys, $dev))
}

rule Container_Image_Malicious {
    meta:
        description = "Malicious container image"
        severity = "high"
    strings:
        $docker = "docker" ascii nocase
        $pull = "pull" ascii
        $run = "run" ascii
        $crypto = "crypto" ascii nocase
        $miner = "miner" ascii nocase
        $backdoor = "backdoor" ascii nocase
        $reverse = "reverse" ascii nocase
    condition:
        $docker and (any of ($pull, $run)) and (any of ($crypto, $miner, $backdoor, $reverse))
}

rule Serverless_Function_Backdoor {
    meta:
        description = "Serverless function backdoor"
        severity = "critical"
    strings:
        $lambda = "lambda" ascii nocase
        $function = "function" ascii nocase
        $azure_func = "AzureFunction" ascii
        $gcp_func = "CloudFunction" ascii
        $shell = "shell" ascii nocase
        $exec = "exec" ascii nocase
        $reverse = "reverse" ascii nocase
    condition:
        (any of ($lambda, $azure_func, $gcp_func) or $function) and (any of ($shell, $exec, $reverse))
}

rule Cloud_IAM_Persistence {
    meta:
        description = "Cloud IAM persistence"
        severity = "critical"
    strings:
        $iam = "IAM" ascii
        $user = "CreateUser" ascii
        $role = "CreateRole" ascii
        $policy = "AttachPolicy" ascii
        $access_key = "CreateAccessKey" ascii
        $admin = "Admin" ascii nocase
        $persist = "persist" ascii nocase
    condition:
        $iam and (any of ($user, $role, $policy, $access_key)) and (any of ($admin, $persist))
}

rule Container_Registry_Attack {
    meta:
        description = "Container registry attack"
        severity = "high"
    strings:
        $registry = "registry" ascii nocase
        $ecr = "ecr" ascii nocase
        $gcr = "gcr.io" ascii
        $acr = "azurecr.io" ascii
        $docker_hub = "docker.io" ascii
        $push = "push" ascii
        $pull = "pull" ascii
        $tag = "tag" ascii
    condition:
        (any of ($registry, $ecr, $gcr, $acr, $docker_hub)) and (any of ($push, $pull, $tag))
}

rule Cloud_VPC_Manipulation {
    meta:
        description = "Cloud VPC manipulation"
        severity = "high"
    strings:
        $vpc = "VPC" ascii
        $security = "SecurityGroup" ascii
        $firewall = "firewall" ascii nocase
        $ingress = "ingress" ascii
        $egress = "egress" ascii
        $allow = "allow" ascii nocase
        $all_traffic = "0.0.0.0/0" ascii
    condition:
        ($vpc or $security or $firewall) and (any of ($ingress, $egress)) and ($allow or $all_traffic)
}

