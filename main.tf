// Terraform & Ansible Script to automate Okta Priviledged Access
// Author: Daniel Harris @ Okta
// Main OPA Feature Set

// Initial Configuration
// Required Terraform Providers

terraform {
  required_providers {
    okta = {
      source = "okta/okta"
      version = "3.34.0"
    }
    aws = {
      source = "hashicorp/aws"
      version = "4.26.0"
    }
    local = {
      source = "hashicorp/local"
      version = "2.2.3"
    }
    oktapam = {
      source = "okta/oktapam"
      version = "0.2.2"
    }
    external = {
      source = "hashicorp/external"
      version = "2.2.2"
    }
    kubernetes = {
      source = "hashicorp/kubernetes"
      version = "2.13.1"
    }
  }
}

// Terraform Provider Configuration
// Okta

provider "okta" {
  org_name  = var.okta_org
  base_url  = var.okta_environment
  api_token = var.okta_admintoken
  }

// Amazon Web Services
provider "aws" {
  region     = var.aws_region
  access_key = var.aws_access_key
  secret_key = var.aws_secret_key
}

// Okta Priviledged Access
provider "oktapam" {
  oktapam_key = var.opa_key
  oktapam_secret = var.opa_secret
  oktapam_team = var.opa_team
}

// Demo Setup 

// Okta - Look up Demo User ID (from config.tfvars)
data "okta_user" "demouser" {
  user_id = "${var.okta_demouser_id}"
}

// Okta - Create Attribute Domain Password Terraform
resource "okta_user_schema_property" "domain-password-terraform" {
  index       = "activeDirectoryIdentity"
  title       = "Active Directory Identity"
  type        = "array"
  array_type  = "string" 
  description = "activeDirectoryIdentity"
  master      = "OKTA"
  permissions = "READ_WRITE"
}

// Okta - Create Attribute Domain Passwordless Terrafom
resource "okta_user_schema_property" "domain-passwordless-terraform" {
  index       = "activeDirectoryPasswordlessIdentity"
  title       = "Active Directory Passwordless Identity"
  type        = "array"
  array_type  = "string" 
  description = "activeDirectoryPasswordlessIdentity"
  master      = "OKTA"
  permissions = "READ_WRITE"
}

resource "null_resource" "okta-attribute-update" {
  provisioner "local-exec" {
      command = <<EOT
        curl -s -X POST https://${var.okta_org}.${var.okta_environment}/api/v1/users/${var.okta_demouser_id} \
             -H 'Accept: application/json' \
             -H 'Content-Type: application/json' \
             -H 'Authorization: SSWS ${var.okta_admintoken}' \
             -d '{
                "profile": {
                      "activeDirectoryPasswordlessIdentity": [
                            "svc-iis@opa-domain.com"
                          ],
                      "activeDirectoryIdentity": [
                            "Administrator@opa-domain.com"
                           ]
                    }
                }'
EOT
  }
  depends_on = [
    okta_user_schema_property.domain-password-terraform, okta_user_schema_property.domain-passwordless-terraform
  ]
}

data "okta_user_profile_mapping_source" "okta-mapping-source" {}

// Okta - Map new user attributes to ASA Application Profile
resource "okta_profile_mapping" "opa-ad-joined-attributes-mapping" {
  source_id          = "${data.okta_user_profile_mapping_source.okta-mapping-source.id}"
  target_id          = var.okta_asa_app_id
  delete_when_absent = false
  always_apply = true

  mappings {
    id         = "activeDirectoryIdentity"
    expression = "user.activeDirectoryIdentity"
    push_status = "PUSH"
  }

  mappings {
    id         = "activeDirectoryPasswordlessIdentity"
    expression = "user.activeDirectoryPasswordlessIdentity"
    push_status = "PUSH"
  }
  depends_on = [
    okta_user_schema_property.domain-password-terraform, okta_user_schema_property.domain-passwordless-terraform
  ]
}

// Okta - Create OPA Full Administrators group
resource "okta_group" "opa_admins" {
  name        = "OPA Full Administrators"
  description = "Okta Priviledged Access Full Administrators"
}

// Okta - Create OPA System Administrators group
resource "okta_group" "systemadministrators" {
  name        = "OPA System Administrators"
  description = "Okta Priviledged Access System Administrators"
}

// Okta - Create OPA DevOps group
resource "okta_group" "opa_devops" {
  name        = "OPA DevOps"
  description = "Okta Priviledged Access DevOps Team Members"
}

// Okta - Create OPA Cloud Operations group
resource "okta_group" "opa_cloudops" {
  name        = "OPA Cloud Operations"
  description = "Okta Priviledged Access Cloud Operations Team Members"
}


// Okta - Assign ASA/OPA Demo User (from config.tfvars) to OPA Full Administrator Group
resource "okta_group_memberships" "opa_fulladmin_memberships" {
  group_id = okta_group.opa_admins.id
  users = [
    data.okta_user.demouser.user_id
  ]
}

// Okta - Look up ASA/OPA Application ID (from config.tfvars)
data "okta_app" "okta_asa_app_id" {
  id = "${var.okta_asa_app_id}"
}

// Okta - Assign OPA Groups to ASA/OPA Application
resource "okta_app_group_assignments" "okta_asa_group_assignment" {
  app_id   = "${var.okta_asa_app_id}"
  group {
    id = okta_group.opa_admins.id
    priority = 1
  }
  group {
    id = okta_group.systemadministrators.id
    priority = 2
  }
  group {
    id = okta_group.opa_devops.id
    priority = 3
  }
  group {
    id = okta_group.opa_cloudops.id
    priority = 3
  }
}

// OPA - Create Gateway Setup Token
resource "oktapam_gateway_setup_token" "opa-gateway-token" {
    description = "opa gateway token"
    labels = {env:"terraform"}
}

// OPA - Create OPA-Gateway Project
resource "oktapam_project" "opa-gateway" {
    name = "opa-gateway"
    create_server_users = true
    forward_traffic = true
    gateway_selector = "env=terraform"
    rdp_session_recording = true
    ssh_session_recording = true
}

// OPA - Create OPA-Gateway Project Enrollment Tokem
resource "oktapam_server_enrollment_token" "opa-gateway-enrollment-token" {
    description = "OPA Gateway Enrollment Token"
    project_name = oktapam_project.opa-gateway.name
}

// OPA - Assign 'everyone' group to the OPA-Gateway Project
// Future - Change to Okta Based Groups
resource "oktapam_project_group" "opa-everyone-group" {
  group_name    = "everyone"
  project_name  = oktapam_project.opa-gateway.name
  create_server_group = true
  server_access = true
  server_admin  = true
}

// OPA - Create OPA-Domain-Joined Project
resource "oktapam_project" "opa-domain-joined" {
    name = "opa-domain-joined"
    create_server_users = true
    forward_traffic = true
    gateway_selector = "env=terraform"
    rdp_session_recording = true
    ssh_session_recording = true
}

// OPA - Assign 'everyone' to OPA-Domain-Joined project
// Future - Change to Okta Based Groups
resource "oktapam_project_group" "opa-everyone-group-domain-joined" {
  group_name    = "everyone"
  project_name  = oktapam_project.opa-domain-joined.name
  create_server_group = false
  server_access = true
  server_admin  = false
}

// OPA - Create OPA-Linux project
resource "oktapam_project" "opa-linux" {
    name = "opa-linux"
    create_server_users = true
    forward_traffic = true
    gateway_selector = "env=terraform"
    rdp_session_recording = true
    ssh_session_recording = true
}

// OPA - Assign 'everyone' to OPA-Linux project
// Future - Change to Okta Based Groups
resource "oktapam_project_group" "opa-everyone-group-linux" {
  group_name    = "everyone"
  project_name  = oktapam_project.opa-linux.name
  create_server_group = true
  server_access = true
  server_admin  = true
}

// OPA - Create OPA-Linux Project Enrollment Tokem
resource "oktapam_server_enrollment_token" "opa-linux-enrollment-token" {
    description = "OPA Linux Enrollment Token"
    project_name = oktapam_project.opa-linux.name
}

// OPA - Create OPA-Windows Project
resource "oktapam_project" "opa-windows-target" {
    name = "opa-windows"
    create_server_users = true
    forward_traffic = true
    gateway_selector = "env=terraform"
    rdp_session_recording = true
    ssh_session_recording = true
    require_preauth_for_creds = true
}

// OPA - Assign 'everyone' to OPA-Windows Project
// Future - Change to Okta Based Groups
resource "oktapam_project_group" "opa-everyone-group-windows" {
  group_name    = "everyone"
  project_name  = oktapam_project.opa-windows-target.name
  create_server_group = true
  server_access = true
  server_admin  = false
}

// OPA - Create OPA-Windows Project Enrollment Token
resource "oktapam_server_enrollment_token" "opa-windows-enrollment-token" {
    description = "OPA Windows Enrollment Token"
    project_name = oktapam_project.opa-windows-target.name
}

# // OPA - Fetch Bearer Token
# resource "null_resource" "opa-bearer-token" {
#   provisioner "local-exec" {
#       command = <<EOT
#         curl -s -X POST https://app.scaleft.com/v1/teams/${var.opa_team}/service_token \
#              -H 'Content-Type: application/json' \
#              -H 'Authorization: Bearer' \
#              -d '{
#     "key_id": "${var.opa_key}",
#     "key_secret": "${var.opa_secret}"
# }'
# EOT
#   }
# }

# // OPA - Create Sudo Entitlement
# resource "null_resource" "opa-sudo-entitlement-create" {
#   provisioner "local-exec" {
#       command = <<EOT
#         curl -s -X POST https://app.scaleft.com/v1/teams/${var.opa_team}/entitlements/sudo \
#              -H 'Accept: application/json' \
#              -H 'Content-Type: application/json' \
#              -H 'Authorization: Bearer' \
#              -d '{
#     "name": "test",
#     "add_env": [],
#     "description": "test",
#     "opt_no_exec": false,
#     "opt_no_passwd": true,
#     "opt_run_as": "root",
#     "opt_set_env": false,
#     "commands": [],
#     "structured_commands": [
#         {
#             "args": "update",
#             "args_type": "custom",
#             "command": "/usr/bin/apt-get",
#             "command_type": "executable"
#         }
#     ],
#     "sub_env": []
# }'
# EOT
#   }
# }

// OPA - Assign Sudo Entitlement to Project Group
// TO DO

// OPA - Create self-signed certificate for password-less authentication to windows ad joined machines
resource "oktapam_ad_certificate_request" "opa_ad_self_signed_cert" {
  type         = "self_signed"
  display_name = "opa_ad_cert"
  common_name  = "opa"
  details {
   ttl_days = 90
  }
}

// Local - Copy OPA AD Certificate locally to copy onto Domain Controller
resource "local_file" "opa_ad_self_signed_cert" {
  content = oktapam_ad_certificate_request.opa_ad_self_signed_cert.content
  filename = "temp/certs/opa_ss.cer"
}

// AWS - Create OPA Demo Network on AWS (VPC, Internet Gateway, Route, Subnet, Interfaces)
// AWS - Create VPC
resource "aws_vpc" "opa-vpc" {
  cidr_block = "172.16.0.0/16"

  tags = {
    Name = "opa-vpc"
    Project = "opa-terraform"
  }
}

// AWS - Create Internet Gateway
resource "aws_internet_gateway" "opa-internet-gateway" {
  vpc_id = "${aws_vpc.opa-vpc.id}"

  tags = {
  Name = "opa-internet-gateway"
  Project = "opa-terraform"
  }
}

// AWS - Create Route
resource "aws_route" "opa-route" {
  route_table_id         = "${aws_vpc.opa-vpc.main_route_table_id}"
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = "${aws_internet_gateway.opa-internet-gateway.id}"
}

// AWS - Create Subnet
resource "aws_subnet" "opa-subnet" {
  vpc_id            = aws_vpc.opa-vpc.id
  cidr_block        = "172.16.10.0/24"
  availability_zone = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = {
    Name = "opa-subnet"
    Project = "opa-terraform"
  }
}

// AWS - Create OPA-GW-Interfact Network Interface
resource "aws_network_interface" "opa-gw-interface" {
  subnet_id   = aws_subnet.opa-subnet.id
  private_ips = ["172.16.10.100"]
  security_groups = [aws_security_group.opa-gateway.id]

  tags = {
    Name = "opa-gw-interface"
    Project = "opa-terraform"
  }
}

// AWS - Create OPA-Domain-Controller Network Interface
resource "aws_network_interface" "opa-dc-interface" {
  subnet_id   = aws_subnet.opa-subnet.id
  private_ips = ["172.16.10.150"]
  security_groups = [aws_security_group.opa-domain-controller.id]

 tags = {
    Name = "opa-dc-interface"
    Project = "opa-terraform"
  }
}

// AWS - Create OPA-Linux-Target Network Interface
resource "aws_network_interface" "opa-linux-target-interface" {
  subnet_id   = aws_subnet.opa-subnet.id
  private_ips = ["172.16.10.200"]
  security_groups = [aws_security_group.opa-linux-target.id]

 tags = {
    Name = "opa-linux-interface"
    Project = "opa-terraform"
  }
}

// AWS - Create OPA-Linux-Target-2 Network Interface
resource "aws_network_interface" "opa-linux-target-2-interface" {
  subnet_id   = aws_subnet.opa-subnet.id
  private_ips = ["172.16.10.205"]
  security_groups = [aws_security_group.opa-linux-target-2.id]

 tags = {
    Name = "opa-linux-interface-2"
    Project = "opa-terraform"
  }
}

// AWS - Create OPA-Windows-Target Network Interface
resource "aws_network_interface" "opa-windows-target-interface" {
  subnet_id   = aws_subnet.opa-subnet.id
  private_ips = ["172.16.10.210"]
  security_groups = [aws_security_group.opa-windows-target.id]

 tags = {
    Name = "opa-windows-target-interface"
    Project = "opa-terraform"
  }
}

// AWS - Look Up Latest Ubuntu Image on AWS
data "aws_ami" "ubuntu" {
  most_recent = true

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = ["099720109477"] # Canonical
}

// AWS - Look Up Latest Windows Image on AWS
data "aws_ami" "windows" {
     most_recent = true
     filter {
        name   = "name"
        values = ["Windows_Server-2019-English-Full-Base-*"]
 }
     filter {
       name   = "virtualization-type"
       values = ["hvm"]
 }
     owners = ["801119661308"] # Canonical
 }

// AWS - Create OPA-Gateway
resource "aws_instance" "opa-gateway" {
  ami                           = data.aws_ami.ubuntu.id
  instance_type                 = "t2.micro"
  key_name                      = var.aws_key_pair
  user_data_replace_on_change   = true
  user_data                     = <<EOF
#!/bin/bash
sudo apt-get update
sudo apt-get -y install resolvconf
echo "nameserver 172.16.10.150" > /etc/resolvconf/resolv.conf.d/head
sudo resolvconf -u

echo "Retrieve information about new packages"
sudo apt-get update
sudo apt-get install -y curl

echo "Trust the repository signing key"
curl -fsSL https://dist.scaleft.com/pki/scaleft_deb_key.asc | gpg --dearmor | sudo tee /usr/share/keyrings/scaleft-archive-keyring.gpg > /dev/null

echo "Add the ASA repos to the repolist"
printf "deb [arch=amd64 signed-by=/usr/share/keyrings/scaleft-archive-keyring.gpg] http://pkg.scaleft.com/deb focal main\ndeb [arch=amd64 signed-by=/usr/share/keyrings/scaleft-archive-keyring.gpg] http://pkg.scaleft.com/deb linux main" | sudo tee /etc/apt/sources.list.d/scaleft.list > /dev/null

echo "Retrieve information about new packages"
sudo apt-get update

echo "Install Gateway"
sudo apt-get install scaleft-gateway
echo ${oktapam_gateway_setup_token.opa-gateway-token.token} > /var/lib/sft-gatewayd/setup.token
echo "RDP:" > /etc/sft/sft-gatewayd.yaml
echo "        Enabled: true" >> /etc/sft/sft-gatewayd.yaml
echo "        DangerouslyIgnoreServerCertificates: true" >> /etc/sft/sft-gatewayd.yaml
sudo service sft-gatewayd restart

echo "Install Server Tools"
sudo mkdir -p /var/lib/sftd
echo ${oktapam_server_enrollment_token.opa-gateway-enrollment-token.token} > /var/lib/sftd/enrollment.token
echo "CanonicalName: opa-gateway" > /etc/sft/sftd.yaml
sudo apt-get update
sudo apt-get install scaleft-server-tools
hostnamectl set-hostname opa-gateway
reboot
EOF

  tags = {
    Name = "opa-gateway"
    Project = "opa-terraform"
  }

    network_interface {
    network_interface_id = aws_network_interface.opa-gw-interface.id
    device_index         = 0
  }
}

// AWS - Create OPA-Gateway Security Group
resource "aws_security_group" "opa-gateway" {
  name        = "opa-gateway"
  description = "Ports required for OPA gateway"
  vpc_id      = aws_vpc.opa-vpc.id

  ingress {
    description      = "TCP 7234"
    from_port        = 7234
    to_port          = 7234
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
  }

   ingress {
    description      = "TCP 22"
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "opa-gateway"
    Project = "opa-terraform"
  }
}

// Local - Create Ansible Variables File used for Domain Controller Configuration
resource "local_file" "ansible_vars_tf" {
  content  = <<-DOC
windows_domain_controller_info:
  domain_name: ${var.domain_name}
  domain_admin_password: ${var.windows_password}
  domain_admin_user: ${var.windows_username}@${var.domain_name}
  safe_mode_password: ${var.windows_password}
  state: domain_controller
certificate_info:
  win_cert_dir: C:\
  local_cert_dir: ../../temp/certs/
  ss_file_name: opa_ss.cer
  DOC
  filename = "ansible/vars/vars.yml"
}

// AWS - Create OPA-Domain-Controller

resource "aws_instance" "opa-domain-controller" {
  ami           = data.aws_ami.windows.id
  instance_type = "t2.small"
  key_name      = var.aws_key_pair
  
  tags = {
    Name        = "opa-domain-controller"
    Project     = "opa-terraform"
  }

  user_data = <<EOF
  <powershell>
  $admin = [adsi]("WinNT://./${var.windows_username}, user")
  $admin.PSBase.Invoke("SetPassword", "${var.windows_password}")
  Invoke-Expression ((New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/ansible/ansible/devel/examples/scripts/ConfigureRemotingForAnsible.ps1'))
  Enable-WSManCredSSP -Role Server -Force
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
  Install-PackageProvider -Name NuGet -Force
  Install-Module PowerShellGet -AllowClobber -Force
  </powershell>
  EOF

  provisioner "local-exec" {
    working_dir = "ansible"
    command     = "sleep 120;cp hosts.default hosts; sed -i '' -e 's/USERNAME/${var.windows_username}/g' -e 's/PASSWORD/${var.windows_password}/g' -e 's/PUBLICIP/${aws_instance.opa-domain-controller.public_ip}/g' hosts;ansible-playbook -v -i hosts playbooks/windows_dc.yml"
  }

  network_interface {
    network_interface_id = aws_network_interface.opa-dc-interface.id
    device_index         = 0
  }
}

// AWS - Create OPA-Domain-Controller Security Group
resource "aws_security_group" "opa-domain-controller" {
  name        = "opa-domain-controller"
  description = "Ports required for OPA Domain Controller"
  vpc_id      = aws_vpc.opa-vpc.id
  
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]

    description = "Allow incoming RDP connections"
  }

  ingress {
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = ["${aws_instance.opa-gateway.private_ip}/32", "${aws_instance.opa-gateway.public_ip}/32"]
    description = "Allow incoming TCP DNS connections"
  }

  ingress {
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["${aws_instance.opa-gateway.private_ip}/32", "${aws_instance.opa-gateway.public_ip}/32"]
    description = "Allow incoming UDP DNS connections"
  }

  ingress {
    from_port   = 389
    to_port     = 389
    protocol    = "tcp"
    cidr_blocks = ["${aws_instance.opa-gateway.private_ip}/32", "${aws_instance.opa-gateway.public_ip}/32"]
    description = "Allow incoming TCP LDAP connections"
  }

  ingress {
    from_port   = 636
    to_port     = 636
    protocol    = "tcp"
    cidr_blocks = ["${aws_instance.opa-gateway.private_ip}/32", "${aws_instance.opa-gateway.public_ip}/32"]
    description = "Allow incoming TCP LDAPS connections"
  }

   ingress {
    from_port   = 5986
    to_port     = 5986
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow incoming WinRM connections"
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
  tags = {
    Name = "opa-domain-controller"
    Project = "opa-terraform"
  }
}

// AWS - Create OPA-Linux-Target
resource "aws_instance" "opa-linux-target" {
  ami                           = data.aws_ami.ubuntu.id
  instance_type                 = "t2.micro"
  key_name                      = var.aws_key_pair
  user_data_replace_on_change   = true
  user_data                     = <<EOF
#!/bin/bash
echo "Retrieve information about new packages"
sudo apt-get update
sudo apt-get install -y curl

echo "Trust the repository signing key"
curl -fsSL https://dist.scaleft.com/pki/scaleft_deb_key.asc | gpg --dearmor | sudo tee /usr/share/keyrings/scaleft-archive-keyring.gpg > /dev/null

echo "Add the ASA repos to the repolist"
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/scaleft-archive-keyring.gpg] http://pkg.scaleft.com/deb linux main" | sudo tee -a /etc/apt/sources.list.d/scaleft.list > /dev/null

echo "Retrieve information about new packages"
sudo apt-get update

echo "Install Server Tools"
sudo mkdir -p /var/lib/sftd
sudo mkdir -p /etc/sft
echo ${oktapam_server_enrollment_token.opa-linux-enrollment-token.token} > /var/lib/sftd/enrollment.token
echo "CanonicalName: opa-linux-target" | sudo tee /etc/sft/sftd.yaml
echo "Labels:" >> /etc/sft/sftd.yaml
echo "  role: devops" >> /etc/sft/sftd.yaml
echo "  env: staging" >> /etc/sft/sftd.yaml
echo "  env: test" >> /etc/sft/sftd.yaml
sudo apt-get update
sudo apt-get install scaleft-server-tools scaleft-client-tools
EOF
  
  tags = {
    Name        = "opa-linux-target"
    Project     = "opa-terraform"
  }

  network_interface {
    network_interface_id = aws_network_interface.opa-linux-target-interface.id
    device_index         = 0
  }
}

// AWS - Create OPA-Linux-Target Security Group
resource "aws_security_group" "opa-linux-target" {
  name        = "opa-linux-target"
  description = "Ports required for OPA Linux Target"
  vpc_id      = aws_vpc.opa-vpc.id
  
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["${aws_instance.opa-gateway.private_ip}/32", "${aws_instance.opa-gateway.public_ip}/32"]
    description = "Allow incoming SSH connections"
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
  tags = {
    Name = "opa-linux-target"
    Project = "opa-terraform"
  }
}

// AWS - Create OPA-Linux-Target-2
resource "aws_instance" "opa-linux-target-2" {
  ami                           = data.aws_ami.ubuntu.id
  instance_type                 = "t2.micro"
  key_name                      = var.aws_key_pair
  user_data_replace_on_change   = true
  user_data                     = <<EOF
#!/bin/bash
echo "Retrieve information about new packages"
sudo apt-get update
sudo apt-get install -y curl

echo "Trust the repository signing key"
curl -fsSL https://dist.scaleft.com/pki/scaleft_deb_key.asc | gpg --dearmor | sudo tee /usr/share/keyrings/scaleft-archive-keyring.gpg > /dev/null

echo "Add the ASA repos to the repolist"
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/scaleft-archive-keyring.gpg] http://pkg.scaleft.com/deb linux main" | sudo tee -a /etc/apt/sources.list.d/scaleft.list > /dev/null

echo "Retrieve information about new packages"
sudo apt-get update

echo "Install Server Tools"
sudo mkdir -p /var/lib/sftd
sudo mkdir -p /etc/sft
echo ${oktapam_server_enrollment_token.opa-linux-enrollment-token.token} > /var/lib/sftd/enrollment.token
echo "CanonicalName: opa-linux-target-2" | sudo tee /etc/sft/sftd.yaml
echo "Labels:" >> /etc/sft/sftd.yaml
echo "  role: devops" >> /etc/sft/sftd.yaml
echo "  env: staging" >> /etc/sft/sftd.yaml
echo "  env: test" >> /etc/sft/sftd.yaml
sudo apt-get update
sudo apt-get install scaleft-server-tools
EOF
  
  tags = {
    Name        = "opa-linux-target-2"
    Project     = "opa-terraform"
  }

  network_interface {
    network_interface_id = aws_network_interface.opa-linux-target-2-interface.id
    device_index         = 0
  }
}

// AWS - Create OPA-Linux-Target-2 Security Group
resource "aws_security_group" "opa-linux-target-2" {
  name        = "opa-linux-target-2"
  description = "Ports required for OPA Linux Target 2"
  vpc_id      = aws_vpc.opa-vpc.id
  
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["${aws_instance.opa-gateway.private_ip}/32", "${aws_instance.opa-gateway.public_ip}/32", "${aws_instance.opa-linux-target.private_ip}/32", "${aws_instance.opa-linux-target.public_ip}/32"]
    description = "Allow incoming SSH connections"
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
  tags = {
    Name = "opa-linux-target-2"
    Project = "opa-terraform"
  }
}

// AWS - Create OPA-Windows-Target
resource "aws_instance" "opa-windows-target" {
  ami = data.aws_ami.windows.id
  instance_type = "t2.micro"
  key_name = var.aws_key_pair
  user_data_replace_on_change = true
  user_data = <<EOF
  <script>
msiexec /qb /I https://dist.scaleft.com/server-tools/windows/latest/ScaleFT-Server-Tools-latest.msi
mkdir C:\Windows\System32\config\systemprofile\AppData\Local\scaleft
echo ${oktapam_server_enrollment_token.opa-windows-enrollment-token.token}  > C:\windows\system32\config\systemprofile\AppData\Local\scaleft\enrollment.token
echo CanonicalName: opa-windows-target > C:\Windows\System32\config\systemprofile\AppData\Local\scaleft\sftd.yaml
net stop scaleft-server-tools && net start scaleft-server-tools
</script>
  EOF
  
  tags = {
    Name        = "opa-windows-target"
    Project     = "opa-terraform"
  }

  network_interface {
    network_interface_id = aws_network_interface.opa-windows-target-interface.id
    device_index         = 0
  }
}

// AWS - Create OPA-Windows-Target Security Group
resource "aws_security_group" "opa-windows-target" {
  name        = "opa-windows-target"
  description = "Ports required for OPA Windows Target"
  vpc_id      = aws_vpc.opa-vpc.id
  
  ingress {
    from_port   = 4421
    to_port     = 4421
    protocol    = "tcp"
    cidr_blocks = ["${aws_instance.opa-gateway.private_ip}/32", "${aws_instance.opa-gateway.public_ip}/32"]
    description = "Allow incoming Broker port connections"
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
  tags = {
    Name = "opa-windows-target"
    Project = "opa-terraform"
  }
}

// OPA - Creating gateway is not supported. Get the gateway id using datasource
data "oktapam_gateways" "opa-gateway" {
  contains = "opa-gateway" # Filter gateway that contains given name
depends_on = [
  aws_instance.opa-domain-controller
]
}

// OPA - Create Active Directory Connection
resource "oktapam_ad_connection" "opa-ad-connection" {
  name                     = "opa-ad-connection"
  gateway_id               = data.oktapam_gateways.opa-gateway.gateways[0].id
  domain                   = var.domain_name
  service_account_username = "${var.windows_username}@${var.domain_name}"
  service_account_password = var.windows_password
  use_passwordless         = true
  certificate_id           = oktapam_ad_certificate_request.opa_ad_self_signed_cert.id
  #domain_controllers       = ["dc1.com", "dc2.com"] //Optional: DC used to query the domain
}

data "oktapam_project" "ad-domain-joined-project" {
  name = "opa-domain-joined"
}

// OPA - Create AD Joined Server Discovery Task
resource "oktapam_ad_task_settings" "opa_ad_task_settings" {
  connection_id            = oktapam_ad_connection.opa-ad-connection.id
  name                     = "opa-ad-job"
  is_active                = true
  frequency                = 1 # Every 12 hours Note: If 24 hours then start_hour_utc is required
  host_name_attribute      = "dNSHostName"
  access_address_attribute = "dNSHostName"
  os_attribute             = "operatingSystem"
  run_test                 = true
  rule_assignments {
    base_dn           = "ou=Domain Controllers,dc=opa-domain,dc=com"
    ldap_query_filter = "(objectCategory=Computer)"
    project_id        = oktapam_project.opa-domain-joined.project_id
    priority          = 1
  }
}