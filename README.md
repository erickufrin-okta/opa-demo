# Okta Privileged Access - Demo Setup

This repository will set up a fully working OPA demo environment. It leverages Terraform and Ansible to deploy and configure the environment.

## Directions

This repository has been designed to be modular, this means that if you only need to deploy a single feature, like Kubernetes you can. Please read the instructions very carefully.

### Prerequisites

- Okta Demo Environment 
- OPA Team integrated into your Okta Demo environment
- Note: For older ASA Teams please create the ASA application attributes as described here: https://help.okta.com/asa/en-us/Content/Topics/Adv_Server_Access/docs/ad-user-manage.htm
- Note: Please ensure that "Create Users", "Update Attributes" and "Deactivate Users" are enabled on your OPA Application within Okta.
- Note: Remove any existing OPA AD Joined Attributes from the Okta User Profile. These will be created automatically for you.
- OPA Client - Enrolled into your OPA Team with your Demo User
- RoyalTSX
- Note: Open RoyalTSX, nagivate to Deafult Settings, right click on Remote Desktop and select Properties - Ensure 'TLS Encryption' is ticked.
- AWS Environment
- AWS Key Pair in the correct region (https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/create-key-pairs.html). This is only as a backup and will most likely never be required.
- Ensure you have space for 5 additional Elastic IPS and 3 VPCs
- Terraform CLI (https://learn.hashicorp.com/tutorials/terraform/install-cli)
- Ansible (https://formulae.brew.sh/formula/ansible) - For Domain Controller automation
- kubectl (https://kubernetes.io/docs/tasks/tools/) - For accessing EKS via CLI
- OpenLens (https://github.com/MuhammedKalkan/OpenLens/releases) - For accessing EKS via GUI

### Base Demo Deployment

Follow these steps to deploy standard OPA features.

- Download the code locally into an accessible folder
- Rename 'terraform.example' to terraform.tfvars
- Fill in all variables in 'terraform.tfvars'
- Open Terminal and change into the top level directory where the code resides. (Do not change into the Kubernetes directory)
- Run: `terraform init` - this will download and install all the required packages
- MacOS - Run: `export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES`
- Run: `terraform apply` 
- Note: This can take around 20 minutes to fully deploy, so please be patient.

After you have completed the above steps you will have a standard working OPA Demo where you will be able to demo;

- Agent Based Server Management and Authentication
- AD Joined User Authentication
- Preauthorization
- Gateway Traversal

In order to save costs, please ensure that this environment has been destroyed when not in use. The beauty of Terraform is that is can be creating very quickly again. To do this please run the following command:

- Run: `terraform destory`
- Note: After destruction please manually delete the opa-gateway from the Gateways menu as there is currently no API avaialble to manage this.

### Kubernetes Feature Deployment

Follow these steps in order to deploy only the Kubernetes features. 

- Open Terminal and change into the Kubernetes directory
- Rename 'terraform.example' to terraform.tfvars
- Fill in all variables in 'terraform.tfvars'
- Run: `terraform init` - this will download and install all the required packages
- Run: `terraform apply` 
- Note: This can take around 30 minutes to fully deploy, so please be patient. There is a known OIDC configuration delay with AWS which is being worked on .

After you have completed the above steps you will have a working Kubernetes environment where you will be able to demo;

- Listing Clusters within SFT CLI
- Connecting to Clusters using Kubectl using OPA for Authentication
- Show different levels of Authorization

In order to save costs, please ensure that this environment has been destroyed when not in use. The beauty of Terraform is that is can be creating very quickly again. To do this please run the following command: 

- Run: `terraform destory`


## Testing

### Agent Based Linux and Windows:

#### GUI Testing

- Log into Okta
- Open OPA Application
- Find 'opa-gateway' and click connect
- Find 'opa-linux-target' and click connect
- Create a preauthorization on the opa-windows project
- Find 'opa-windows-target' and click connect
- Click Connect when prompted

#### CLI Testing

- Open Terminal
- Type: `sft list-servers`
- Type: `sft ssh opa-gateway`
- Type: `sft ssh opa-linux-target`
- Type: `sft rdp opa-windows-target`

### AD Joined:

#### GUI Testing

- Log into Okta
- Open OPA Application
- Click Project
- Click opa-domain-joined
- Click Servers
- Click Connect against server
- From the drop down select svc-iis - This is a passwordless flow
- Click connect
- For a password flow, select the Administrator user and enter the password specified in your variables file

#### CLI Testing

Open Terminal
Type: `sft list-servers`
Type: `sft rdp <servername>` // Name of Domain Controller
Enter number that represents svc-iis - This is a passwordless flow
- For a password flow, select the Administrator number and enter the password specified in your variables file

### Kubernetes: 

- Open Terminal
- Type: sft k8s list-clusters
- Type: kubectl config get-contexts
- Type: kubectl config use-context xxx // xxx = name from previous command (eg: first.last@cluster-name.asa-team)
- Type: kubectl cluster-info

## What is Happening?

### Okta Configuration

- Create 4 new Okta groups
    - OPA Full Administrators
    - OPA System Administrators
    - OPA Devops
    - OPA Cloud Operations
- Assign your Okta Demo User to one of the groups
- Assign the groups to your OPA Application
- Create activeDirectoryIdentity Attribute
- Create activeDirectoryPasswordlessIdentity Attribute
- Assign Values to Attributes

- Push New Groups into OPA (Roadmap - Awaiting API)

### OPA Configuration

- Create Gateway Setup Token
- Create OPA-Gateway Project
- Create OPA-Gateway Enrollment Token
- Assign 'everyone' group to OPA-Gateway Project 
- Create OPA-Domain-Joined Project
- Assign 'everyone' group to OPA-Domain-Joined Project
- Create OPA-Linux Project
- Create OPA-Linux Enrollment Token
- Assign 'everyone' group to OPA-Linux Project
- Create OPA-Windows Project 
- Set Preauthorizations Required on OPA-Windows Project
- Create OPA-Windows Enrollment Token
- Assign 'everyone' group to OPA-Windows Project
- Create Kubernetes Clusters
- Set Connection Information on Kubernetes Clusters
- Create Kubernetes Cluster Groups

### AWS Configuration

- Look up latest images for Ubuntu and Windows
- Create OPA Demo Network (VPC, Internet Gateway, Routes, Subnets & Interfaces)
- Create OPA-Gateway Ubuntu Server
- Create OPA-Gateway Security Group
- Create OPA-Domain-Controller Windows Server
- Create OPA-Domain-Controller Security Group
- Automate Windows Services Installation;
    - DNS
    - ADCS
    - Domain Services
    - Certificate Exchange for OPA Domain Joined 
    - Configure example Domain User (svc-iis)
- Create OPA-Linux-Target Ubuntu Server
- Create OPA-Linux-Target Security Group
- Create OPA-Windows-Target Windows Server
- Create OPA-Windows-Target Security Group

### Kubernetes Configuration

- Create AWS EKS Networking (VPC, Internet Gateway, Routes, Subnets x 2 )
- Create Various IAM Roles to Connect to EKS
- Create Security Group to Allow Access to EKS Cluster
- Create 2x EKS Clusters (Prod and Dev)
- Configure OIDC Authenication against EKS Clusters
- Create EKS Cluster Node Groups
- Create Kubernetes Cluster Role
- Create Kubernetes Cluster Role Binding

## Troubleshooting

- If you get a python error during execution please run the following:

`export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES`

- If you get a timeout error relating to the EKS Cluster, please run `terraform apply` again
 
## Thanks

- Felix Colaci
- Sachin Saxena
- Jacob Jones
- Adam Drayer
- Stephen Bennett
- Joe Ranson
- Grey Thrasher
