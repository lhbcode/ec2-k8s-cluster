provider "aws" {
  region     = var.region
}

locals {
  region            = var.lookup-region_abbr["${var.region}"]
  ami               = lookup(var.aws_amis, var.region)
  instance_type     = "t3.medium" #bastion instance type
  cidr              = "10.30.0.0/16"
  public_subnet     = ["10.30.1.0/24", "10.30.2.0/24"]
  private_subnet    = ["10.30.3.0/24", "10.30.4.0/24"]
  database_subnet   = ["10.30.5.0/24", "10.30.6.0/24"]
  private_key_name  = "private"
}


#################################################################################
## Random string                                                               ##
#################################################################################

# for iam role and frontend deploy tags
resource "random_string" "random" {
  length  = 4
  special = false
}


#################################################################################
## Keypair                                                                     ##
#################################################################################
resource "tls_private_key" "this" {
  algorithm = "RSA"
  rsa_bits  = 4096

  provisioner "local-exec" {
    command = <<EOF
    rm ./${local.private_key_name}-key.pem
    echo '${self.private_key_pem}' > ./${local.private_key_name}-key.pem
    chmod 400 ${local.private_key_name}-key.pem
    EOF
  }
}

module "keypair" {
  source = "./module/key"

  key_name   = "${var.project}-${var.environment}-${local.region}-key"
  public_key = tls_private_key.this.public_key_openssh
}

#################################################################################
## VPC                                                                         ##
#################################################################################

# for azs
data "aws_availability_zones" "azs" {
    state = "available"
}

# for vpc
module "vpc" {
  source = "./module/vpc"

  name = "${var.project}-${var.environment}-${local.region}-redis-vpc"
  cidr = local.cidr

  azs              = ["${data.aws_availability_zones.azs.names[0]}","${data.aws_availability_zones.azs.names[1]}"]
  public_subnets   = local.public_subnet
  private_subnets  = local.private_subnet
  database_subnets = local.database_subnet

  create_igw           = true
  enable_dhcp_options  = true
  enable_dns_support   = true
  enable_dns_hostnames = true
  enable_nat_gateway   = true
  single_nat_gateway   = true


   tags = {
    Project    = "${var.project}"
  }
}


#################################################################################
## IAM                                                                         ##
#################################################################################
# for master
resource "aws_iam_role" "master_role" {
  name               = "${var.project}-${var.environment}-master-${random_string.random.id}"
  path               = "/"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
   tags = {
    Project    = "${var.project}"
  }
}


resource "aws_iam_role_policy_attachment" "this_1" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.master_role.name
}

resource "aws_iam_instance_profile" "master_role" {
  name = "${var.project}-${var.environment}--${local.region}-master-${random_string.random.id}"
  role = aws_iam_role.master_role.name
}
##############################################
# for worker
resource "aws_iam_role" "worker_role" {
  name               = "${var.project}-${var.environment}-worker-${random_string.random.id}"
  path               = "/"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
   tags = {
    Project    = "${var.project}"
  }
}


resource "aws_iam_role_policy_attachment" "this_2" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.worker_role.name
}

resource "aws_iam_instance_profile" "worker_role" {
  name = "${var.project}-${var.environment}-${local.region}-worker-${random_string.random.id}"
  role = aws_iam_role.worker_role.name
}
#################################################################################
## Security Group                                                              ##
#################################################################################

# security groups
module "security_group_k8s_ec2" {
  source = "./module/security"

  name        = "${var.project}-${var.environment}-${local.region}-k8s-sg"
  description = "Security group for k8s usage with EC2 instance"
  vpc_id      = module.vpc.vpc_id

  ingress_cidr_blocks = ["0.0.0.0/0"]
  ingress_rules       = ["ssh-tcp" ]
  egress_rules        = ["http-80-tcp","https-443-tcp","ssh-tcp"]
  computed_ingress_with_source_security_group_id = [
    {
      rule                     = "all-all"
      source_security_group_id = module.security_group_k8s_ec2.security_group_id
      description = "access k8s"
    },
  ]
  number_of_computed_ingress_with_source_security_group_id = 1
  computed_egress_with_source_security_group_id = [
    {
      rule                     = "all-all"
      source_security_group_id = module.security_group_k8s_ec2.security_group_id
      description = "out k8s"
    },
  ]
  number_of_computed_egress_with_source_security_group_id = 1
   ingress_with_cidr_blocks = [
    {
      from_port   = 30000
      to_port     = 32767
      protocol    = "tcp"
      description = "NodePort"
      cidr_blocks = "0.0.0.0/0"
    },
  ]
   tags = {
    Project    = "${var.project}"

  }
}



#################################################################################
## EC2                                                                         ##
#################################################################################
# for master
module "ec2_k8s" {
  source = "./module/ec2"

  name           = "${var.project}-${var.environment}-${local.region}-master"
  ami            = local.ami[0]
  instance_type  = local.instance_type
  key_name   = module.keypair.key_pair_key_name
  monitoring = false

  vpc_security_group_ids = [module.security_group_k8s_ec2.security_group_id]
  iam_instance_profile = aws_iam_instance_profile.master_role.name

  subnet_id = module.vpc.public_subnets[0]

  root_block_device = [
    {
      volume_type = "gp2"
      volume_size = var.OsVolume
    },
  ]
   tags = {
     Project             = "${var.project}"
    "kubernetes.io/cluster/test" = "shared"
  }
}





# for worker1
module "ec2_k8s_worker1" {
  source = "./module/ec2"

  name           = "${var.project}-${var.environment}-${local.region}-worker1"
  ami            = local.ami[0]
  instance_type  = local.instance_type

  key_name   = module.keypair.key_pair_key_name
  monitoring = false
  iam_instance_profile = aws_iam_instance_profile.worker_role.name

  vpc_security_group_ids = [module.security_group_k8s_ec2.security_group_id]

  subnet_id = module.vpc.public_subnets[0]

  root_block_device = [
    {
      volume_type = "gp2"
      volume_size = var.OsVolume
    },
  ]
  tags = {
    Project             = "${var.project}"
    "kubernetes.io/cluster/test" = "shared"
 
    
  }
}


# for worker2
module "ec2_k8s_worker2" {
  source = "./module/ec2"

  name           = "${var.project}-${var.environment}-${local.region}-worker2"
  ami            = local.ami[0]
  instance_type  = local.instance_type
  key_name   = module.keypair.key_pair_key_name
  monitoring = false

  vpc_security_group_ids = [module.security_group_k8s_ec2.security_group_id]
  iam_instance_profile = aws_iam_instance_profile.worker_role.name

  subnet_id = module.vpc.public_subnets[0]

  root_block_device = [
    {
      volume_type = "gp2"
      volume_size = var.OsVolume
    },
  ]
  tags = {
    Project             = "${var.project}"
    "kubernetes.io/cluster/test" = "shared"
    
  }
}


#################################################################################
## shell                                                                       ##
#################################################################################
###### 
# for master1 
resource "null_resource" "install_1" {
  depends_on = [
    module.ec2_k8s,
    tls_private_key.this
  ]
  connection {
    user = "ubuntu"
    type = "ssh"
    host = module.ec2_k8s.public_ip
    private_key = file("./private-key.pem")
    timeout = "10m"
  }
  provisioner "remote-exec" {
    script = "./master_script.sh"
  }

  provisioner "file" {
    source      = "./private-key.pem"
    destination = "/tmp/private-key.pem"
  }

   provisioner "remote-exec" {
   inline = [
     "sudo apt-get install -y sshpass",
     "chmod 400 /tmp/private-key.pem",
     "sshpass scp -i /tmp/private-key.pem  -o StrictHostKeyChecking=no /tmp/join.yml ubuntu@${module.ec2_k8s_worker1.public_ip}:/tmp",
    "sshpass scp -i /tmp/private-key.pem  -o StrictHostKeyChecking=no /tmp/join.yml ubuntu@${module.ec2_k8s_worker2.public_ip}:/tmp",
   ]
  }

}

###### 
# for worker1
resource "null_resource" "install_2" {
  depends_on = [
    module.ec2_k8s_worker1,
    tls_private_key.this,
    null_resource.install_1

  ]
  connection {
    user = "ubuntu"
    type = "ssh"
    host = module.ec2_k8s_worker1.public_ip
    private_key = file("./private-key.pem")
    timeout = "10m"
  }
  provisioner "remote-exec" {
    script = "./worker_script.sh"
  }
}

###### 
# for worker2
resource "null_resource" "install_3" {
  depends_on = [
    module.ec2_k8s_worker2,
    tls_private_key.this,
    null_resource.install_1
  ]
  connection {
    user = "ubuntu"
    type = "ssh"
    host = module.ec2_k8s_worker2.public_ip
    private_key = file("./private-key.pem")
    timeout = "10m"
  }
  provisioner "remote-exec" {
    script = "./worker_script.sh"
  }
}

