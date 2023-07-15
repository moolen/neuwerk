
locals {
  region = "eu-central-1"
}

module "neuwerk" {
  source = "./modules/neuwerk"

  vpc_id               = module.vpc.vpc_id
  vpc_cidr             = module.vpc.vpc_cidr_block
  ssh_pubkey           = var.ssh_pubkey
  bastion_subnet_ids   = module.vpc.public_subnets
  mgmt_subnet_ids      = module.vpc.private_subnets
  mgmt_subnet_cidrs    = module.vpc.private_subnets_cidr_blocks
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.1"

  name = "neuwerk"
  cidr = "10.0.0.0/16"

  azs = ["${local.region}a"]

  # neuwerk runs in the public subnet
  public_subnets  = ["10.0.5.0/24"]
  private_subnets = ["10.0.7.0/24"]


  enable_nat_gateway   = true
  single_nat_gateway   = true
  enable_dns_hostnames = true

  enable_flow_log                      = false
  create_flow_log_cloudwatch_iam_role  = false
  create_flow_log_cloudwatch_log_group = false
}
