locals {
  apps_vpc_cidr            = "10.7.0.0/16"
  apps_vpc_public_subnets  = "10.7.0.0/24"
  apps_vpc_private_subnets = "10.7.1.0/24"
}

module "apps" {
  source = "./modules/apps"

  azs                 = local.azs
  vpc_id              = module.apps.vpc_id
  vpc_cidr            = local.apps_vpc_cidr
  private_subnet_cidr = local.apps_vpc_private_subnets
  public_subnet_cidr  = local.apps_vpc_public_subnets
  public_subnet_ids   = [module.apps.public_subnet_id]
  private_subnet_ids  = [module.apps.private_subnet_id]
  ssh_key_name        = local.ssh_key_name
}
