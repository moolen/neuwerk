
locals {
  region       = "eu-central-1"
  ssh_key_name = "neuwerk-ssh-key"

  azs                 = ["${local.region}a"]
  neuwerk_vpc_cidr            = "10.0.0.0/16"
}

resource "aws_key_pair" "neuwerk-key" {
  key_name   = local.ssh_key_name
  public_key = var.ssh_pubkey
}

module "neuwerk" {
  source = "./modules/neuwerk"

  azs                             = local.azs
  vpc_cidr                        = local.neuwerk_vpc_cidr
  neuwerk_vpc_public_subnet_cidr  = "10.0.0.0/24"
  neuwerk_vpc_egress_subnet_cidr  = "10.0.50.0/24"
  neuwerk_vpc_ingress_subnet_cidr = "10.0.100.0/24"
  ssh_key_name                    = local.ssh_key_name
}

module "tgw" {
  source  = "terraform-aws-modules/transit-gateway/aws"
  version = "~> 2.0"

  name        = "neuwerk-tgw"
  description = "TGW that connects VPCs"

  share_tgw                             = false
  enable_auto_accept_shared_attachments = true
  ram_allow_external_principals         = false
  ram_principals                        = []

  vpc_attachments = {
    neuwerk = {
      vpc_id       = module.neuwerk.vpc_id
      subnet_ids   = [module.neuwerk.ingress_subnet_id]
      dns_support  = true
      ipv6_support = false

      tgw_routes = [
        {
          destination_cidr_block = local.apps_vpc_cidr
        },
        {
          destination_cidr_block = "0.0.0.0/0"
        }
      ]
    }
    apps = {
      vpc_id       = module.apps.vpc_id
      subnet_ids   = [module.apps.private_subnet_id]
      dns_support  = true
      ipv6_support = false

      tgw_routes = [
        {
          destination_cidr_block = local.neuwerk_vpc_cidr
        }
      ]
    }
  }
}

resource "aws_route" "tgw_neuwerk_egress_to_apps" {
  route_table_id         = module.neuwerk.egress_route_table_id
  destination_cidr_block = local.apps_vpc_cidr
  transit_gateway_id     = module.tgw.ec2_transit_gateway_id
}

resource "aws_route" "tgw_neuwerk_ingress_to_apps" {
  route_table_id         = module.neuwerk.ingress_route_table_id
  destination_cidr_block = local.apps_vpc_cidr
  transit_gateway_id     = module.tgw.ec2_transit_gateway_id
}

resource "aws_route" "tgw_neuwerk_public_to_apps" {
  route_table_id         = module.neuwerk.public_route_table_id
  destination_cidr_block = local.apps_vpc_cidr
  transit_gateway_id     = module.tgw.ec2_transit_gateway_id
}

resource "aws_route" "tgw_apps" {
  route_table_id         = module.apps.private_route_table_id
  destination_cidr_block = local.neuwerk_vpc_cidr
  transit_gateway_id     = module.tgw.ec2_transit_gateway_id
}

resource "aws_route" "apps_default_to_tgw" {
  route_table_id         = module.apps.private_route_table_id
  destination_cidr_block = "0.0.0.0/0"
  transit_gateway_id     = module.tgw.ec2_transit_gateway_id
}
