
module "bastion" {
  source                = "../bastion"
  vpc_id                = var.vpc_id
  subnet_id             = var.public_subnet_ids[0]
  ssh_key_name          = var.ssh_key_name
  bastion_instance_type = "t2.micro"
  cidr_block            = "0.0.0.0/0"
  bastion_name          = "apps-bastion"
}
