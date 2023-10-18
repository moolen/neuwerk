module "testbox" {
  source = "../testbox"

  name         = "apps-testbox"
  vpc_id       = var.vpc_id
  vpc_cidr     = var.vpc_cidr
  ssh_key_name = var.ssh_key_name
  subnet_id    = var.private_subnet_ids[0]
}
