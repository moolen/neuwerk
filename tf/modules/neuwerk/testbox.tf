module "testbox" {
  source = "../testbox"

  name         = "neuwerk-testbox"
  vpc_id       = aws_vpc.main.id
  vpc_cidr     = var.vpc_cidr
  ssh_key_name = var.ssh_key_name
  subnet_id    = aws_subnet.egress.id
}
