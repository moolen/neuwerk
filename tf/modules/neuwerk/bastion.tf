module "bastion" {
  source                = "../bastion"
  vpc_id                = aws_vpc.main.id
  subnet_id             = aws_subnet.public.id
  ssh_key_name          = var.ssh_key_name
  bastion_instance_type = "t2.micro"
  cidr_block            = "0.0.0.0/0"
  bastion_name          = "neuwerk-bastion"
}
