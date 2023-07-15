data "aws_ami" "amazon-linux" {
  owners      = ["amazon"]
  most_recent = true

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }

  filter {
    name   = "owner-alias"
    values = ["amazon"]
  }

  filter {
    name   = "name"
    values = ["amzn2-ami-kernel-5.10-hvm*"]
  }
}

resource "aws_instance" "test_box" {
  ami           = data.aws_ami.amazon-linux.id

  instance_type = "t2.micro"
  key_name      = local.ssh_key_name
  subnet_id     = var.mgmt_subnet_ids[0]
  vpc_security_group_ids = [aws_security_group.allow_ssh_icmp.id]
  associate_public_ip_address = false

  iam_instance_profile = module.asg.iam_instance_profile_id

  tags = {
    Name = "text_box"
  }

}

resource "aws_security_group" "allow_ssh_icmp" {
  name        = "test_box_allow_ssh_icmp"
  description = "Allow SSH and ALL ICMP IPV4 inbound traffic"
  vpc_id      = var.vpc_id

  ingress {
    description = "SSH from VPC"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  ingress {
    description = "yolo"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.vpc_cidr]
  }

  ingress {
    description = "ALL ICMP IPV4 from VPC"
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}