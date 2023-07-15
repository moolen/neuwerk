locals {
  ssh_key_name              = "neuwerk-ssh-key"
  vip                       = cidrsubnet(var.mgmt_subnet_cidrs[0], 8, 133)
}

module "bastion" {
  source                = "./bastion"
  vpc_id                = var.vpc_id
  subnet_id             = var.bastion_subnet_ids[0]
  ssh_key_name          = local.ssh_key_name
  bastion_instance_type = "t2.micro"
  cidr_block            = "0.0.0.0/0"
  bastion_name          = "neuwerk-bastion"
}

module "leader-election" {
  source = "./leader-election"

  name            = "neuwerk-asg-leader-election"
  asg_name_prefix = "neuwerk"
}

resource "aws_ec2_subnet_cidr_reservation" "neuwerk_vip" {
  cidr_block       = local.vip
  reservation_type = "explicit"
  subnet_id        = var.mgmt_subnet_ids[0]
}


module "asg" {
  source  = "terraform-aws-modules/autoscaling/aws"
  version = "~> 6.10"


  name = "neuwerk"

  min_size            = 1
  max_size            = 3
  desired_capacity    = 3
  health_check_type   = "EC2"
  vpc_zone_identifier = var.mgmt_subnet_ids

  # Launch template
  launch_template_name        = "neuwerk-asg"
  launch_template_description = "Neuwerk launch template"
  update_default_version      = true

  # user_data = <<EOF
  #     #cloud-config
  #     runcmd:
  #         - sed -i s/127.0.0.53/10.0.0.2/g /etc/resolv.conf
  #         - systemctl stop systemd-resolved
  # EOF

  image_id      = data.aws_ami.ubuntu.id
  instance_type = "t3.medium"
  key_name      = local.ssh_key_name

  # IAM role & instance profile
  create_iam_instance_profile = true
  iam_role_name               = "neuwerk-instance-profile"
  iam_role_description        = "IAM instance profile for neuwerk"

  iam_role_policies = {
    neuwerk = aws_iam_policy.neuwerk-instance-profile.arn
  }

  metadata_options = {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    instance_metadata_tags      = "enabled"
    http_put_response_hop_limit = 32
  }

  security_groups = [aws_security_group.neuwerk-identity.id]

  network_interfaces = [
    {
      # management interface
      delete_on_termination = true
      description           = "management"
      device_index          = 0
      security_groups       = [aws_security_group.neuwerk_mgmt.id]
    },
    {
      # traffic interface
      delete_on_termination = true
      description           = "ingress"
      device_index          = 1
      security_groups       = [aws_security_group.neuwerk_ingress.id]
    }
  ]
  tag_specifications = [
    {
      resource_type = "instance"
      tags          = { "neuwerk:vip" = local.vip }
    }
  ]
}

resource "aws_key_pair" "neuwerk-key" {
  key_name   = local.ssh_key_name
  public_key = var.ssh_pubkey
}


data "aws_ami" "ubuntu" {
  most_recent = true

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-lunar-23.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = ["099720109477"] # Canonical
}


resource "aws_security_group" "neuwerk-identity" {
  name        = "neuwerk-identity"
  description = "Neuwerk instance identity"
  vpc_id      = var.vpc_id
}

resource "aws_security_group" "neuwerk_mgmt" {
  name        = "neuwerk_mgmt"
  description = "Neuwerk management traffic"
  vpc_id      = var.vpc_id

  ingress {
    description = "redis DB port"
    from_port   = 3320
    to_port     = 3320
    protocol    = "tcp"
    # security_groups = [aws_security_group.neuwerk-identity.id]
    cidr_blocks = [var.vpc_cidr] # TODO
  }

  ingress {
    description = "redis DB port"
    from_port   = 3320
    to_port     = 3320
    protocol    = "udp"
    # security_groups = [aws_security_group.neuwerk-identity.id]
    cidr_blocks = [var.vpc_cidr] # TODO
  }

  ingress {
    description = "cluster port"
    from_port   = 3322
    to_port     = 3322
    protocol    = "tcp"
    # security_groups = [aws_security_group.neuwerk-identity.id]
    cidr_blocks = [var.vpc_cidr] # TODO
  }

  ingress {
    description = "dns tcp port"
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  ingress {
    description = "dns udp port"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = [var.vpc_cidr]
  }

  ingress {
    description = "icmp"
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = [var.vpc_cidr]
  }

  ingress {
    description = "ssh port"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
}

resource "aws_security_group" "neuwerk_ingress" {
  name        = "neuwerk_ingress"
  description = "Neuwerk ingress traffic"
  vpc_id      = var.vpc_id

  ingress {
    description = "traffic to filter"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
}


resource "aws_iam_role" "neuwerk-instance" {
  name = "neuwerk-instance"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_policy" "neuwerk-instance-profile" {
  name = "neuwerk-instance-profile"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "autoscaling:*",
        "ec2:*",
        "autoscaling:DescribeAutoScalingInstances",
        "autoscaling:DescribeAutoScalingGroups",
        "ec2:DescribeTags",
        "ec2:CreateTags",
        "ec2:DescribeInstances",
        "ec2:ModifyInstanceAttribute",
        "ec2:DescribeAddresses",
        "ec2:AllocateAddress",
        "ec2:ReleaseAddress",
        "ec2:DescribeInstances",
        "ec2:AssociateAddress",
        "ec2:DisassociateAddress",
        "ec2:DescribeNetworkInterfaces",
        "ec2:AssignPrivateIpAddresses",
        "ec2:UnassignPrivateIpAddresses"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}
