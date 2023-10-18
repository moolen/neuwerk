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
  vpc_id      = aws_vpc.main.id
}

resource "aws_security_group" "neuwerk_mgmt" {
  name        = "neuwerk_mgmt"
  description = "Neuwerk management traffic"
  vpc_id      = aws_vpc.main.id

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
    description = "cluster port"
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    # security_groups = [aws_security_group.neuwerk-identity.id]
    cidr_blocks = [var.vpc_cidr] # TODO
  }

  ingress {
    description = "dns tcp port"
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "dns udp port"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "icmp"
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = ["0.0.0.0/0"]
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

resource "aws_security_group" "neuwerk_ingress_egress" {
  name        = "neuwerk_ingress_egress"
  description = "Neuwerk ingress traffic"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "traffic to filter"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
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
