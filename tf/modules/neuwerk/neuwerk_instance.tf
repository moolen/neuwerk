resource "aws_instance" "neuwerk" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.medium"
  key_name      = var.ssh_key_name

  iam_instance_profile = aws_iam_instance_profile.this.id

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    instance_metadata_tags      = "enabled"
    http_put_response_hop_limit = 32
  }

  network_interface {
    device_index         = 0
    network_interface_id = aws_network_interface.egress.id
  }

  network_interface {
    device_index         = 1
    network_interface_id = aws_network_interface.ingress.id
  }

  network_interface {
    device_index         = 2
    network_interface_id = aws_network_interface.mgmt.id
  }

  tags = {
    "Name"            = "neuwerk"
    "neuwerk:cluster" = "default"
    "neuwker:leader"  = "true"
  }
}

resource "aws_network_interface" "egress" {
  subnet_id         = aws_subnet.egress.id
  description       = "egress"
  source_dest_check = false
  security_groups   = [aws_security_group.neuwerk_ingress_egress.id]
}


resource "aws_network_interface" "ingress" {
  subnet_id         = aws_subnet.ingress.id
  description       = "ingress"
  source_dest_check = false
  security_groups   = [aws_security_group.neuwerk_ingress_egress.id]
}

resource "aws_network_interface" "mgmt" {
  subnet_id         = aws_subnet.egress.id
  description       = "management"
  source_dest_check = false
  security_groups   = [aws_security_group.neuwerk_ingress_egress.id]
}


data "aws_partition" "current" {}

data "aws_iam_policy_document" "assume_role_policy" {
  statement {
    sid     = "EC2AssumeRole"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.${data.aws_partition.current.dns_suffix}"]
    }
  }
}


resource "aws_iam_role" "this" {
  name        = "neuwerk-instance-profile"
  description = "instance profile for neuwerk EC2 instances"

  assume_role_policy    = data.aws_iam_policy_document.assume_role_policy.json
  force_detach_policies = true
}

resource "aws_iam_role_policy_attachment" "neuwerk_policy_attachment" {
  policy_arn = aws_iam_policy.neuwerk-instance-profile.arn
  role       = aws_iam_role.this.name
}


resource "aws_iam_instance_profile" "this" {
  role = aws_iam_role.this.name
  name = "neuwerk-instance-profile"
}
