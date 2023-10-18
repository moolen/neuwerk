resource "aws_vpc" "main" {
  cidr_block = var.vpc_cidr

  tags = {
    Name = "neuwerk-apps"
  }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.main.id

  tags = merge(
    { "Name" = "neuwerk" },
  )
}

