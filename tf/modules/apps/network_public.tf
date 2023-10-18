resource "aws_subnet" "public" {
  availability_zone = var.azs[0]
  cidr_block        = var.public_subnet_cidr
  vpc_id            = aws_vpc.main.id

  tags = merge(
    {
      Name = "neuwerk-apps-public"
    },
  )
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  tags = merge(
    {
      "Name" = "neuwerk-apps-public"
    },
  )
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route" "public_to_nat" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id = aws_internet_gateway.this.id
}


resource "aws_eip" "nat" {
  domain = "vpc"
  tags = merge(
    {
      "Name" = "neuwerk-nat"
    },
  )
}

resource "aws_nat_gateway" "this" {
  allocation_id = aws_eip.nat.allocation_id
  subnet_id     = aws_subnet.public.id

  tags = merge(
    {
      "Name" = "neuwerk-apps-public"
    },
  )
}
