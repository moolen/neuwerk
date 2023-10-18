resource "aws_subnet" "egress" {
  availability_zone = var.azs[0]
  cidr_block        = var.neuwerk_vpc_egress_subnet_cidr
  vpc_id            = aws_vpc.main.id

  tags = merge(
    {
      Name = "neuwerk-egress"
      "neuwerk:cluster" : "default"
    },
  )
}

resource "aws_route_table" "egress" {
  vpc_id = aws_vpc.main.id

  tags = merge(
    {
      "Name" = "neuwerk-egress"
      "neuwerk:cluster" : "default"
    },
  )
}

resource "aws_route_table_association" "egress" {
  subnet_id      = aws_subnet.egress.id
  route_table_id = aws_route_table.egress.id
}

resource "aws_route" "egress_to_nat" {
  route_table_id         = aws_route_table.egress.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.this.id
}
