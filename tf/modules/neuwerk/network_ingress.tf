resource "aws_subnet" "ingress" {
  availability_zone = var.azs[0]
  cidr_block        = var.neuwerk_vpc_ingress_subnet_cidr
  vpc_id            = aws_vpc.main.id

  tags = merge(
    {
      Name = "neuwerk-ingress"
      "neuwerk:cluster" : "default"
    },
  )
}

resource "aws_route_table" "ingress" {
  vpc_id = aws_vpc.main.id

  tags = merge(
    {
      "Name" = "neuwerk-ingress"
      "neuwerk:cluster" : "default"
    },
  )
}

resource "aws_route_table_association" "ingress" {
  subnet_id      = aws_subnet.ingress.id
  route_table_id = aws_route_table.ingress.id
}
