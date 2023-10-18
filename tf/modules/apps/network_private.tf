resource "aws_subnet" "private" {
  availability_zone = var.azs[0]
  cidr_block        = var.private_subnet_cidr
  vpc_id            = aws_vpc.main.id

  tags = merge(
    {
      Name = "neuwerk-apps-private"
    },
  )
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  tags = merge(
    {
      "Name" = "neuwerk-apps-private"
    },
  )
}

resource "aws_route_table_association" "private" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private.id
}

# default route points towards tgw
# which is created in the root module
# resource "aws_route" "private_to_nat" {
#   route_table_id         = aws_route_table.private.id
#   destination_cidr_block = "0.0.0.0/0"
#   nat_gateway_id         = aws_nat_gateway.this.id
# }
