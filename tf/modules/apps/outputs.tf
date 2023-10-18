output "test_box_ip" {
  value = module.testbox.ip
}

output "bastion_ip" {
  value = module.bastion.instance_public_ip
}

output "vpc_id" {
  value = aws_vpc.main.id
}

output "private_subnet_id" {
  value = aws_subnet.private.id
}

output "public_subnet_id" {
  value = aws_subnet.public.id
}

output "private_route_table_id" {
  value = aws_route_table.private.id
}
