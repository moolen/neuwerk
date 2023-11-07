output "bastion_ip" {
  value = module.bastion.instance_public_ip
}

output "vpc_id" {
  value = aws_vpc.main.id
}

output "ingress_subnet_id" {
  value = aws_subnet.ingress.id
}

output "egress_route_table_id" {
  value = aws_route_table.egress.id
}

output "ingress_route_table_id" {
  value = aws_route_table.ingress.id
}

output "public_route_table_id" {
  value = aws_route_table.public.id
}
output "testbox_ip_internal" {
  value = module.testbox.ip
}
