output "bastion_ip" {
    value = module.bastion.instance_public_ip
}

output "test_box_ip" {
    value = aws_instance.test_box.private_ip
}

output "neuwerk_vip" {
    value = local.vip
}