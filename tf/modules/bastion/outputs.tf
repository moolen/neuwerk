output "instance_public_ip" {
  value = aws_instance.bastion.public_ip
  description = "The public IP address of the bastion instance."
}

output "instance_private_ip" {
  value = aws_instance.bastion.private_ip
  description = "The private IP address of the bastion instance."
}