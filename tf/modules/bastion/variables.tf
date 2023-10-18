variable "bastion_name" {
  type        = string
  default     = "Bastion-Host"
  description = "The name of the Bastion Host"
}

variable "bastion_instance_type" {
  type        = string
  default     = "t2.micro"
  description = "The instance type of the Bastion Host"
}

variable "subnet_id" {
  type        = string
  description = "The ID of the subnet where the Bastion Host will be deployed"
}

variable "ssh_key_name" {
  type        = string
  description = "The name of the SSH key to use for the Bastion Host"
}

variable "cidr_block" {
  type        = string
  default     = "0.0.0.0/0"
  description = "The IPv4 CIDR block for the Security Group."
}

variable "vpc_id" {
  type        = string
  description = "The ID of the VPC"
}
