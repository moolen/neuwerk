variable "neuwerk_vpc_ingress_subnet_cidr" {
  type = string
}

variable "neuwerk_vpc_egress_subnet_cidr" {
  type = string
}

variable "neuwerk_vpc_public_subnet_cidr" {
  type = string
}

variable "azs" {
  type = list(string)
}

variable "vpc_cidr" {
  type = string
}

variable "ssh_key_name" {
  type = string
}
