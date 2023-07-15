variable "vpc_id" {
    type = string
}

variable "vpc_cidr" {
    type = string
}

variable "ssh_pubkey" {
    type = string
}

variable "bastion_subnet_ids" {
    type = list(string)
}

variable "mgmt_subnet_ids" {
    type = list(string)
}

variable "mgmt_subnet_cidrs" {
    type = list(string)
}
