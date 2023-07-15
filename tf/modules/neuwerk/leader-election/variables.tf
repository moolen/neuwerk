variable "name" {
  description = "A unique name for the infra"
  type        = string
  default     = "asg-leader-election"
}

variable "asg_name_prefix" {
  description = "The prefix of the autoscaling group name"
  type        = string
  default     = "awseb-"
}