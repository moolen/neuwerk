terraform {
  required_version = ">= 0.13"
  required_providers {}
}

provider "aws" {
  region = "eu-central-1"

  default_tags {
    tags = {    }
  }
}
