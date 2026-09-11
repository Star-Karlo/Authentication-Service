terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.40"
    }
  }

  # Remote state per service, so each repo deploys independently and two people
  # cannot apply the same service at once. The key is namespaced by service and
  # environment; the bucket and lock table are created by platform-terraform.
  backend "s3" {
    bucket         = "karlo-terraform-state-057114645059"
    key            = "authentication-service/terraform.tfstate"
    region         = "ap-southeast-3"
    dynamodb_table = "karlo-terraform-locks"
    encrypt        = true
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project     = "karlo-tms"
      Service     = "authentication-service"
      Environment = var.environment
      ManagedBy   = "terraform"
      Repo        = "Star-Karlo/Authentication-Service"
    }
  }
}

# The shared platform: VPC, cluster, ALB, databases, secrets. Applied
# separately, before this. Read rather than duplicated — four VPCs would cost
# four NAT gateways for no benefit.
data "terraform_remote_state" "platform" {
  backend = "s3"

  config = {
    bucket = "karlo-terraform-state-057114645059"
    key    = "platform/terraform.tfstate"
    region = var.region
  }
}

locals {
  platform = data.terraform_remote_state.platform.outputs
  name     = "karlo-${var.environment}-auth"
}
