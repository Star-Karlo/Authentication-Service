locals {
  # The platform exports repository URLs; IAM needs the ARN. Deriving it here
  # avoids exporting both and keeps the platform's output surface small.
  ecr_repository_arn = "arn:aws:ecr:${var.region}:${data.aws_caller_identity.current.account_id}:repository/karlo/${var.service_name}"
}
