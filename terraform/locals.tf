locals {

  # Secrets, resolved from the platform's remote state.
  #
  # These used to be pasted into prod.tfvars as ARNs, copied by hand from a
  # `terraform output`. Every service would ship with the placeholders still
  # in the file at least once — IAM refuses "SECRET_RDS" as a resource, and the
  # apply dies on the first policy. The platform already exports the ARNs and
  # this module already reads that state, so there is nothing to copy.
  #
  # A ":key::" suffix selects one field of a JSON secret; a bare ARN is the
  # whole value, for the secrets stored as plain strings.
  secrets = [
    { name = "DB_HOST", valueFrom = "${local.platform.secret_arns.rds_master}:host::" },
    { name = "DB_USER", valueFrom = "${local.platform.secret_arns.rds_master}:username::" },
    { name = "DB_PASSWORD", valueFrom = "${local.platform.secret_arns.rds_master}:password::" },
    { name = "JWT_PRIVATE_KEY", valueFrom = local.platform.secret_arns.jwt_private },
    { name = "JWT_PUBLIC_KEY", valueFrom = local.platform.secret_arns.jwt_public },
    { name = "SERVICE_TOKEN", valueFrom = "${local.platform.secret_arns.service_tokens}:authentication-service::" },
    { name = "ACCEPTED_SERVICE_TOKENS", valueFrom = "${local.platform.secret_arns.service_tokens}:all::" },
  ]

  secret_arns = [
    local.platform.secret_arns.rds_master,
    local.platform.secret_arns.jwt_private,
    local.platform.secret_arns.jwt_public,
    local.platform.secret_arns.service_tokens,
  ]
}
