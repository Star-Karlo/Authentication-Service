variable "region" {
  type    = string
  default = "ap-southeast-3"
}

variable "environment" {
  type = string

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be dev, staging or prod."
  }
}

variable "github_branch" {
  description = "The branch the pipeline deploys from."
  type        = string
  default     = "main"
}

# --- Task sizing ------------------------------------------------------------
# Fargate bills per vCPU-second and GB-second, so these are the two numbers that
# decide the compute bill. The defaults are deliberately small: see
# ../../docs/COST.md for what each step up costs.

variable "task_cpu" {
  description = "Fargate CPU units. 256 = 0.25 vCPU."
  type        = number
  default     = 256
}

variable "task_memory" {
  description = "Fargate memory in MiB. Must be a valid pairing with task_cpu."
  type        = number
  default     = 512
}

variable "desired_count" {
  description = <<-EOT
    Baseline task count.

    One is the deliberate starting position. Deploys are still safe — the
    rolling policy starts the replacement before stopping the old task — but a
    crash or an AZ failure means downtime until ECS reschedules, roughly 30 to
    60 seconds. Move to two when that becomes unacceptable, not before.
  EOT
  type        = number
  default     = 1
}

variable "min_capacity" {
  type    = number
  default = 1
}

variable "tasks_in_public_subnets" {
  description = "Must match the platform's setting of the same name."
  type        = bool
  default     = false
}

variable "max_capacity" {
  type    = number
  default = 4
}

variable "log_retention_days" {
  description = <<-EOT
    CloudWatch retention.

    Seven days, not thirty. Logs are also forwarded to Fluentd, so this is the
    fallback copy used for debugging something that just happened — and a week
    covers that. Anything needing a longer history belongs in the Fluentd
    destination, where storage is far cheaper than CloudWatch's per-GB rate.
  EOT
  type        = number
  default     = 7
}

# --- Service identity -------------------------------------------------------
# Fixed per service; declared as variables so the module reads the same in every
# repository and only these values differ.

variable "service_name" {
  type    = string
  default = "authentication-service"
}

variable "github_repository" {
  type    = string
  default = "Star-Karlo/Authentication-Service"
}

variable "http_port" {
  type    = number
  default = 5001
}

variable "grpc_port" {
  type    = number
  default = 6001
}

variable "discovery_name" {
  description = "The Cloud Map name other services dial, as <name>.karlo.internal."
  type        = string
  default     = "authentication"
}

variable "listener_priority" {
  description = <<-EOT
    ALB rule priority. Must be unique across all four services, since they share
    one listener. Allocated in hundreds so a rule can be inserted between two
    without renumbering: auth 100, masterdata 200, business 300,
    notification 400.
  EOT
  type        = number
  default     = 100
}

variable "path_patterns" {
  description = "The paths this service claims on the shared load balancer."
  # These must match the Vite dev proxy in karlo_platform/vite.config.ts. A path
  # present in only one of the two works locally and 404s behind the load
  # balancer, or the reverse — and neither failure appears until the environment
  # the path is missing from is exercised.
  type        = list(string)
  default     = ["/api/v1/auth/*", "/api/v1/users/*", "/api/v1/admin/*", "/api/v1/shippers/*", "/api/v1/permissions/*", "/api/v1/roles/*"]
}

variable "cors_allowed_origins" {
  description = "Required. There is no wildcard default on a credentialed API."
  type        = list(string)
}

variable "fluentd_host" {
  description = "Log collector. Empty disables forwarding; stdout is unaffected."
  type        = string
  default     = ""
}

variable "extra_environment" {
  description = "Service-specific environment, added to the common set."
  type        = list(object({ name = string, value = string }))
  default     = []
}


