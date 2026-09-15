# Cold storage, on a timer: the audit log to Parquet in S3, dead sessions
# purged. Same mechanism as the business service (EventBridge Scheduler
# starting a one-off task from this service's own image and secrets);
# see internal/archive for what a run does.

# The task role's only AWS permission: write archive files under this
# service's own prefix in the platform's uploads bucket. Put only — the
# archiver never reads back, lists, or deletes objects.
data "aws_iam_policy_document" "task_archive" {
  statement {
    actions   = ["s3:PutObject"]
    resources = ["${local.platform.uploads_bucket_arn}/archive/auth/*"]
  }
}

resource "aws_iam_role_policy" "task_archive" {
  name   = "${local.name}-archive"
  role   = aws_iam_role.task.id
  policy = data.aws_iam_policy_document.task_archive.json
}

variable "archive_schedule" {
  description = "When the archiver runs. Cron in the schedule's own timezone; 02:30 Jakarta, after the business service's run."
  type        = string
  default     = "cron(30 2 * * ? *)"
}

variable "archive_enabled" {
  type    = bool
  default = true
}

data "aws_iam_policy_document" "scheduler_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["scheduler.amazonaws.com"]
    }
    # Only schedules in this account may assume it.
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_iam_role" "archive_scheduler" {
  name               = "${local.name}-archive-scheduler"
  assume_role_policy = data.aws_iam_policy_document.scheduler_assume.json
}

data "aws_iam_policy_document" "archive_scheduler" {
  # Run this family and nothing else. The revision wildcard is what lets the
  # schedule follow deploys.
  statement {
    actions   = ["ecs:RunTask"]
    resources = ["${replace(aws_ecs_task_definition.main.arn, "/:\\d+$/", "")}:*"]
    condition {
      test     = "ArnEquals"
      variable = "ecs:cluster"
      values   = [local.platform.ecs_cluster_arn]
    }
  }
  # The task runs under the service's roles; the scheduler has to be allowed
  # to hand them over.
  statement {
    actions   = ["iam:PassRole"]
    resources = [aws_iam_role.task_execution.arn, aws_iam_role.task.arn]
    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "archive_scheduler" {
  name   = "${local.name}-archive-scheduler"
  role   = aws_iam_role.archive_scheduler.id
  policy = data.aws_iam_policy_document.archive_scheduler.json
}

resource "aws_scheduler_schedule" "archive" {
  count = var.archive_enabled ? 1 : 0

  name        = "${local.name}-archive"
  description = "Nightly cold-storage run: server archive (audit log to Parquet, dead sessions purged)"

  schedule_expression          = var.archive_schedule
  schedule_expression_timezone = "Asia/Jakarta"

  flexible_time_window {
    mode = "OFF"
  }

  target {
    arn      = local.platform.ecs_cluster_arn
    role_arn = aws_iam_role.archive_scheduler.arn

    ecs_parameters {
      # Family only: resolves to the latest ACTIVE revision at run time.
      task_definition_arn = replace(aws_ecs_task_definition.main.arn, "/:\\d+$/", "")
      launch_type         = "FARGATE"
      task_count          = 1

      network_configuration {
        subnets          = local.platform.tasks_in_public_subnets ? local.platform.public_subnet_ids : local.platform.private_subnet_ids
        security_groups  = [local.platform.tasks_security_group_id]
        assign_public_ip = local.platform.tasks_in_public_subnets
      }
    }

    # ECS appends the override to the image's ENTRYPOINT, which is the
    # binary, so this is ["archive"] and not ["server", "archive"].
    input = jsonencode({
      containerOverrides = [{
        name    = var.service_name
        command = ["archive"]
      }]
    })

    retry_policy {
      maximum_retry_attempts       = 2
      maximum_event_age_in_seconds = 3600
    }
  }
}

data "aws_caller_identity" "current" {}

# --- Did last night's run happen? -------------------------------------------
#
# A scheduled task that fails to launch, or launches and dies, leaves nothing
# but a missing log line. The archiver ends every successful run with
# "archive run finished"; this counts those and alarms when two days pass
# without one. A run that fails partway logs errors and exits non-zero
# without that line, so it counts as missing too.
resource "aws_cloudwatch_log_metric_filter" "archive_finished" {
  count = var.archive_enabled ? 1 : 0

  name           = "${local.name}-archive-finished"
  log_group_name = aws_cloudwatch_log_group.service.name
  pattern        = "\"archive run finished\""

  metric_transformation {
    name      = "ArchiveRunsFinished"
    namespace = "Karlo/${local.name}"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "archive_missed" {
  count = var.archive_enabled ? 1 : 0

  alarm_name          = "${local.name}-archive-missed"
  alarm_description   = "No completed cold-storage run in the last two days"
  namespace           = "Karlo/${local.name}"
  metric_name         = "ArchiveRunsFinished"
  statistic           = "Sum"
  period              = 86400
  evaluation_periods  = 2
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  # No data means no run, which is exactly the condition to report.
  treat_missing_data = "breaching"

  alarm_actions = local.alarm_actions
  ok_actions    = local.alarm_actions
}
