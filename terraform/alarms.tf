# This service's own alarms, published to the platform's topic. A platform
# state applied before the topic existed yields no actions: the alarm still
# shows in the console, it just tells nobody.

locals {
  alarm_actions = compact([try(local.platform.alerts_topic_arn, "")])
}

# The load balancer sees no healthy target. This is the alarm that fires when
# a deploy rolls out a build that will not start, or every task is stuck.
resource "aws_cloudwatch_metric_alarm" "no_healthy_hosts" {
  alarm_name          = "${local.name}-no-healthy-hosts"
  alarm_description   = "No healthy task behind the load balancer for two minutes"
  namespace           = "AWS/ApplicationELB"
  metric_name         = "HealthyHostCount"
  statistic           = "Minimum"
  period              = 60
  evaluation_periods  = 2
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"

  dimensions = {
    LoadBalancer = local.platform.alb_arn_suffix
    TargetGroup  = aws_lb_target_group.main.arn_suffix
  }

  alarm_actions = local.alarm_actions
  ok_actions    = local.alarm_actions
}

# The service itself answering 5xx: a panic recovered by the middleware, a
# database that stopped answering, a downstream gRPC call that failed.
resource "aws_cloudwatch_metric_alarm" "target_5xx" {
  alarm_name          = "${local.name}-5xx"
  alarm_description   = "More than 20 5xx responses from the service in five minutes"
  namespace           = "AWS/ApplicationELB"
  metric_name         = "HTTPCode_Target_5XX_Count"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 20
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  dimensions = {
    LoadBalancer = local.platform.alb_arn_suffix
    TargetGroup  = aws_lb_target_group.main.arn_suffix
  }

  alarm_actions = local.alarm_actions
  ok_actions    = local.alarm_actions
}

# Sustained CPU at the top of the autoscaling range means the ceiling is too
# low, not that scaling is broken — scaling handles the middle on its own.
resource "aws_cloudwatch_metric_alarm" "cpu_high" {
  alarm_name          = "${local.name}-cpu-high"
  alarm_description   = "Service CPU above 85% for fifteen minutes"
  namespace           = "AWS/ECS"
  metric_name         = "CPUUtilization"
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 3
  threshold           = 85
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  dimensions = {
    ClusterName = local.platform.ecs_cluster_name
    ServiceName = aws_ecs_service.main.name
  }

  alarm_actions = local.alarm_actions
  ok_actions    = local.alarm_actions
}
