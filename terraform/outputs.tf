output "service_name" {
  value = aws_ecs_service.main.name
}

output "task_definition_arn" {
  value = aws_ecs_task_definition.main.arn
}

output "target_group_arn" {
  value = aws_lb_target_group.main.arn
}

output "pipeline_name" {
  value = aws_codepipeline.main.name
}

output "log_group" {
  value = aws_cloudwatch_log_group.service.name
}

output "discovery_endpoint" {
  description = "What other services dial for gRPC."
  value       = "${var.discovery_name}.karlo.internal:${var.grpc_port}"
}
