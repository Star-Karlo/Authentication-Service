# The Fargate service: task definition, ECS service, autoscaling, ALB routing
# and service discovery.

resource "aws_cloudwatch_log_group" "service" {
  name              = "/ecs/${local.name}"
  retention_in_days = var.log_retention_days
  tags              = { Name = local.name }
}

resource "aws_ecs_task_definition" "main" {
  family                   = local.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.task_cpu
  memory                   = var.task_memory

  # Two roles, deliberately. The execution role is used by the ECS agent to pull
  # the image and read secrets at start; the task role is what the running code
  # itself can do. Merging them would give the application the ability to read
  # every secret the agent can.
  execution_role_arn = aws_iam_role.task_execution.arn
  task_role_arn      = aws_iam_role.task.arn

  container_definitions = jsonencode([
    {
      name      = var.service_name
      image     = "${local.platform.ecr_repository_urls[var.service_name]}:bootstrap"
      essential = true

      portMappings = [
        { containerPort = var.http_port, protocol = "tcp" },
        { containerPort = var.grpc_port, protocol = "tcp" },
      ]

      environment = concat(
        [
          { name = "ENVIRONMENT", value = var.environment },
          { name = "HTTP_PORT", value = tostring(var.http_port) },
          { name = "GRPC_PORT", value = tostring(var.grpc_port) },
          { name = "LOG_LEVEL", value = var.environment == "prod" ? "info" : "debug" },

          # Service discovery: a stable DNS name inside the VPC, so an address
          # does not change on every deploy.
          { name = "AUTH_GRPC_ADDR", value = "authentication.karlo.internal:6001" },
          { name = "MASTERDATA_GRPC_ADDR", value = "masterdata.karlo.internal:6002" },
          { name = "BUSINESS_GRPC_ADDR", value = "business.karlo.internal:6003" },
          { name = "NOTIFICATION_GRPC_ADDR", value = "notification.karlo.internal:6004" },

          { name = "REDIS_ADDR", value = "${local.platform.redis_endpoint}:6379" },
          # ElastiCache has encryption in transit enabled, so the client must
          # use TLS or every connection is refused.
          { name = "REDIS_TLS", value = "true" },

          { name = "FLUENTD_HOST", value = var.fluentd_host },
          { name = "CORS_ALLOWED_ORIGINS", value = join(",", var.cors_allowed_origins) },
        ],
        var.extra_environment,
      )

      # Secrets are injected by the ECS agent at start, so they never appear in
      # the task definition — which is readable by anyone with console access.
      secrets = var.secrets

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.service.name
          "awslogs-region"        = var.region
          "awslogs-stream-prefix" = "ecs"
        }
      }

      healthCheck = {
        command     = ["CMD-SHELL", "wget -qO- http://localhost:${var.http_port}/health || exit 1"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 30
      }
    }
  ])

  # The image tag is set by CodePipeline on every deploy, so Terraform must not
  # fight it. Without this, every terraform apply would roll the service back to
  # whatever tag was last in state.
  lifecycle {
    ignore_changes = [container_definitions]
  }

  tags = { Name = local.name }
}

resource "aws_ecs_service" "main" {
  name            = var.service_name
  cluster         = local.platform.ecs_cluster_arn
  task_definition = aws_ecs_task_definition.main.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = local.platform.private_subnet_ids
    security_groups  = [local.platform.tasks_security_group_id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.main.arn
    container_name   = var.service_name
    container_port   = var.http_port
  }

  service_registries {
    registry_arn = aws_service_discovery_service.main.arn
  }

  # A rolling deploy that keeps the old tasks until the new ones are healthy.
  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200

  deployment_circuit_breaker {
    enable = true
    # Roll back automatically when a deploy cannot reach a healthy state, rather
    # than leaving the service down until someone notices.
    rollback = true
  }

  # The task definition revision and the desired count are both changed outside
  # Terraform — by CodePipeline and by autoscaling respectively.
  lifecycle {
    ignore_changes = [task_definition, desired_count]
  }

  depends_on = [aws_lb_listener_rule.main]

  tags = { Name = local.name }
}

# --- Load balancer routing --------------------------------------------------

resource "aws_lb_target_group" "main" {
  name        = local.name
  port        = var.http_port
  protocol    = "HTTP"
  vpc_id      = local.platform.vpc_id
  target_type = "ip"

  health_check {
    path                = "/health"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
    matcher             = "200"
  }

  # Give in-flight requests time to finish before a draining task is killed.
  deregistration_delay = 30

  tags = { Name = local.name }
}

resource "aws_lb_listener_rule" "main" {
  listener_arn = local.platform.alb_https_listener_arn
  priority     = var.listener_priority

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.main.arn
  }

  condition {
    path_pattern {
      values = var.path_patterns
    }
  }

  tags = { Name = local.name }
}

# --- Service discovery ------------------------------------------------------

resource "aws_service_discovery_service" "main" {
  name = var.discovery_name

  dns_config {
    namespace_id = local.platform.service_discovery_namespace_id

    dns_records {
      ttl  = 10
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }

  health_check_custom_config {
    failure_threshold = 1
  }
}

# --- Autoscaling ------------------------------------------------------------

resource "aws_appautoscaling_target" "main" {
  service_namespace  = "ecs"
  resource_id        = "service/${local.platform.ecs_cluster_name}/${aws_ecs_service.main.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  min_capacity       = var.min_capacity
  max_capacity       = var.max_capacity
}

# Scale on CPU. Target tracking rather than step scaling: it needs one number
# instead of a ladder of thresholds, and it scales down as readily as up, which
# is what keeps the bill proportional to load.
resource "aws_appautoscaling_policy" "cpu" {
  name               = "${local.name}-cpu"
  policy_type        = "TargetTrackingScaling"
  service_namespace  = aws_appautoscaling_target.main.service_namespace
  resource_id        = aws_appautoscaling_target.main.resource_id
  scalable_dimension = aws_appautoscaling_target.main.scalable_dimension

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }

    target_value = 65

    # Scale out quickly, in slowly. Adding a task costs a few cents; removing
    # one too eagerly during a lull means adding it back under load.
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }
}

resource "aws_appautoscaling_policy" "memory" {
  name               = "${local.name}-memory"
  policy_type        = "TargetTrackingScaling"
  service_namespace  = aws_appautoscaling_target.main.service_namespace
  resource_id        = aws_appautoscaling_target.main.resource_id
  scalable_dimension = aws_appautoscaling_target.main.scalable_dimension

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageMemoryUtilization"
    }

    target_value       = 75
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }
}
