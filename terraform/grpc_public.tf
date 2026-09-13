# The service's gRPC port, published on the load balancer for callers outside
# the VPC.
#
# Inside the VPC services find each other by private DNS and speak plaintext
# HTTP/2 on 6001/6002. FMS runs in another region, where those names do not
# resolve, so the same port is also reachable on a public *-grpc.karlo.id
# name: TLS terminates on the load balancer (the wildcard certificate), the
# load balancer speaks HTTP/2 to the task, and the service-token interceptor
# authenticates every call exactly as it does for an internal one.
#
# Health: the ALB calls a method nobody implements and expects gRPC status 12
# (UNIMPLEMENTED) — the standard probe for a server with no health service.
# The interceptor exempts health-check paths, so it never needs a token.

resource "aws_lb_target_group" "grpc" {
  name             = "${local.name}-grpc"
  port             = var.grpc_port
  protocol         = "HTTP"
  protocol_version = "GRPC"
  vpc_id           = local.platform.vpc_id
  target_type      = "ip"

  health_check {
    path                = "/grpc.health.v1.Health/Check"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
    matcher             = "0-99"
  }

  deregistration_delay = 30

  tags = { Name = "${local.name}-grpc" }
}

resource "aws_lb_listener_rule" "grpc_host" {
  listener_arn = local.platform.alb_listener_arns.https
  priority     = var.listener_priority - 60

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.grpc.arn
  }

  condition {
    host_header {
      values = [local.platform.grpc_hostnames[var.service_name]]
    }
  }

  tags = { Name = "${local.name}-grpc-host" }
}
