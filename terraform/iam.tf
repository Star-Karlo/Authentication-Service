# IAM.
#
# Four roles, each scoped to what it actually needs. The split that matters most
# is task_execution versus task: the first is used by the ECS agent to pull the
# image and read secrets at start, the second is what the running application
# can do. Merging them would give the application the ability to read every
# secret the agent can.

data "aws_iam_policy_document" "ecs_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

# --- Task execution role ----------------------------------------------------

resource "aws_iam_role" "task_execution" {
  name               = "${local.name}-task-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

resource "aws_iam_role_policy_attachment" "task_execution" {
  role       = aws_iam_role.task_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# Secret access is enumerated, not wildcarded. A service reads the secrets it
# needs and no others, so a compromised task definition cannot widen its own
# reach.
data "aws_iam_policy_document" "task_execution_secrets" {
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = var.secret_arns
  }
}

resource "aws_iam_role_policy" "task_execution_secrets" {
  name   = "${local.name}-secrets"
  role   = aws_iam_role.task_execution.id
  policy = data.aws_iam_policy_document.task_execution_secrets.json
}

# --- Task role --------------------------------------------------------------

resource "aws_iam_role" "task" {
  name               = "${local.name}-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

# The application's own permissions. Deliberately minimal: these services talk
# to their database, to each other over gRPC, and to Fluentd. None of that needs
# an AWS API call, so the only grant is the one ECS Exec needs for a shell into
# a running task, and only outside production.
data "aws_iam_policy_document" "task" {
  count = var.environment == "prod" ? 0 : 1

  statement {
    actions = [
      "ssmmessages:CreateControlChannel",
      "ssmmessages:CreateDataChannel",
      "ssmmessages:OpenControlChannel",
      "ssmmessages:OpenDataChannel",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "task" {
  count = var.environment == "prod" ? 1 : 0

  name = "${local.name}-task"
  role = aws_iam_role.task.id

  # An empty-but-present policy in production, so the role exists with no
  # permissions rather than silently inheriting something later.
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = []
  })
}

resource "aws_iam_role_policy" "task_exec_access" {
  count = var.environment == "prod" ? 0 : 1

  name   = "${local.name}-exec"
  role   = aws_iam_role.task.id
  policy = data.aws_iam_policy_document.task[0].json
}

# --- CodeBuild role ---------------------------------------------------------

data "aws_iam_policy_document" "codebuild_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["codebuild.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "codebuild" {
  name               = "${local.name}-codebuild"
  assume_role_policy = data.aws_iam_policy_document.codebuild_assume.json
}

data "aws_iam_policy_document" "codebuild" {
  statement {
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.build.arn}:*"]
  }

  statement {
    actions = [
      "s3:GetObject",
      "s3:GetObjectVersion",
      "s3:PutObject",
      "s3:GetBucketAcl",
      "s3:GetBucketLocation",
    ]
    resources = [
      "arn:aws:s3:::${local.platform.artifacts_bucket}",
      "arn:aws:s3:::${local.platform.artifacts_bucket}/*",
    ]
  }

  # GetAuthorizationToken cannot be scoped to a repository — it is an
  # account-level call — but every write is confined to this service's own
  # repository.
  statement {
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:CompleteLayerUpload",
      "ecr:InitiateLayerUpload",
      "ecr:PutImage",
      "ecr:UploadLayerPart",
      "ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer",
    ]
    resources = [local.ecr_repository_arn]
  }
}

resource "aws_iam_role_policy" "codebuild" {
  name   = "${local.name}-codebuild"
  role   = aws_iam_role.codebuild.id
  policy = data.aws_iam_policy_document.codebuild.json
}

# --- CodePipeline role ------------------------------------------------------

data "aws_iam_policy_document" "codepipeline_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["codepipeline.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "codepipeline" {
  name               = "${local.name}-codepipeline"
  assume_role_policy = data.aws_iam_policy_document.codepipeline_assume.json
}

data "aws_iam_policy_document" "codepipeline" {
  statement {
    actions = [
      "s3:GetObject",
      "s3:GetObjectVersion",
      "s3:PutObject",
      "s3:GetBucketVersioning",
    ]
    resources = [
      "arn:aws:s3:::${local.platform.artifacts_bucket}",
      "arn:aws:s3:::${local.platform.artifacts_bucket}/*",
    ]
  }

  statement {
    actions   = ["codebuild:BatchGetBuilds", "codebuild:StartBuild"]
    resources = [aws_codebuild_project.build.arn]
  }

  statement {
    actions   = ["codestar-connections:UseConnection"]
    resources = [local.platform.github_connection_arn]
  }

  # The ECS deploy action registers a new task definition revision and updates
  # the service.
  statement {
    actions = [
      "ecs:DescribeServices",
      "ecs:DescribeTaskDefinition",
      "ecs:DescribeTasks",
      "ecs:ListTasks",
      "ecs:RegisterTaskDefinition",
      "ecs:UpdateService",
    ]
    resources = ["*"]
  }

  # Required so CodePipeline may hand the task's roles to ECS. Scoped to this
  # service's two roles, so a pipeline cannot attach an unrelated role to a
  # task it starts.
  statement {
    actions   = ["iam:PassRole"]
    resources = [aws_iam_role.task_execution.arn, aws_iam_role.task.arn]

    condition {
      test     = "StringEqualsIfExists"
      variable = "iam:PassedToService"
      values   = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "codepipeline" {
  name   = "${local.name}-codepipeline"
  role   = aws_iam_role.codepipeline.id
  policy = data.aws_iam_policy_document.codepipeline.json
}
