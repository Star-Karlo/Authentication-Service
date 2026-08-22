# The delivery pipeline: GitHub -> CodePipeline -> CodeBuild -> Fargate.
#
# Source is the CodeStar connection created by platform-terraform. It must be
# authorised once by hand in the console before any pipeline can pull; Terraform
# can create the connection but cannot complete the OAuth handshake.

# --- CodeBuild --------------------------------------------------------------

resource "aws_cloudwatch_log_group" "build" {
  name              = "/aws/codebuild/${local.name}"
  retention_in_days = var.log_retention_days
}

resource "aws_codebuild_project" "build" {
  name          = local.name
  service_role  = aws_iam_role.codebuild.arn
  build_timeout = 20

  artifacts {
    type = "CODEPIPELINE"
  }

  environment {
    compute_type = "BUILD_GENERAL1_SMALL"
    image        = "aws/codebuild/amazonlinux2-x86_64-standard:5.0"
    type         = "LINUX_CONTAINER"

    # Required to build a container image inside CodeBuild.
    privileged_mode = true

    environment_variable {
      name  = "AWS_ACCOUNT_ID"
      value = data.aws_caller_identity.current.account_id
    }
    environment_variable {
      name  = "AWS_REGION"
      value = var.region
    }
    environment_variable {
      name  = "ECR_REPOSITORY"
      value = local.platform.ecr_repository_urls[var.service_name]
    }
    environment_variable {
      name  = "CONTAINER_NAME"
      value = var.service_name
    }
  }

  source {
    type      = "CODEPIPELINE"
    buildspec = file("${path.module}/buildspec.yml")
  }

  # A local cache keeps the Go module cache and Docker layers between builds.
  # Without it every build re-downloads the whole dependency tree, which is the
  # single biggest contributor to build minutes and therefore to build cost.
  cache {
    type  = "LOCAL"
    modes = ["LOCAL_DOCKER_LAYER_CACHE", "LOCAL_CUSTOM_CACHE"]
  }

  logs_config {
    cloudwatch_logs {
      group_name = aws_cloudwatch_log_group.build.name
    }
  }

  tags = { Name = local.name }
}

# --- CodePipeline -----------------------------------------------------------

resource "aws_codepipeline" "main" {
  name     = local.name
  role_arn = aws_iam_role.codepipeline.arn

  artifact_store {
    location = local.platform.artifacts_bucket
    type     = "S3"
  }

  stage {
    name = "Source"

    action {
      name             = "GitHub"
      category         = "Source"
      owner            = "AWS"
      provider         = "CodeStarSourceConnection"
      version          = "1"
      output_artifacts = ["source"]

      configuration = {
        ConnectionArn    = local.platform.github_connection_arn
        FullRepositoryId = var.github_repository
        BranchName       = var.github_branch
        # Webhook-driven rather than polled: polling costs a pipeline execution
        # check every minute and delays every deploy by up to that long.
        DetectChanges = true
      }
    }
  }

  stage {
    name = "Build"

    action {
      name             = "Build"
      category         = "Build"
      owner            = "AWS"
      provider         = "CodeBuild"
      version          = "1"
      input_artifacts  = ["source"]
      output_artifacts = ["build"]

      configuration = {
        ProjectName = aws_codebuild_project.build.name
      }
    }
  }

  stage {
    name = "Deploy"

    action {
      name            = "Fargate"
      category        = "Deploy"
      owner           = "AWS"
      provider        = "ECS"
      version         = "1"
      input_artifacts = ["build"]

      configuration = {
        ClusterName = local.platform.ecs_cluster_name
        ServiceName = aws_ecs_service.main.name
        # Produced by buildspec.yml; names the image the task should run.
        FileName = "imagedefinitions.json"
      }
    }
  }

  tags = { Name = local.name }
}

data "aws_caller_identity" "current" {}
