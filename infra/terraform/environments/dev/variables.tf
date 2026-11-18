variable "aws_account_id" {
  description = "Real AWS account ID; never LocalStack."
  type        = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.aws_account_id)) && var.aws_account_id != "000000000000"
    error_message = "A real 12-digit AWS account ID is mandatory."
  }
}

variable "aws_region" {
  type    = string
  default = "ap-northeast-1"
}

variable "project_name" {
  type    = string
  default = "connected-vehicle"
}
