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

variable "availability_zones" {
  description = "Explicitly pinned AZ names; check them in the target AWS account."
  type        = list(string)
  default     = ["ap-northeast-1a", "ap-northeast-1c"]
  validation {
    condition     = length(var.availability_zones) == 2 && length(distinct(var.availability_zones)) == 2
    error_message = "Two distinct Availability Zones are required."
  }
}

variable "private_subnet_cidrs" {
  type    = list(string)
  default = ["10.74.10.0/24", "10.74.20.0/24"]
  validation {
    condition     = length(var.private_subnet_cidrs) == 2 && alltrue([for c in var.private_subnet_cidrs : can(cidrhost(c, 1))])
    error_message = "Two valid private subnet CIDRs are required."
  }
}
