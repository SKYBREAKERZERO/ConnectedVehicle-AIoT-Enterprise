variable "project_name" {
  description = "Project identifier used in OU and SCP names."
  type        = string
  default     = "connected-vehicle"
  nullable    = false

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,22}[a-z0-9]$", var.project_name))
    error_message = "project_name must contain 3-24 lowercase letters, numbers, or hyphens."
  }
}

variable "deployment_mode" {
  description = "offline generates contracts only; localstack and aws permit explicitly enabled Organizations writes."
  type        = string
  default     = "offline"
  nullable    = false

  validation {
    condition     = contains(["offline", "localstack", "aws"], var.deployment_mode)
    error_message = "deployment_mode must be offline, localstack, or aws."
  }
}

variable "enable_organizations_management" {
  description = "Explicitly enable OU creation and SCP management; does not create an organization or accounts."
  type        = bool
  default     = false
  nullable    = false

  validation {
    condition     = !var.enable_organizations_management || var.deployment_mode != "offline"
    error_message = "Organizations writes are forbidden in offline mode."
  }
}

variable "management_account_id" {
  description = "Expected management account ID; the all-zero default is for offline and LocalStack only."
  type        = string
  default     = "000000000000"
  nullable    = false

  validation {
    condition     = can(regex("^[0-9]{12}$", var.management_account_id))
    error_message = "management_account_id must contain exactly 12 digits."
  }

  validation {
    condition     = var.deployment_mode != "aws" || var.management_account_id != "000000000000"
    error_message = "AWS mode requires the actual management account ID."
  }
}

variable "organization_root_id" {
  description = "Existing organization root used only as the parent of newly created OUs."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.organization_root_id == null || can(regex("^r-[a-z0-9]{4,32}$", var.organization_root_id))
    error_message = "organization_root_id must be null or a valid organization root ID."
  }

  validation {
    condition = (
      !var.enable_organizations_management ||
      alltrue([for config in values(var.environment_accounts) : config.existing_ou_id != null]) ||
      var.organization_root_id != null
    )

    error_message = "Creating an environment OU requires an existing organization_root_id."
  }
}

variable "environment_accounts" {
  description = "Existing member accounts by environment; null existing_ou_id requests a new OU when management is enabled."

  type = map(object({
    account_id     = string
    existing_ou_id = optional(string)
    manage_ou      = optional(bool, false)
  }))

  default  = {}
  nullable = false

  validation {
    condition = alltrue([
      for environment, config in var.environment_accounts :
      contains(["dev", "staging", "prod"], environment) &&
      can(regex("^[0-9]{12}$", config.account_id)) &&
      config.account_id != var.management_account_id &&
      (
        config.existing_ou_id == null ||
        can(regex("^ou-[a-z0-9]{4,32}-[a-z0-9]{8,32}$", config.existing_ou_id))
      )
    ])

    error_message = "Use dev, staging, or prod with a member account distinct from management and an optional valid OU ID."
  }

  validation {
    condition = (
      length(toset([for config in values(var.environment_accounts) : config.account_id])) ==
      length(var.environment_accounts)
    )

    error_message = "Each environment must use a distinct account ID."
  }

  validation {
    condition     = !var.enable_organizations_management || length(var.environment_accounts) > 0
    error_message = "Organizations management requires at least one environment account mapping."
  }
}

variable "allowed_regions" {
  description = "Approved workload regions; SCP generation must handle global services separately."
  type        = set(string)
  default     = ["ap-northeast-1"]
  nullable    = false

  validation {
    condition = length(var.allowed_regions) > 0 && alltrue([
      for region in var.allowed_regions :
      can(regex("^[a-z]{2}(-[a-z]+)+-[0-9]+$", region))
    ])

    error_message = "Provide at least one valid AWS-style region name."
  }
}

variable "protected_bucket_arns" {
  description = "Exact state and firmware bucket ARNs to protect; object ARNs and wildcards are forbidden."
  type        = set(string)
  default     = []
  nullable    = false

  validation {
    condition = alltrue([
      for arn in var.protected_bucket_arns :
      can(regex("^arn:(aws|aws-cn|aws-us-gov):s3:::[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", arn))
    ])

    error_message = "Provide exact S3 bucket ARNs without object paths or wildcards."
  }
}

variable "protected_kms_key_arns" {
  description = "Exact state, firmware, and authority KMS key ARNs to protect."
  type        = set(string)
  default     = []
  nullable    = false

  validation {
    condition = alltrue([
      for arn in var.protected_kms_key_arns :
      can(regex("^arn:(aws|aws-cn|aws-us-gov):kms:[a-z0-9-]+:[0-9]{12}:key/[A-Za-z0-9-]+$", arn))
    ])

    error_message = "Provide explicit KMS key ARNs without aliases or wildcards."
  }

  validation {
    condition = (
      !var.enable_organizations_management || var.governance_stage != "enforce" ||
      length(var.protected_kms_key_arns) > 0
    )
    error_message = "Enforcement requires explicitly protected KMS keys."
  }
}

variable "tags" {
  description = "Additional governance tags; reserved module tags are set in locals.tf."
  type        = map(string)
  default     = {}
  nullable    = false

  validation {
    condition = length(var.tags) <= 40 && alltrue([
      for key, value in var.tags :
      length(trimspace(key)) > 0 &&
      length(key) <= 128 &&
      length(value) <= 256 &&
      !startswith(lower(key), "aws:")
    ])

    error_message = "Use at most 40 valid tags without the reserved aws: prefix."
  }
}
variable "governance_stage" {
  description = "topology creates empty OUs; enforce requires established membership before attaching SCPs."
  type        = string
  default     = "topology"
  nullable    = false
  validation {
    condition     = contains(["topology", "enforce"], var.governance_stage)
    error_message = "governance_stage must be topology or enforce."
  }
}

variable "attachment_scope" {
  description = "Use verified OU inheritance by default; account attachments require an explicit opt-in."
  type        = string
  default     = "ou"
  nullable    = false
  validation {
    condition     = contains(["ou", "account"], var.attachment_scope)
    error_message = "attachment_scope must be ou or account."
  }
  validation {
    condition = (
      !var.enable_organizations_management || var.governance_stage != "enforce" ||
      var.attachment_scope != "ou" ||
      alltrue([for config in values(var.environment_accounts) : config.existing_ou_id != null])
    )
    error_message = "OU enforcement requires existing OUs. Create topology, move accounts under an audited organization procedure, then enforce."
  }
}

variable "protected_firmware_bucket_arns" {
  description = "Dedicated firmware buckets whose object versions must not be deleted. Never include state buckets."
  type        = set(string)
  default     = []
  nullable    = false
  validation {
    condition = alltrue([
      for arn in var.protected_firmware_bucket_arns : contains(var.protected_bucket_arns, arn)
    ])
    error_message = "Every firmware bucket must also be in protected_bucket_arns."
  }
  validation {
    condition = (
      !var.enable_organizations_management || var.governance_stage != "enforce" ||
      length(var.protected_firmware_bucket_arns) > 0
    )
    error_message = "Enforcement requires at least one explicitly protected firmware bucket."
  }
}

variable "protected_state_bucket_arns" {
  description = "State buckets, protected administratively but excluded from firmware object deletion denies."
  type        = set(string)
  default     = []
  nullable    = false
  validation {
    condition = alltrue([
      for arn in var.protected_state_bucket_arns :
      contains(var.protected_bucket_arns, arn) && !contains(var.protected_firmware_bucket_arns, arn)
    ])
    error_message = "State buckets must be protected and disjoint from firmware buckets."
  }
}

variable "retired_environments" {
  description = "Requested attachment retirements; prevent_destroy still requires the separately reviewed retirement procedure."
  type        = set(string)
  default     = []
  nullable    = false
  validation {
    condition     = alltrue([for environment in var.retired_environments : contains(keys(var.environment_accounts), environment)])
    error_message = "Retirements must name configured environments; keep topology mappings until handoff is complete."
  }
  validation {
    condition     = length(var.retired_environments) == 0 || can(regex("^[0-9a-f]{32}$", var.retirement_operation_id))
    error_message = "A retirement requires an explicit 32-character operation ID and the documented review workflow."
  }
}

variable "retirement_operation_id" {
  description = "Operation ID used to correlate a separately reviewed retirement manifest."
  type        = string
  default     = null
  nullable    = true
}
