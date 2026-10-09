[CmdletBinding()]
param(
    [string]$EndpointUrl = "http://localhost:14566",

    [string]$Region = "ap-northeast-1",

    [string]$RoleArn = (
        "arn:aws:iam::000000000000:role/" +
        "connected-vehicle-aiot-enterprise-local-secret-bootstrap"
    ),

    [string]$RoleSessionName = (
        "connected-vehicle-secret-bootstrap"
    ),

    [string]$SecretId = (
        "/connected-vehicle/local/database/application"
    ),

    [string]$DatabaseHost = "postgres",

    [int]$DatabasePort = 5432,

    [string]$DatabaseName = "",

    [string]$DatabaseUsername = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-FirstNonEmptyValue {
    param(
        [string[]]$Values
    )

    foreach ($value in $Values) {
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            return $value
        }
    }

    return $null
}

function Restore-ProcessEnvironmentVariable {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [AllowNull()]
        [string]$Value
    )

    [Environment]::SetEnvironmentVariable(
        $Name,
        $Value,
        [EnvironmentVariableTarget]::Process
    )
}

if ([string]::IsNullOrWhiteSpace($DatabaseName)) {
    $DatabaseName = Get-FirstNonEmptyValue @(
        $env:DATABASE_NAME,
        $env:POSTGRES_DB
    )
}

if ([string]::IsNullOrWhiteSpace($DatabaseName)) {
    $DatabaseName = Read-Host "Database name"
}

if ([string]::IsNullOrWhiteSpace($DatabaseUsername)) {
    $DatabaseUsername = Get-FirstNonEmptyValue @(
        $env:DATABASE_USERNAME,
        $env:POSTGRES_USER
    )
}

if ([string]::IsNullOrWhiteSpace($DatabaseUsername)) {
    $DatabaseUsername = Read-Host "Database username"
}

if ([string]::IsNullOrWhiteSpace($DatabaseName)) {
    throw "Database name must not be empty."
}

if ([string]::IsNullOrWhiteSpace($DatabaseUsername)) {
    throw "Database username must not be empty."
}

$plainPassword = Get-FirstNonEmptyValue @(
    $env:DATABASE_PASSWORD,
    $env:POSTGRES_PASSWORD
)

if ([string]::IsNullOrEmpty($plainPassword)) {
    $securePassword = Read-Host `
        "Database password" `
        -AsSecureString

    $passwordPointer = (
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR(
            $securePassword
        )
    )

    try {
        $plainPassword = (
            [Runtime.InteropServices.Marshal]::PtrToStringBSTR(
                $passwordPointer
            )
        )
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR(
            $passwordPointer
        )
    }
}

if ([string]::IsNullOrEmpty($plainPassword)) {
    throw "Database password must not be empty."
}

$secretPayload = [ordered]@{
    engine   = "postgres"
    host     = $DatabaseHost
    port     = $DatabasePort
    dbname   = $DatabaseName
    username = $DatabaseUsername
    password = $plainPassword
} | ConvertTo-Json -Compress

$tempFile = Join-Path `
    ([System.IO.Path]::GetTempPath()) `
    (
        "connected-vehicle-db-secret-" +
        [guid]::NewGuid().ToString("N") +
        ".json"
    )

$originalAccessKeyId = (
    [Environment]::GetEnvironmentVariable(
        "AWS_ACCESS_KEY_ID",
        [EnvironmentVariableTarget]::Process
    )
)

$originalSecretAccessKey = (
    [Environment]::GetEnvironmentVariable(
        "AWS_SECRET_ACCESS_KEY",
        [EnvironmentVariableTarget]::Process
    )
)

$originalSessionToken = (
    [Environment]::GetEnvironmentVariable(
        "AWS_SESSION_TOKEN",
        [EnvironmentVariableTarget]::Process
    )
)

$originalSecurityToken = (
    [Environment]::GetEnvironmentVariable(
        "AWS_SECURITY_TOKEN",
        [EnvironmentVariableTarget]::Process
    )
)

try {
    [System.IO.File]::WriteAllText(
        $tempFile,
        $secretPayload,
        [System.Text.UTF8Encoding]::new($false)
    )

    $assumeRoleOutput = & aws `
        --endpoint-url $EndpointUrl `
        --region $Region `
        sts assume-role `
        --role-arn $RoleArn `
        --role-session-name $RoleSessionName `
        --output json

    if ($LASTEXITCODE -ne 0) {
        throw "Failed to assume the Secret Bootstrap IAM role."
    }

    $assumedRole = (
        $assumeRoleOutput |
        ConvertFrom-Json
    )

    if ($null -eq $assumedRole.Credentials) {
        throw "AssumeRole did not return temporary credentials."
    }

    if ($null -eq $assumedRole.AssumedRoleUser) {
        throw "AssumeRole did not return assumed-role identity information."
    }

    $credentials = $assumedRole.Credentials

    if (
        [string]::IsNullOrWhiteSpace(
            [string]$credentials.AccessKeyId
        ) -or
        [string]::IsNullOrWhiteSpace(
            [string]$credentials.SecretAccessKey
        ) -or
        [string]::IsNullOrWhiteSpace(
            [string]$credentials.SessionToken
        )
    ) {
        throw "AssumeRole returned incomplete temporary credentials."
    }

    Write-Host (
        "Assumed Secret Bootstrap role: " +
        $assumedRole.AssumedRoleUser.Arn
    )

    [Environment]::SetEnvironmentVariable(
        "AWS_ACCESS_KEY_ID",
        [string]$credentials.AccessKeyId,
        [EnvironmentVariableTarget]::Process
    )

    [Environment]::SetEnvironmentVariable(
        "AWS_SECRET_ACCESS_KEY",
        [string]$credentials.SecretAccessKey,
        [EnvironmentVariableTarget]::Process
    )

    [Environment]::SetEnvironmentVariable(
        "AWS_SESSION_TOKEN",
        [string]$credentials.SessionToken,
        [EnvironmentVariableTarget]::Process
    )

    [Environment]::SetEnvironmentVariable(
        "AWS_SECURITY_TOKEN",
        $null,
        [EnvironmentVariableTarget]::Process
    )

    & aws `
        --endpoint-url $EndpointUrl `
        --region $Region `
        secretsmanager put-secret-value `
        --secret-id $SecretId `
        --secret-string "file://$tempFile" `
        --query (
            "{ARN:ARN," +
            "Name:Name," +
            "VersionId:VersionId," +
            "VersionStages:VersionStages}"
        ) `
        --output json

    if ($LASTEXITCODE -ne 0) {
        throw (
            "Failed to create the Secrets Manager secret version " +
            "using the Secret Bootstrap role."
        )
    }
}
finally {
    Restore-ProcessEnvironmentVariable `
        -Name "AWS_ACCESS_KEY_ID" `
        -Value $originalAccessKeyId

    Restore-ProcessEnvironmentVariable `
        -Name "AWS_SECRET_ACCESS_KEY" `
        -Value $originalSecretAccessKey

    Restore-ProcessEnvironmentVariable `
        -Name "AWS_SESSION_TOKEN" `
        -Value $originalSessionToken

    Restore-ProcessEnvironmentVariable `
        -Name "AWS_SECURITY_TOKEN" `
        -Value $originalSecurityToken

    $plainPassword = $null
    $secretPayload = $null

    if (Test-Path -LiteralPath $tempFile) {
        Remove-Item `
            -LiteralPath $tempFile `
            -Force
    }
}