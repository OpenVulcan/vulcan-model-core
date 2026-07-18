# This script creates the local startup configuration without overwriting existing credentials.
# 此脚本创建本地启动配置且不会覆盖已有凭据。
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$TemplatePath,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ConfigurationPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# templateFullPath is the tracked source YAML used only for first-time bootstrapping.
# templateFullPath 是仅用于首次引导的受版本控制源 YAML。
$templateFullPath = [System.IO.Path]::GetFullPath($TemplatePath)
# configurationFullPath is the ignored active startup YAML file.
# configurationFullPath 是被忽略的生效启动 YAML 文件。
$configurationFullPath = [System.IO.Path]::GetFullPath($ConfigurationPath)

if (-not (Test-Path -LiteralPath $templateFullPath -PathType Leaf)) {
    throw "Configuration template was not found: $templateFullPath"
}

if (Test-Path -LiteralPath $configurationFullPath -PathType Leaf) {
    Write-Host "Configuration already exists and was not overwritten: $configurationFullPath"
    exit 0
}

# configurationDirectory is created before the first configuration copy.
# configurationDirectory 会在首次复制配置前创建。
$configurationDirectory = Split-Path -Parent $configurationFullPath
$null = New-Item -ItemType Directory -Force -Path $configurationDirectory
Copy-Item -LiteralPath $templateFullPath -Destination $configurationFullPath
Write-Host "Configuration created: $configurationFullPath"
Write-Host "Replace the management and call-plane key placeholders before running make run."
