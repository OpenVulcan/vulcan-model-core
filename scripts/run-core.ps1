# This script runs the compiled core from output/bin with stable local runtime paths.
# 此脚本从 output/bin 运行编译后的核心服务并使用稳定的本地运行时路径。
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$BinaryPath,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$RelativeConfigurationPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# binaryFullPath is the compiled executable created by make run.
# binaryFullPath 是由 make run 创建的编译后可执行文件。
$binaryFullPath = [System.IO.Path]::GetFullPath($BinaryPath)
if (-not (Test-Path -LiteralPath $binaryFullPath -PathType Leaf)) {
    throw "Core executable was not found: $binaryFullPath"
}

# binaryDirectory is the process working directory, whose parent is the output root.
# binaryDirectory 是进程工作目录，其父目录为 output 根目录。
$binaryDirectory = Split-Path -Parent $binaryFullPath
# configurationFullPath validates the exact configuration resolved from output/bin.
# configurationFullPath 验证从 output/bin 解析出的精确配置文件。
$configurationFullPath = [System.IO.Path]::GetFullPath((Join-Path -Path $binaryDirectory -ChildPath $RelativeConfigurationPath))
if (-not (Test-Path -LiteralPath $configurationFullPath -PathType Leaf)) {
    throw "Startup configuration was not found: $configurationFullPath. Run make config and replace the key placeholders first."
}

# userProfilePath is the Windows home directory that backs the requested ~/.vulcan path.
# userProfilePath 是承载所需 ~/.vulcan 路径的 Windows 主目录。
$userProfilePath = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
if ([string]::IsNullOrWhiteSpace($userProfilePath)) {
    throw "The current user profile directory could not be resolved."
}
# userDataRoot is the user-level persistent router root.
# userDataRoot 是用户级持久化 Router 根目录。
$userDataRoot = Join-Path -Path (Join-Path -Path $userProfilePath -ChildPath ".vulcan") -ChildPath "router"
# databaseDirectory owns the durable SQLite database file.
# databaseDirectory 管理持久化 SQLite 数据库文件。
$databaseDirectory = Join-Path -Path $userDataRoot -ChildPath "database"
# databasePath is the prescribed ~/.vulcan/router/database/data.db location.
# databasePath 是规定的 ~/.vulcan/router/database/data.db 位置。
$databasePath = Join-Path -Path $databaseDirectory -ChildPath "data.db"
# secretDirectory stores OS-protected upstream credentials outside the repository.
# secretDirectory 将受操作系统保护的上游凭据存储在仓库之外。
$secretDirectory = Join-Path -Path $userDataRoot -ChildPath "secrets"
# resourceDirectory stores Router-owned verified objects outside the repository.
# resourceDirectory 在仓库之外保存 Router 拥有的已验证对象。
$resourceDirectory = Join-Path -Path $userDataRoot -ChildPath "resources"

$null = New-Item -ItemType Directory -Force -Path $databaseDirectory
$null = New-Item -ItemType Directory -Force -Path $secretDirectory
$null = New-Item -ItemType Directory -Force -Path $resourceDirectory

# processExitCode preserves the core process result after returning to the caller's directory.
# processExitCode 在返回调用方目录后保留核心进程结果。
$processExitCode = 0
Push-Location -LiteralPath $binaryDirectory
try {
    & $binaryFullPath --config $RelativeConfigurationPath --database-path $databasePath --secret-directory $secretDirectory --resource-directory $resourceDirectory
    $processExitCode = $LASTEXITCODE
}
finally {
    Pop-Location
}

if ($processExitCode -ne 0) {
    exit $processExitCode
}
