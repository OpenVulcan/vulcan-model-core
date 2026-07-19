# This script controls the recorded local Vite process for the management page.
# 此脚本控制本地管理页面已记录的 Vite 进程。
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Start", "Stop")]
    [string]$Action,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ProjectRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# projectRootFullPath is the repository root used to derive all local Vite paths.
# projectRootFullPath 是用于推导全部本地 Vite 路径的仓库根目录。
$projectRootFullPath = [System.IO.Path]::GetFullPath($ProjectRoot)
if (-not (Test-Path -LiteralPath $projectRootFullPath -PathType Container)) {
    throw "Project root was not found: $projectRootFullPath"
}

# managementDirectory owns the Vite package and its node_modules installation.
# managementDirectory 管理 Vite 包及其 node_modules 安装目录。
$managementDirectory = Join-Path -Path $projectRootFullPath -ChildPath "web/manage"
if (-not (Test-Path -LiteralPath $managementDirectory -PathType Container)) {
    throw "Management-page directory was not found: $managementDirectory"
}

# outputDirectory holds only ignored build and startup artifacts.
# outputDirectory 只保存被忽略的构建产物与启动信息。
$outputDirectory = Join-Path -Path $projectRootFullPath -ChildPath "output"
# statePath records the exact Vite process that this script is allowed to stop.
# statePath 记录此脚本允许停止的精确 Vite 进程。
$statePath = Join-Path -Path $outputDirectory -ChildPath "vite-state.json"
# standardOutputPath captures Vite standard output outside version control.
# standardOutputPath 在版本控制之外捕获 Vite 标准输出。
$standardOutputPath = Join-Path -Path $outputDirectory -ChildPath "vite.stdout.log"
# standardErrorPath captures Vite standard error outside version control.
# standardErrorPath 在版本控制之外捕获 Vite 标准错误。
$standardErrorPath = Join-Path -Path $outputDirectory -ChildPath "vite.stderr.log"
# standardInputPath prevents the detached Vite process from retaining the caller terminal input handle.
# standardInputPath 防止分离的 Vite 进程保留调用方终端输入句柄。
$standardInputPath = Join-Path -Path $outputDirectory -ChildPath "vite.stdin.log"

switch ($Action) {
    "Start" {
        $null = New-Item -ItemType Directory -Force -Path $outputDirectory

        if (Test-Path -LiteralPath $statePath -PathType Leaf) {
            # existingState is parsed before any process decision to prevent PID-only termination.
            # existingState 会在任何进程判断前解析，以避免仅凭 PID 终止进程。
            try {
                $existingState = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
            }
            catch {
                throw "Vite state file cannot be parsed: $statePath"
            }
            if ($null -eq $existingState.PSObject.Properties["process_id"] -or $null -eq $existingState.PSObject.Properties["started_at_utc"]) {
                throw "Vite state file is missing process identity: $statePath"
            }

            # existingProcess is valid only when both PID and process start time match the recorded state.
            # existingProcess 仅在 PID 和进程启动时间均与记录状态匹配时有效。
            $existingProcess = Get-Process -Id ([int]$existingState.process_id) -ErrorAction SilentlyContinue
            if ($null -ne $existingProcess) {
                $existingStartedAtUtc = $existingProcess.StartTime.ToUniversalTime().ToString("O")
                if ($existingStartedAtUtc -eq [string]$existingState.started_at_utc) {
                    Write-Host "Vite is already running, PID: $($existingProcess.Id)"
                    exit 0
                }
            }

            Remove-Item -LiteralPath $statePath -Force
        }

        # viteEntryPoint is the package-local executable used to avoid an npm child-process chain.
        # viteEntryPoint 是包本地可执行入口，用于避免 npm 子进程链。
        $viteEntryPoint = Join-Path -Path $managementDirectory -ChildPath "node_modules/vite/bin/vite.js"
        if (-not (Test-Path -LiteralPath $viteEntryPoint -PathType Leaf)) {
            # npmCommand installs the locked frontend dependencies only when Vite is unavailable.
            # npmCommand 仅在 Vite 不可用时安装锁定的前端依赖。
            $npmCommand = Get-Command "npm.cmd" -ErrorAction SilentlyContinue
            if ($null -eq $npmCommand) {
                $npmCommand = Get-Command "npm" -ErrorAction Stop
            }
            # npmExitCode preserves dependency installation failures after restoring the working directory.
            # npmExitCode 在恢复工作目录后保留依赖安装失败结果。
            $npmExitCode = 0
            Push-Location -LiteralPath $managementDirectory
            try {
                & $npmCommand.Path ci
                $npmExitCode = $LASTEXITCODE
            }
            finally {
                Pop-Location
            }
            if ($npmExitCode -ne 0) {
                throw "Vite dependency installation failed with exit code: $npmExitCode"
            }
        }
        if (-not (Test-Path -LiteralPath $viteEntryPoint -PathType Leaf)) {
            throw "Vite entry point was not found: $viteEntryPoint"
        }

        # nodeCommand directly hosts Vite so the recorded PID belongs to the server process itself.
        # nodeCommand 直接承载 Vite，使记录的 PID 归属于服务进程自身。
        $nodeCommand = Get-Command "node" -ErrorAction Stop
        # viteArguments preserve the existing loopback, port, and strict-port development contract.
        # viteArguments 保持既有仅环回、端口和严格端口开发约定。
        $viteArguments = @(
            ('"{0}"' -f $viteEntryPoint),
            "--host",
            "127.0.0.1",
            "--port",
            "13520",
            "--strictPort"
        )
        # viteProcess is hidden because it is controlled through make rather than an interactive console.
        # viteProcess 被隐藏，因为它通过 make 而非交互式控制台控制。
        $null = New-Item -ItemType File -Force -Path $standardInputPath
        $viteProcess = Start-Process -FilePath $nodeCommand.Path -ArgumentList $viteArguments -WorkingDirectory $managementDirectory -RedirectStandardInput $standardInputPath -RedirectStandardOutput $standardOutputPath -RedirectStandardError $standardErrorPath -WindowStyle Hidden -PassThru
        Start-Sleep -Milliseconds 700
        $viteProcess.Refresh()
        if ($viteProcess.HasExited) {
            throw "Vite startup failed. Inspect log: $standardErrorPath"
        }

        # viteState binds the PID to its start time so a recycled PID is never stopped later.
        # viteState 将 PID 绑定到启动时间，确保之后绝不停止复用的 PID。
        $viteState = [PSCustomObject]@{
            process_id     = $viteProcess.Id
            started_at_utc = $viteProcess.StartTime.ToUniversalTime().ToString("O")
        }
        $viteState | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding utf8
        Write-Host "Vite started: http://127.0.0.1:13520 (PID: $($viteProcess.Id))"
        break
    }
    "Stop" {
        if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
            Write-Host "No Vite process is managed by Make."
            break
        }

        # recordedState authorizes a stop only after both identity values are present.
        # recordedState 仅在两个身份值均存在时才授权停止操作。
        try {
            $recordedState = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
        }
        catch {
            throw "Vite state file cannot be parsed: $statePath"
        }
        if ($null -eq $recordedState.PSObject.Properties["process_id"] -or $null -eq $recordedState.PSObject.Properties["started_at_utc"]) {
            throw "Vite state file is missing process identity: $statePath"
        }

        # recordedProcess is the single process identified by the saved state.
        # recordedProcess 是由保存状态唯一标识的进程。
        $recordedProcess = Get-Process -Id ([int]$recordedState.process_id) -ErrorAction SilentlyContinue
        if ($null -eq $recordedProcess) {
            Remove-Item -LiteralPath $statePath -Force
            Write-Host "The recorded Vite process already exited; state was cleared."
            break
        }

        # recordedStartedAtUtc protects unrelated processes when Windows has reused a PID.
        # recordedStartedAtUtc 在 Windows 复用 PID 时保护无关进程。
        $recordedStartedAtUtc = $recordedProcess.StartTime.ToUniversalTime().ToString("O")
        if ($recordedStartedAtUtc -ne [string]$recordedState.started_at_utc) {
            Remove-Item -LiteralPath $statePath -Force
            Write-Warning "The recorded PID was reused; no process was stopped and state was cleared."
            break
        }

        # taskKillExitCode records the verified process-tree termination result for Vite child processes.
        # taskKillExitCode 记录已验证 Vite 子进程树终止操作的结果。
        & taskkill.exe /PID $recordedProcess.Id /T /F | Out-Null
        $taskKillExitCode = $LASTEXITCODE
        if ($taskKillExitCode -ne 0) {
            throw "Vite process-tree termination failed with exit code: $taskKillExitCode"
        }
        Remove-Item -LiteralPath $statePath -Force
        Write-Host "Vite stopped, PID: $($recordedProcess.Id)"
        break
    }
}
