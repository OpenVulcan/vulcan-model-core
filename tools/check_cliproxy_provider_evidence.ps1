# The source root points at the fixed CLIProxyAPI checkout used as provider evidence.
# 源根目录指向作为供应商证据使用的固定 CLIProxyAPI 检出目录。
$sourceRoot = [System.IO.Path]::GetFullPath("D:/openvulcan/third_git/CLIProxyAPI")

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "cliproxy_paths.ps1")

# The expected commit freezes every provider conclusion to one reviewed upstream state.
# 预期提交将每项供应商结论固定到一个已审核的上游状态。
$expectedCommit = "9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66"

# The repository root is resolved from this evidence script.
# 仓库根目录根据当前证据脚本解析。
$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))

# The capability matrix must contain one explicit conclusion for every upstream authentication file.
# 能力矩阵必须为每个上游认证文件包含一条明确结论。
$matrixPath = [System.IO.Path]::GetFullPath((Join-Path $repositoryRoot "docs/architecture/0008-cliproxyapi-provider-capability-matrix.md"))

# The problems collection accumulates all evidence drift in one deterministic pass.
# 问题集合在一次确定性检查中累积全部证据漂移。
$problems = [System.Collections.Generic.List[string]]::new()

# The actual commit is read without modifying the reviewed checkout.
# 实际提交以只读方式从已审核检出目录读取。
$actualCommit = (& git -C $sourceRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0) {
    throw "Unable to read CLIProxyAPI source commit"
}
if ($actualCommit -cne $expectedCommit) {
    $problems.Add("SOURCE_COMMIT expected=$expectedCommit actual=$actualCommit")
}

# The internal authentication root contains provider protocol implementations at the fixed baseline.
# 内部认证根目录包含固定基线上的供应商协议实现。
$authenticationRoot = [System.IO.Path]::GetFullPath((Join-Path $sourceRoot "internal/auth"))

# The source authentication files are normalized to repository-style relative paths.
# 源认证文件被规范化为仓库风格的相对路径。
$authenticationFiles = @(
    Get-ChildItem -LiteralPath $authenticationRoot -Recurse -File -Filter "*.go" |
        ForEach-Object { Get-ValidatedRelativePath -Root $sourceRoot -Child $_.FullName } |
        Sort-Object
)

# The SDK authentication root contains provider login orchestration, Codex device flow, and persistence boundaries.
# SDK 认证根目录包含供应商登录编排、Codex 设备授权与持久化边界。
$sdkAuthenticationRoot = [System.IO.Path]::GetFullPath((Join-Path $sourceRoot "sdk/auth"))

# The SDK authentication files are normalized independently so neither source family can hide omissions in the other.
# SDK 认证文件独立规范化，确保两个源码系列不能互相掩盖遗漏。
$sdkAuthenticationFiles = @(
    Get-ChildItem -LiteralPath $sdkAuthenticationRoot -File -Filter "*.go" |
        ForEach-Object { Get-ValidatedRelativePath -Root $sourceRoot -Child $_.FullName } |
        Sort-Object
)

# The complete authentication evidence inventory joins protocol and SDK orchestration files.
# 完整认证证据清单合并协议文件与 SDK 编排文件。
$allAuthenticationFiles = @($authenticationFiles) + @($sdkAuthenticationFiles)

# The matrix text is parsed only for exact backtick-quoted authentication evidence paths.
# 矩阵文本只解析由反引号包围的精确认证证据路径。
$matrixText = [System.IO.File]::ReadAllText($matrixPath)

# The documented path matches retain duplicates so accidental repeated rows remain detectable.
# 文档路径匹配保留重复项，使意外重复行仍可被发现。
$documentedMatches = [System.Text.RegularExpressions.Regex]::Matches($matrixText, '`(?<path>(?:internal/auth/[^`]+|sdk/auth/[^`]+)\.go)`')

# The documented files form the unique sorted comparison set.
# 已记录文件构成唯一且排序后的对比集合。
$documentedFiles = @(
    $documentedMatches |
        ForEach-Object { $_.Groups["path"].Value } |
        Sort-Object -Unique
)

if ($documentedMatches.Count -ne $documentedFiles.Count) {
    $problems.Add("DUPLICATE_AUTH_MATRIX_ROWS matches=$($documentedMatches.Count) unique=$($documentedFiles.Count)")
}
foreach ($authenticationFile in $allAuthenticationFiles) {
    if ($documentedFiles -notcontains $authenticationFile) {
        $problems.Add("UNDOCUMENTED_AUTH_FILE $authenticationFile")
    }
}
foreach ($documentedFile in $documentedFiles) {
    if ($allAuthenticationFiles -notcontains $documentedFile) {
        $problems.Add("STALE_AUTH_MATRIX_ROW $documentedFile")
    }
}

# The config evidence table names every built-in provider configuration family adapted by Vulcan.
# 配置证据表列出 Vulcan 适配的每个内置供应商配置系列。
$configurationEvidence = @(
    [PSCustomObject]@{ Path = "internal/config/config.go"; Pattern = "type ClaudeKey struct" },
    [PSCustomObject]@{ Path = "internal/config/config.go"; Pattern = "type CodexKey struct" },
    [PSCustomObject]@{ Path = "internal/config/config.go"; Pattern = "type XAIKey = CodexKey" },
    [PSCustomObject]@{ Path = "internal/config/config.go"; Pattern = "type GeminiKey struct" },
    [PSCustomObject]@{ Path = "internal/config/config.go"; Pattern = "InteractionsKey []GeminiKey" },
    [PSCustomObject]@{ Path = "internal/config/config.go"; Pattern = "type OpenAICompatibility struct" },
    [PSCustomObject]@{ Path = "internal/config/vertex_compat.go"; Pattern = "type VertexCompatKey struct" }
)
foreach ($evidence in $configurationEvidence) {
    # The evidence source is an exact reviewed upstream file.
    # 证据源是精确且已审核的上游文件。
    $evidencePath = [System.IO.Path]::GetFullPath((Join-Path $sourceRoot $evidence.Path))
    # The evidence text is compared ordinally to prevent case-insensitive false positives.
    # 证据文本使用序数比较，防止不区分大小写造成误判。
    $evidenceText = [System.IO.File]::ReadAllText($evidencePath)
    if (-not $evidenceText.Contains($evidence.Pattern, [System.StringComparison]::Ordinal)) {
        $problems.Add("MISSING_CONFIG_EVIDENCE $($evidence.Path) :: $($evidence.Pattern)")
    }
}

# The executor registration file is the unique built-in runtime inventory source at this baseline.
# 执行器注册文件是该基线上唯一的内置运行时清单来源。
$executorRegistrationPath = [System.IO.Path]::GetFullPath((Join-Path $sourceRoot "sdk/cliproxy/service.go"))

# The executor registration text is inspected for every native constructor, including the intentionally excluded relay.
# 执行器注册文本检查每个原生构造器，包括有意排除的中继实现。
$executorRegistrationText = [System.IO.File]::ReadAllText($executorRegistrationPath)

# The executor constructors close the native registration inventory without including plugin-provided candidates.
# 执行器构造器封闭原生注册清单，且不包含插件提供的候选项。
$executorConstructors = @(
    "executor.NewCodexAutoExecutor(s.cfg)",
    "executor.NewGeminiExecutor(s.cfg)",
    "executor.NewGeminiInteractionsExecutor(s.cfg)",
    "executor.NewGeminiVertexExecutor(s.cfg)",
    "executor.NewAIStudioExecutor(s.cfg, a.ID, s.wsGateway)",
    "executor.NewAntigravityExecutor(s.cfg)",
    "executor.NewClaudeExecutor(s.cfg)",
    "executor.NewKimiExecutor(s.cfg)",
    "executor.NewXAIAutoExecutor(s.cfg)"
)
foreach ($constructor in $executorConstructors) {
    if (-not $executorRegistrationText.Contains($constructor, [System.StringComparison]::Ordinal)) {
        $problems.Add("MISSING_EXECUTOR_EVIDENCE $constructor")
    }
}

# The copied model assets are the exact source of static model and Codex client capability facts.
# 已复制模型资源是静态模型与 Codex 客户端能力事实的精确来源。
$modelAssets = @(
    "internal/registry/models/models.json",
    "internal/registry/models/codex_client_models.json"
)
foreach ($modelAsset in $modelAssets) {
    # The source asset is the byte-authoritative upstream document.
    # 源资源是字节级权威上游文档。
    $sourceAsset = [System.IO.Path]::GetFullPath((Join-Path $sourceRoot $modelAsset))
    # The target asset is the repository's verbatim evidence copy.
    # 目标资源是仓库中的原样证据副本。
    $targetAsset = [System.IO.Path]::GetFullPath((Join-Path $repositoryRoot (Join-Path "internal/thirdparty/cliproxyapi" $modelAsset)))
    if (-not (Test-Path -LiteralPath $targetAsset -PathType Leaf)) {
        $problems.Add("MISSING_MODEL_ASSET $modelAsset")
        continue
    }
    # The source bytes are never normalized as text.
    # 源字节绝不按文本进行规范化。
    $sourceBytes = [System.IO.File]::ReadAllBytes($sourceAsset)
    # The target bytes must match the source exactly.
    # 目标字节必须与源完全一致。
    $targetBytes = [System.IO.File]::ReadAllBytes($targetAsset)
    if (-not [System.Linq.Enumerable]::SequenceEqual([byte[]]$sourceBytes, [byte[]]$targetBytes)) {
        $problems.Add("CHANGED_MODEL_ASSET $modelAsset")
    }
}

if ($problems.Count -gt 0) {
    $problems | Sort-Object | ForEach-Object { Write-Error $_ }
    exit 1
}

Write-Output ("CLIProxyAPI provider evidence check passed: commit {0}, {1} internal auth files, {2} SDK auth files, {3} config families, {4} executor constructors, {5} model assets" -f $actualCommit, $authenticationFiles.Count, $sdkAuthenticationFiles.Count, $configurationEvidence.Count, $executorConstructors.Count, $modelAssets.Count)
