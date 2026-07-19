# The source root points at the fixed CLIProxyAPI checkout used for comparison.
# 源根目录指向用于对比的固定 CLIProxyAPI 检出目录。
$sourceRoot = [System.IO.Path]::GetFullPath("D:/openvulcan/third_git/CLIProxyAPI")

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "cliproxy_paths.ps1")

# The repository root is resolved from this comparison script.
# 仓库根目录根据当前对比脚本解析。
$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))

# The target root contains only mechanically synchronized upstream files plus documented local adapters.
# 目标根目录仅包含机械同步的上游文件及已记录的本地适配。
$targetRoot = [System.IO.Path]::GetFullPath((Join-Path $repositoryRoot "internal/thirdparty/cliproxyapi"))

# The package list must match the reviewed build dependency closure in the synchronization script.
# 包列表必须与同步脚本中审核过的构建依赖闭包一致。
$packagePaths = @(
    "sdk/translator",
    "internal/constant",
    "internal/interfaces",
    "internal/misc",
    "internal/registry",
    "internal/signature",
    "internal/thinking",
    "internal/httpfetch",
    "internal/pluginstore",
    "sdk/pluginstore",
    "internal/config",
    "sdk/config",
    "sdk/proxyutil",
    "internal/util",
    "internal/translator/common",
    "internal/translator/translator",
    "internal/translator/claude/openai/responses",
    "internal/translator/codex/openai/responses",
    "internal/translator/openai/interactions/responses",
    "internal/translator/gemini/common",
    "internal/translator/antigravity/gemini",
    "internal/translator/gemini/openai/responses",
    "internal/translator/antigravity/openai/responses"
)

# The test package set identifies the upstream regression suites copied verbatim.
# 测试包集合标识原样复制的上游回归测试套件。
$testPackagePaths = @(
    "sdk/translator",
    "internal/translator/claude/openai/responses",
    "internal/translator/codex/openai/responses",
    "internal/translator/openai/interactions/responses",
    "internal/translator/antigravity/openai/responses"
)

# The upstream asset list contains every non-Go file retained in the exact copied subtree.
# 上游资源列表包含原样复制子树中保留的每个非 Go 文件。
$upstreamAssetPaths = @(
    "internal/registry/models/codex_client_models.json",
    "internal/registry/models/models.json",
    "LICENSE"
)

# The upstream prefix is normalized before byte comparison.
# 上游前缀在字节对比前进行规范化。
$upstreamModulePrefix = "github.com/router-for-me/CLIProxyAPI/v7/"

# The local prefix is the sole accepted source-code difference.
# 本地前缀是唯一接受的源码差异。
$localModulePrefix = "github.com/OpenVulcan/vulcan-model-core/internal/thirdparty/cliproxyapi/"

# The expected file map records every synchronized relative path and normalized content.
# 预期文件映射记录每个同步相对路径及规范化内容。
$expectedFiles = @{}

foreach ($packagePath in $packagePaths) {
    # The package source is an explicit member of the reviewed closure.
    # 包源路径是已审核闭包中的明确成员。
    $packageSource = [System.IO.Path]::GetFullPath((Join-Path $sourceRoot $packagePath))
    foreach ($sourceFile in Get-ChildItem -LiteralPath $packageSource -File) {
        if ($sourceFile.Name.EndsWith("_test.go") -and $testPackagePaths -notcontains $packagePath) {
            continue
        }
        # The relative path is stable across source and target roots.
        # 相对路径在源根目录和目标根目录之间保持稳定。
        $relativePath = Get-ValidatedRelativePath -Root $sourceRoot -Child $sourceFile.FullName
        if ($sourceFile.Extension -eq ".go") {
            # The expected text applies only the documented module-prefix rewrite.
            # 预期文本仅应用已记录的模块前缀替换。
            $expectedFiles[$relativePath] = [System.IO.File]::ReadAllText($sourceFile.FullName).Replace($upstreamModulePrefix, $localModulePrefix)
        } else {
            $expectedFiles[$relativePath] = [System.IO.File]::ReadAllBytes($sourceFile.FullName)
        }
    }
}

foreach ($upstreamAssetPath in $upstreamAssetPaths) {
    # Upstream asset bytes must remain exactly identical.
    # 上游资源字节必须保持完全一致。
    $expectedFiles[$upstreamAssetPath] = [System.IO.File]::ReadAllBytes((Join-Path $sourceRoot $upstreamAssetPath))
}

# The sole local file inside the copied root is an inert registration shim required by Go internal-package visibility.
# 复制根目录内唯一的本地文件是 Go 内部包可见性所需的无业务逻辑注册垫片。
$registerTemplate = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "cliproxy_register.go.txt"))
$expectedFiles["register/register.go"] = [System.IO.File]::ReadAllText($registerTemplate)

# The problems collection accumulates every missing or changed upstream file in one pass.
# 问题集合在一次检查中累积所有缺失或变化的上游文件。
$problems = [System.Collections.Generic.List[string]]::new()

foreach ($relativePath in $expectedFiles.Keys) {
    # The target file is resolved only beneath the fixed third-party root.
    # 目标文件仅在固定第三方根目录下解析。
    $targetFile = [System.IO.Path]::GetFullPath((Join-Path $targetRoot $relativePath))
    if (-not (Test-Path -LiteralPath $targetFile -PathType Leaf)) {
        $problems.Add("MISSING $relativePath")
        continue
    }
    $expected = $expectedFiles[$relativePath]
    if ($expected -is [byte[]]) {
        # The actual binary bytes are compared without text normalization.
        # 实际二进制字节不经过文本规范化直接比较。
        $actualBytes = [System.IO.File]::ReadAllBytes($targetFile)
        if (-not [System.Linq.Enumerable]::SequenceEqual([byte[]]$expected, [byte[]]$actualBytes)) {
            $problems.Add("CHANGED $relativePath")
        }
        continue
    }
    # The actual Go text must match the mechanically normalized upstream source exactly.
    # 实际 Go 文本必须与机械规范化后的上游源码完全一致。
    $actualText = [System.IO.File]::ReadAllText($targetFile)
    if ($actualText -cne $expected) {
        $problems.Add("CHANGED $relativePath")
    }
}

# The actual file set is closed so an unreviewed local Go file cannot alter copied behavior without failing comparison.
# 实际文件集合保持封闭，防止未审核的本地 Go 文件改变复制行为而未触发对比失败。
$actualFiles = @(
    Get-ChildItem -LiteralPath $targetRoot -Recurse -File |
        ForEach-Object { Get-ValidatedRelativePath -Root $targetRoot -Child $_.FullName } |
        Sort-Object
)
foreach ($actualFile in $actualFiles) {
    if (-not $expectedFiles.ContainsKey($actualFile)) {
        $problems.Add("EXTRA $actualFile")
    }
}

if ($problems.Count -gt 0) {
    $problems | Sort-Object | ForEach-Object { Write-Error $_ }
    exit 1
}

Write-Output ("CLIProxyAPI protocol source comparison passed: {0} files" -f $expectedFiles.Count)
