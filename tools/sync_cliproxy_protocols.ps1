# The source root points at the reviewed CLIProxyAPI checkout.
# 源根目录指向已审核的 CLIProxyAPI 检出目录。
$sourceRoot = [System.IO.Path]::GetFullPath("D:/openvulcan/third_git/CLIProxyAPI")

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "cliproxy_paths.ps1")

# The repository root is resolved from this synchronization script.
# 仓库根目录根据当前同步脚本解析。
$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))

# The target root isolates mechanically synchronized third-party source.
# 目标根目录隔离机械同步的第三方源码。
$targetRoot = [System.IO.Path]::GetFullPath((Join-Path $repositoryRoot "internal/thirdparty/cliproxyapi"))

# The expected target prefix prevents writes outside this repository.
# 预期目标前缀用于阻止写入当前仓库之外的位置。
$expectedTargetPrefix = [System.IO.Path]::GetFullPath((Join-Path $repositoryRoot "internal/thirdparty"))

if (-not (Test-Path -LiteralPath $sourceRoot -PathType Container)) {
    throw "CLIProxyAPI source root does not exist: $sourceRoot"
}

if (-not $targetRoot.StartsWith($expectedTargetPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to synchronize outside the third-party source root: $targetRoot"
}

if (Test-Path -LiteralPath $targetRoot) {
    # The generated target is removed only after its absolute path is validated inside the repository.
    # 仅在生成目标的绝对路径确认位于仓库内部后才删除该目录。
    Remove-Item -LiteralPath $targetRoot -Recurse -Force
}

# The package list is the complete build dependency closure of the four migrated translators.
# 包列表是四个迁移转换器的完整构建依赖闭包。
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

# The test package set preserves upstream regression suites at protocol boundaries.
# 测试包集合保留协议边界处的上游回归测试套件。
$testPackagePaths = @(
    "sdk/translator",
    "internal/translator/claude/openai/responses",
    "internal/translator/codex/openai/responses",
    "internal/translator/openai/interactions/responses",
    "internal/translator/antigravity/openai/responses"
)

# The upstream module prefix is the only mechanical import-path replacement.
# 上游模块前缀是唯一允许的机械导入路径替换。
$upstreamModulePrefix = "github.com/router-for-me/CLIProxyAPI/v7/"

# The local module prefix keeps the copied source inside the Vulcan module.
# 本地模块前缀确保复制源码位于 Vulcan 模块内部。
$localModulePrefix = "github.com/OpenVulcan/vulcan-model-core/internal/thirdparty/cliproxyapi/"

New-Item -ItemType Directory -Force -Path $targetRoot | Out-Null

foreach ($packagePath in $packagePaths) {
    # The package source path is an explicit member of the reviewed dependency closure.
    # 包源路径是已审核依赖闭包中的明确成员。
    $packageSource = [System.IO.Path]::GetFullPath((Join-Path $sourceRoot $packagePath))

    # The package target mirrors the upstream package-relative path.
    # 包目标路径镜像上游包相对路径。
    $packageTarget = [System.IO.Path]::GetFullPath((Join-Path $targetRoot $packagePath))

    if (-not (Test-Path -LiteralPath $packageSource -PathType Container)) {
        throw "CLIProxyAPI package does not exist: $packageSource"
    }

    New-Item -ItemType Directory -Force -Path $packageTarget | Out-Null

    # The copied file set includes embedded assets and selected upstream tests.
    # 复制文件集合包含嵌入资源和选定的上游测试。
    $sourceFiles = Get-ChildItem -LiteralPath $packageSource -File
    foreach ($sourceFile in $sourceFiles) {
        # The relative file path preserves embedded-resource directory layout.
        # 相对文件路径保留嵌入资源目录结构。
        $relativeFile = Get-ValidatedRelativePath -Root $packageSource -Child $sourceFile.FullName

        if ($sourceFile.Name.EndsWith("_test.go") -and $testPackagePaths -notcontains $packagePath) {
            continue
        }

        # The target file is constrained to the already validated package target.
        # 目标文件被限制在已经验证的包目标路径内。
        $targetFile = [System.IO.Path]::GetFullPath((Join-Path $packageTarget $relativeFile))

        New-Item -ItemType Directory -Force -Path ([System.IO.Path]::GetDirectoryName($targetFile)) | Out-Null
        Copy-Item -LiteralPath $sourceFile.FullName -Destination $targetFile -Force

        if ($sourceFile.Extension -eq ".go") {
            # The Go source text remains upstream-identical except for the module import prefix.
            # Go 源码文本除模块导入前缀外保持与上游一致。
            $sourceText = [System.IO.File]::ReadAllText($targetFile)
            $rewrittenText = $sourceText.Replace($upstreamModulePrefix, $localModulePrefix)
            [System.IO.File]::WriteAllText($targetFile, $rewrittenText, [System.Text.UTF8Encoding]::new($false))
        }
    }
}

# The embedded asset list contains non-source files referenced by go:embed directives.
# 嵌入资源列表包含 go:embed 指令引用的非源码文件。
$embeddedAssetPaths = @(
    "internal/registry/models/codex_client_models.json",
    "internal/registry/models/models.json"
)

foreach ($embeddedAssetPath in $embeddedAssetPaths) {
    # The embedded source path is an explicit reviewed upstream asset.
    # 嵌入资源源路径是经过明确审核的上游资源。
    $embeddedSource = [System.IO.Path]::GetFullPath((Join-Path $sourceRoot $embeddedAssetPath))

    # The embedded target path preserves the go:embed relative location.
    # 嵌入资源目标路径保留 go:embed 所需的相对位置。
    $embeddedTarget = [System.IO.Path]::GetFullPath((Join-Path $targetRoot $embeddedAssetPath))

    New-Item -ItemType Directory -Force -Path ([System.IO.Path]::GetDirectoryName($embeddedTarget)) | Out-Null
    Copy-Item -LiteralPath $embeddedSource -Destination $embeddedTarget -Force
}

# The copied license satisfies the upstream MIT redistribution condition.
# 复制许可证用于满足上游 MIT 再分发条件。
Copy-Item -LiteralPath (Join-Path $sourceRoot "LICENSE") -Destination (Join-Path $targetRoot "LICENSE") -Force
