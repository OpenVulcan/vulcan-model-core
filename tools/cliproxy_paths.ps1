# Get-ValidatedRelativePath returns a normalized relative path only when the child is inside the declared root.
# Get-ValidatedRelativePath 仅在子路径位于声明根目录内时返回规范化相对路径。
function Get-ValidatedRelativePath {
    param(
        # Root is the trusted containing directory.
        # Root 是受信任的包含目录。
        [Parameter(Mandatory = $true)][string]$Root,
        # Child is the exact file or directory whose relative path is required.
        # Child 是需要计算相对路径的精确文件或目录。
        [Parameter(Mandatory = $true)][string]$Child
    )

    # rootPrefix includes one separator so sibling paths with the same text prefix cannot pass containment.
    # rootPrefix 包含一个分隔符，避免具有相同文本前缀的同级路径通过包含校验。
    $rootPrefix = [System.IO.Path]::GetFullPath($Root).TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    # childPath is normalized before ordinal filesystem containment comparison.
    # childPath 在执行序数文件系统包含比较前进行规范化。
    $childPath = [System.IO.Path]::GetFullPath($Child)
    if (-not $childPath.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Path is outside the declared root: $childPath"
    }
    return $childPath.Substring($rootPrefix.Length).Replace("\", "/")
}
