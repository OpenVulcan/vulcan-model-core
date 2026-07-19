// Command check_bilingual_go_comments validates the repository's required English-first and Chinese-second declaration comments.
// Command check_bilingual_go_comments 校验仓库要求的声明注释：英文第一行、中文第二行。
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
)

// documentationIssue identifies one declaration whose bilingual comment contract is incomplete.
// documentationIssue 标识一个双语注释合同不完整的声明。
type documentationIssue struct {
	// path is the inspected Go source file.
	// path 是接受检查的 Go 源文件。
	path string
	// line is the declaration's one-based source line.
	// line 是声明在源码中的一基行号。
	line int
	// declaration is the stable declaration description used in diagnostics.
	// declaration 是诊断中使用的稳定声明描述。
	declaration string
	// reason explains the exact comment-contract violation.
	// reason 说明精确的注释合同违规原因。
	reason string
}

// main scans explicit files or the repository tree and exits unsuccessfully when any declaration comment violates the contract.
// main 扫描显式文件或仓库目录树，并在任一声明注释违反合同时以失败状态退出。
func main() {
	paths, errPaths := sourcePaths(os.Args[1:])
	if errPaths != nil {
		fmt.Fprintln(os.Stderr, errPaths)
		os.Exit(2)
	}
	issues := make([]documentationIssue, 0)
	for _, path := range paths {
		fileIssues, errCheck := inspectFile(path)
		if errCheck != nil {
			fmt.Fprintln(os.Stderr, errCheck)
			os.Exit(2)
		}
		issues = append(issues, fileIssues...)
	}
	sort.Slice(issues, func(left int, right int) bool {
		if issues[left].path != issues[right].path {
			return issues[left].path < issues[right].path
		}
		return issues[left].line < issues[right].line
	})
	if len(issues) > 0 {
		for _, issue := range issues {
			fmt.Fprintf(os.Stderr, "%s:%d: %s: %s\n", issue.path, issue.line, issue.declaration, issue.reason)
		}
		os.Exit(1)
	}
	fmt.Printf("Bilingual Go declaration comment check passed: %d files\n", len(paths))
}

// sourcePaths resolves explicit Go files or discovers repository files while excluding the verbatim third-party subtree.
// sourcePaths 解析显式 Go 文件，或发现仓库文件并排除必须保持原样的第三方子树。
func sourcePaths(arguments []string) ([]string, error) {
	if len(arguments) > 0 {
		paths := make([]string, 0, len(arguments))
		for _, argument := range arguments {
			path, errPath := filepath.Abs(argument)
			if errPath != nil {
				return nil, fmt.Errorf("resolve Go source path %q: %w", argument, errPath)
			}
			if filepath.Ext(path) != ".go" {
				continue
			}
			paths = append(paths, path)
		}
		sort.Strings(paths)
		return paths, nil
	}
	root, errRoot := os.Getwd()
	if errRoot != nil {
		return nil, fmt.Errorf("resolve repository root: %w", errRoot)
	}
	paths := make([]string, 0)
	errWalk := filepath.WalkDir(root, func(path string, entry os.DirEntry, errEntry error) error {
		if errEntry != nil {
			return errEntry
		}
		relativePath, errRelative := filepath.Rel(root, path)
		if errRelative != nil {
			return errRelative
		}
		normalizedPath := filepath.ToSlash(relativePath)
		if entry.IsDir() && excludedDirectory(normalizedPath) {
			return filepath.SkipDir
		}
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".go" {
			return nil
		}
		paths = append(paths, path)
		return nil
	})
	if errWalk != nil {
		return nil, fmt.Errorf("discover Go source files: %w", errWalk)
	}
	sort.Strings(paths)
	return paths, nil
}

// excludedDirectory reports whether one repository-relative directory is generated, external, or intentionally verbatim.
// excludedDirectory 报告一个仓库相对目录是否属于生成内容、外部内容或必须原样保留的内容。
func excludedDirectory(path string) bool {
	return path == ".git" || path == "output" || path == "web2/manage/node_modules" || path == "internal/thirdparty/cliproxyapi" ||
		strings.HasPrefix(path, ".git/") || strings.HasPrefix(path, "output/") || strings.HasPrefix(path, "web2/manage/node_modules/") || strings.HasPrefix(path, "internal/thirdparty/cliproxyapi/")
}

// inspectFile parses one Go file and checks declarations and named struct or interface fields.
// inspectFile 解析一个 Go 文件并检查声明以及具名结构或接口字段。
func inspectFile(path string) ([]documentationIssue, error) {
	fileSet := token.NewFileSet()
	file, errParse := parser.ParseFile(fileSet, path, nil, parser.ParseComments)
	if errParse != nil {
		return nil, fmt.Errorf("parse %s: %w", path, errParse)
	}
	issues := make([]documentationIssue, 0)
	for _, declaration := range file.Decls {
		switch typedDeclaration := declaration.(type) {
		case *ast.FuncDecl:
			issues = appendDocumentationIssue(issues, path, fileSet.Position(typedDeclaration.Pos()).Line, "function "+typedDeclaration.Name.Name, typedDeclaration.Doc)
		case *ast.GenDecl:
			issues = inspectGeneralDeclaration(issues, path, fileSet, typedDeclaration)
		}
	}
	ast.Inspect(file, func(node ast.Node) bool {
		switch typedNode := node.(type) {
		case *ast.StructType:
			issues = inspectFields(issues, path, fileSet, typedNode.Fields.List, "field")
		case *ast.InterfaceType:
			issues = inspectFields(issues, path, fileSet, typedNode.Methods.List, "interface method")
		}
		return true
	})
	return issues, nil
}

// inspectGeneralDeclaration checks package-level types, variables, and constants using their closest documentation group.
// inspectGeneralDeclaration 使用最近的文档组检查包级类型、变量和常量。
func inspectGeneralDeclaration(issues []documentationIssue, path string, fileSet *token.FileSet, declaration *ast.GenDecl) []documentationIssue {
	for _, specification := range declaration.Specs {
		switch typedSpecification := specification.(type) {
		case *ast.TypeSpec:
			documentation := typedSpecification.Doc
			if documentation == nil && len(declaration.Specs) == 1 {
				documentation = declaration.Doc
			}
			issues = appendDocumentationIssue(issues, path, fileSet.Position(typedSpecification.Pos()).Line, "type "+typedSpecification.Name.Name, documentation)
		case *ast.ValueSpec:
			documentation := typedSpecification.Doc
			if documentation == nil && len(declaration.Specs) == 1 {
				documentation = declaration.Doc
			}
			for _, name := range typedSpecification.Names {
				issues = appendDocumentationIssue(issues, path, fileSet.Position(name.Pos()).Line, strings.ToLower(declaration.Tok.String())+" "+name.Name, documentation)
			}
		}
	}
	return issues
}

// inspectFields checks named struct fields and named interface methods while permitting intentional anonymous embedding.
// inspectFields 检查具名结构字段与具名接口方法，同时允许有意的匿名嵌入。
func inspectFields(issues []documentationIssue, path string, fileSet *token.FileSet, fields []*ast.Field, kind string) []documentationIssue {
	for _, field := range fields {
		if len(field.Names) == 0 {
			continue
		}
		documentation := field.Doc
		if documentation == nil {
			documentation = field.Comment
		}
		for _, name := range field.Names {
			issues = appendDocumentationIssue(issues, path, fileSet.Position(name.Pos()).Line, kind+" "+name.Name, documentation)
		}
	}
	return issues
}

// appendDocumentationIssue validates one comment group's first two non-empty lines and appends a precise diagnostic when invalid.
// appendDocumentationIssue 校验一个注释组的前两条非空行，并在无效时追加精确诊断。
func appendDocumentationIssue(issues []documentationIssue, path string, line int, declaration string, documentation *ast.CommentGroup) []documentationIssue {
	if documentation == nil {
		return append(issues, documentationIssue{path: path, line: line, declaration: declaration, reason: "missing bilingual documentation"})
	}
	lines := make([]string, 0)
	for _, lineText := range strings.Split(documentation.Text(), "\n") {
		if trimmed := strings.TrimSpace(lineText); trimmed != "" {
			lines = append(lines, trimmed)
		}
	}
	if len(lines) < 2 {
		return append(issues, documentationIssue{path: path, line: line, declaration: declaration, reason: "documentation must contain English and Chinese lines"})
	}
	if containsHan(lines[0]) {
		return append(issues, documentationIssue{path: path, line: line, declaration: declaration, reason: "first documentation line must be English"})
	}
	if !containsHan(lines[1]) {
		return append(issues, documentationIssue{path: path, line: line, declaration: declaration, reason: "second documentation line must be Chinese"})
	}
	return issues
}

// containsHan reports whether text includes at least one Han character.
// containsHan 报告文本是否至少包含一个汉字。
func containsHan(value string) bool {
	return strings.IndexFunc(value, func(character rune) bool {
		return unicode.Is(unicode.Han, character)
	}) >= 0
}
