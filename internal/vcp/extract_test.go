package vcp

import (
	"math"
	"testing"
)

// TestWebExtractOperationValidatesDocumentedBoundaries verifies URLs, relevance chunks, enums, and timeouts.
// TestWebExtractOperationValidatesDocumentedBoundaries 校验 URL、相关性片段、枚举与超时的文档边界。
func TestWebExtractOperationValidatesDocumentedBoundaries(t *testing.T) {
	chunks := 3
	timeout := 12.5
	valid := WebExtractOperation{URLs: []string{"https://example.com/a", "https://example.org/b"}, Query: "router", ChunksPerSource: &chunks, Depth: WebExtractDepthAdvanced, Format: WebExtractFormatText, IncludeImages: true, IncludeFavicon: true, TimeoutSeconds: &timeout}
	if errValidate := valid.Validate(); errValidate != nil {
		t.Fatalf("Validate() error = %v", errValidate)
	}
	invalidTimeout := math.NaN()
	tests := []WebExtractOperation{
		{},
		{URLs: []string{"http://example.com"}},
		{URLs: []string{"https://user:secret@example.com"}},
		{URLs: []string{"https://example.com", "https://example.com"}},
		{URLs: []string{"https://example.com"}, ChunksPerSource: &chunks},
		{URLs: []string{"https://example.com"}, Query: "router", ChunksPerSource: integerPointer(6)},
		{URLs: []string{"https://example.com"}, Depth: "future"},
		{URLs: []string{"https://example.com"}, Format: "html"},
		{URLs: []string{"https://example.com"}, TimeoutSeconds: &invalidTimeout},
	}
	for index, operation := range tests {
		if errValidate := operation.Validate(); errValidate == nil {
			t.Fatalf("invalid operation %d unexpectedly passed", index)
		}
	}
}

// integerPointer returns an isolated integer pointer for validation fixtures.
// integerPointer 为校验样本返回独立的整数指针。
func integerPointer(value int) *int { return &value }
