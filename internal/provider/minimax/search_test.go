package minimax

import "testing"

// TestMiniMaxSearchPublishedAtUsesPinnedDateShape verifies exact date normalization without heuristic parsing.
// TestMiniMaxSearchPublishedAtUsesPinnedDateShape 验证精确日期规范化且不使用启发式解析。
func TestMiniMaxSearchPublishedAtUsesPinnedDateShape(t *testing.T) {
	publishedAt, errParse := miniMaxSearchPublishedAt("2024-01-01")
	if errParse != nil || publishedAt == nil || publishedAt.Format("2006-01-02T15:04:05Z07:00") != "2024-01-01T00:00:00Z" {
		t.Fatalf("miniMaxSearchPublishedAt() = %v, %v", publishedAt, errParse)
	}
	if _, errParse := miniMaxSearchPublishedAt("January 1, 2024"); errParse == nil {
		t.Fatal("expected unproved date shape to be rejected")
	}
	if publishedAt, errParse := miniMaxSearchPublishedAt(""); errParse != nil || publishedAt != nil {
		t.Fatalf("empty date = %v, %v", publishedAt, errParse)
	}
}
