package secret

import (
	"context"
	"testing"
)

// TestMemoryStoreDeleteClearsOwnedBytes verifies ephemeral deletion clears the removed backing buffer before dropping its reference.
// TestMemoryStoreDeleteClearsOwnedBytes 验证临时存储删除时会在丢弃引用前清零被移除的底层缓冲区。
func TestMemoryStoreDeleteClearsOwnedBytes(t *testing.T) {
	store := NewMemoryStore()
	reference, errPut := store.Put(context.Background(), []byte("ephemeral-secret"))
	if errPut != nil {
		t.Fatalf("Put() error = %v", errPut)
	}
	store.mu.RLock()
	retained := store.values[reference]
	store.mu.RUnlock()
	if errDelete := store.Delete(context.Background(), reference); errDelete != nil {
		t.Fatalf("Delete() error = %v", errDelete)
	}
	if !allZero(retained) {
		t.Fatalf("Delete() retained plaintext bytes: %q", retained)
	}
}
