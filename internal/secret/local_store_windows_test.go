//go:build windows

package secret

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNewLocalStoreUsesWindowsDPAPI verifies the production constructor protects bytes through the Windows DPAPI boundary.
// TestNewLocalStoreUsesWindowsDPAPI 验证生产构造器通过 Windows DPAPI 边界保护字节。
func TestNewLocalStoreUsesWindowsDPAPI(t *testing.T) {
	// directory isolates protected files for this operating-system integration test.
	// directory 为此操作系统集成测试隔离受保护文件。
	directory := t.TempDir()
	store, errStore := NewLocalStore(directory)
	if errStore != nil {
		t.Fatalf("create Windows local secret store: %v", errStore)
	}
	// secretValue is fixture material whose plaintext must not appear in the protected file.
	// secretValue 是不得出现在受保护文件中的夹具材料。
	secretValue := []byte("windows-dpapi-fixture-secret")
	reference, errPut := store.Put(context.Background(), secretValue)
	if errPut != nil {
		t.Fatalf("store DPAPI secret: %v", errPut)
	}
	loadedValue, errGet := store.Get(context.Background(), reference)
	if errGet != nil {
		t.Fatalf("load DPAPI secret: %v", errGet)
	}
	if string(loadedValue) != string(secretValue) {
		t.Fatalf("loaded secret = %q, want %q", loadedValue, secretValue)
	}
	entries, errEntries := os.ReadDir(directory)
	if errEntries != nil || len(entries) != 1 {
		t.Fatalf("protected secret files entries=%d error=%v", len(entries), errEntries)
	}
	protectedBytes, errRead := os.ReadFile(filepath.Join(directory, entries[0].Name()))
	if errRead != nil {
		t.Fatalf("read protected secret file: %v", errRead)
	}
	if strings.Contains(string(protectedBytes), string(secretValue)) {
		t.Fatal("protected DPAPI file contains plaintext secret")
	}
}
