package secret

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestLocalStoreRoundTripKeepsProtectedBytesOutOfTheSecretFile verifies the file boundary never stores plaintext.
// TestLocalStoreRoundTripKeepsProtectedBytesOutOfTheSecretFile 验证文件边界绝不存储明文。
func TestLocalStoreRoundTripKeepsProtectedBytesOutOfTheSecretFile(t *testing.T) {
	// directory is isolated so the test can inspect every protected file safely.
	// directory 被隔离，因此测试可以安全检查每一个受保护文件。
	directory := t.TempDir()
	store, errStore := newLocalStore(directory, reversingProtector{})
	if errStore != nil {
		t.Fatalf("newLocalStore() error = %v", errStore)
	}
	// value is an explicit plaintext sentinel that must never appear in the protected file.
	// value 是一个明确的明文哨兵，绝不能出现在受保护文件中。
	value := []byte("upstream-auth-key")
	reference, errPut := store.Put(context.Background(), value)
	if errPut != nil {
		t.Fatalf("Put() error = %v", errPut)
	}
	got, errGet := store.Get(context.Background(), reference)
	if errGet != nil {
		t.Fatalf("Get() error = %v", errGet)
	}
	if string(got) != string(value) {
		t.Fatalf("Get() = %q, want %q", got, value)
	}
	// files contains exactly the opaque protected file emitted by the local store.
	// files 包含本地存储生成的精确不透明受保护文件。
	files, errReadDirectory := os.ReadDir(directory)
	if errReadDirectory != nil {
		t.Fatalf("ReadDir() error = %v", errReadDirectory)
	}
	if len(files) != 1 {
		t.Fatalf("ReadDir() count = %d, want 1", len(files))
	}
	protectedBytes, errRead := os.ReadFile(filepath.Join(directory, files[0].Name()))
	if errRead != nil {
		t.Fatalf("ReadFile() error = %v", errRead)
	}
	if string(protectedBytes) == string(value) {
		t.Fatalf("protected file retained plaintext %q", protectedBytes)
	}
	if errDelete := store.Delete(context.Background(), reference); errDelete != nil {
		t.Fatalf("Delete() error = %v", errDelete)
	}
	if _, errMissing := store.Get(context.Background(), reference); !errors.Is(errMissing, ErrNotFound) {
		t.Fatalf("Get() after Delete() error = %v, want ErrNotFound", errMissing)
	}
}

// TestLocalStoreRejectsTraversalReference verifies opaque SecretRef parsing constrains all file operations.
// TestLocalStoreRejectsTraversalReference 验证不透明 SecretRef 解析约束全部文件操作。
func TestLocalStoreRejectsTraversalReference(t *testing.T) {
	store, errStore := newLocalStore(t.TempDir(), reversingProtector{})
	if errStore != nil {
		t.Fatalf("newLocalStore() error = %v", errStore)
	}
	if _, errGet := store.Get(context.Background(), "secret://local/../../outside"); !errors.Is(errGet, ErrNotFound) {
		t.Fatalf("Get() traversal error = %v, want ErrNotFound", errGet)
	}
	if errDelete := store.Delete(context.Background(), "secret://local/../../outside"); !errors.Is(errDelete, ErrNotFound) {
		t.Fatalf("Delete() traversal error = %v, want ErrNotFound", errDelete)
	}
}

// TestLocalStoreClearsTransientPlaintextCopies verifies protection adapters cannot retain store-owned plaintext buffers after return.
// TestLocalStoreClearsTransientPlaintextCopies 验证保护适配器返回后不能保留存储层拥有的明文缓冲区。
func TestLocalStoreClearsTransientPlaintextCopies(t *testing.T) {
	protector := &retainingProtector{}
	store, errStore := newLocalStore(t.TempDir(), protector)
	if errStore != nil {
		t.Fatalf("newLocalStore() error = %v", errStore)
	}
	original := []byte("sensitive-provider-token")
	reference, errPut := store.Put(context.Background(), original)
	if errPut != nil {
		t.Fatalf("Put() error = %v", errPut)
	}
	if string(original) != "sensitive-provider-token" {
		t.Fatalf("Put() mutated caller-owned bytes: %q", original)
	}
	if !allZero(protector.protectInput) {
		t.Fatalf("Protect() input retained plaintext: %q", protector.protectInput)
	}
	got, errGet := store.Get(context.Background(), reference)
	if errGet != nil {
		t.Fatalf("Get() error = %v", errGet)
	}
	if string(got) != "sensitive-provider-token" {
		t.Fatalf("Get() = %q", got)
	}
	if !allZero(protector.unprotectedOutput) {
		t.Fatalf("Unprotect() output retained plaintext: %q", protector.unprotectedOutput)
	}
}

// allZero reports whether every byte in one retained test buffer was cleared.
// allZero 报告一个被保留的测试缓冲区是否已全部清零。
func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}

// retainingProtector deliberately retains store-owned buffers so tests can observe post-call clearing.
// retainingProtector 有意保留存储层拥有的缓冲区，以便测试观察调用后的清零行为。
type retainingProtector struct {
	// protectInput retains the exact buffer passed to Protect.
	// protectInput 保留传给 Protect 的精确缓冲区。
	protectInput []byte
	// unprotectedOutput retains the exact buffer returned by Unprotect.
	// unprotectedOutput 保留 Unprotect 返回的精确缓冲区。
	unprotectedOutput []byte
}

// Protect retains its input and emits deterministic non-plaintext bytes.
// Protect 保留输入并生成确定性的非明文字节。
func (p *retainingProtector) Protect(value []byte) ([]byte, error) {
	p.protectInput = value
	return []byte("protected-payload"), nil
}

// Unprotect returns one retained plaintext buffer for the store to copy and clear.
// Unprotect 返回一个被保留的明文缓冲区，供存储层复制并清零。
func (p *retainingProtector) Unprotect([]byte) ([]byte, error) {
	p.unprotectedOutput = []byte("sensitive-provider-token")
	return p.unprotectedOutput, nil
}

// reversingProtector is a deterministic test-only protector that proves LocalStore uses its protection boundary.
// reversingProtector 是确定性的仅测试保护器，用于证明 LocalStore 使用其保护边界。
type reversingProtector struct{}

// Protect reverses test bytes and prefixes a marker so plaintext equality cannot pass accidentally.
// Protect 反转测试字节并添加标记，因此无法意外通过明文相等性。
func (reversingProtector) Protect(value []byte) ([]byte, error) {
	// protectedValue reserves one marker byte plus the original payload length.
	// protectedValue 预留一个标记字节和原始载荷长度。
	protectedValue := make([]byte, len(value)+1)
	protectedValue[0] = 0xA5
	for index := range value {
		protectedValue[index+1] = value[len(value)-index-1]
	}
	return protectedValue, nil
}

// Unprotect validates the test marker and restores the original test bytes.
// Unprotect 校验测试标记并恢复原始测试字节。
func (reversingProtector) Unprotect(value []byte) ([]byte, error) {
	if len(value) == 0 || value[0] != 0xA5 {
		return nil, errors.New("invalid protected test payload")
	}
	// plainValue mirrors Protect and remains isolated from the file bytes.
	// plainValue 与 Protect 对应并保持与文件字节隔离。
	plainValue := make([]byte, len(value)-1)
	for index := range plainValue {
		plainValue[index] = value[len(value)-index-1]
	}
	return plainValue, nil
}
