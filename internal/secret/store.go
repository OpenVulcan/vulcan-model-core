// Package secret defines storage boundaries for provider credentials outside business repositories.
// secret 包定义位于业务 Repository 之外的供应商秘密存储边界。
package secret

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
)

var (
	// ErrNotFound reports a missing secret reference.
	// ErrNotFound 表示 Secret 引用不存在。
	ErrNotFound = errors.New("secret not found")
)

// Store persists opaque secret bytes and returns non-secret references.
// Store 持久化不透明 Secret 字节并返回非秘密引用。
type Store interface {
	// Put stores one non-empty secret and returns an opaque reference.
	// Put 保存一个非空 Secret 并返回不透明引用。
	Put(context.Context, []byte) (string, error)
	// Get returns one isolated secret copy by exact reference.
	// Get 按精确引用返回一个隔离的 Secret 副本。
	Get(context.Context, string) ([]byte, error)
	// Delete removes one exact secret reference.
	// Delete 删除一个精确 Secret 引用。
	Delete(context.Context, string) error
}

// MemoryStore is a process-local SecretStore for tests and explicit ephemeral operation.
// MemoryStore 是用于测试和显式临时运行的进程内 SecretStore。
type MemoryStore struct {
	// mu protects secret values and reference generation writes.
	// mu 保护 Secret 值与引用生成写入。
	mu sync.RWMutex
	// values stores isolated secret bytes by opaque reference.
	// values 按不透明引用存储隔离的 Secret 字节。
	values map[string][]byte
}

// NewMemoryStore creates an empty ephemeral SecretStore.
// NewMemoryStore 创建一个空的临时 SecretStore。
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{values: make(map[string][]byte)}
}

// Put stores one secret under a cryptographically random opaque reference.
// Put 使用密码学随机不透明引用保存一个 Secret。
func (s *MemoryStore) Put(ctx context.Context, value []byte) (string, error) {
	if err := contextError(ctx); err != nil {
		return "", err
	}
	if len(value) == 0 {
		return "", errors.New("secret value is required")
	}
	randomBytes := make([]byte, 16)
	if _, errRandom := rand.Read(randomBytes); errRandom != nil {
		return "", fmt.Errorf("generate secret reference: %w", errRandom)
	}
	reference := "secret://memory/" + hex.EncodeToString(randomBytes)
	s.mu.Lock()
	s.values[reference] = append([]byte(nil), value...)
	s.mu.Unlock()
	return reference, nil
}

// Get returns one mutation-safe secret copy.
// Get 返回一个防止外部修改的 Secret 副本。
func (s *MemoryStore) Get(ctx context.Context, reference string) ([]byte, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	s.mu.RLock()
	value, exists := s.values[reference]
	s.mu.RUnlock()
	if !exists {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, reference)
	}
	return append([]byte(nil), value...), nil
}

// Delete removes one secret and reports missing references explicitly.
// Delete 删除一个 Secret，并显式报告缺失引用。
func (s *MemoryStore) Delete(ctx context.Context, reference string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.values[reference]; !exists {
		return fmt.Errorf("%w: %s", ErrNotFound, reference)
	}
	delete(s.values, reference)
	return nil
}

// Count returns the number of ephemeral secrets for lifecycle verification.
// Count 返回用于生命周期验证的临时 Secret 数量。
func (s *MemoryStore) Count() int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.values)
}

// contextError validates one SecretStore operation context.
// contextError 校验一个 SecretStore 操作 Context。
func contextError(ctx context.Context) error {
	if ctx == nil {
		return errors.New("context is required")
	}
	return ctx.Err()
}
