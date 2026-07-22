package resource

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ObjectStore owns opaque resource bytes independently from metadata persistence.
// ObjectStore 独立于元数据持久化管理不透明资源字节。
type ObjectStore interface {
	// Publish atomically creates one immutable object from a completed local staging file.
	// Publish 从已完成的本地暂存文件原子创建一个不可变对象。
	Publish(context.Context, string, string) error
	// Open returns a readable immutable object.
	// Open 返回一个可读取的不可变对象。
	Open(context.Context, string) (io.ReadCloser, error)
	// Delete idempotently removes one immutable object.
	// Delete 幂等删除一个不可变对象。
	Delete(context.Context, string) error
}

// LocalObjectStore stores immutable objects below one resolved private directory.
// LocalObjectStore 在一个已解析私有目录下存储不可变对象。
type LocalObjectStore struct {
	// root is the absolute boundary used for every object-key resolution.
	// root 是用于解析每个对象键的绝对边界。
	root string
}

// NewLocalObjectStore creates one filesystem-backed object store.
// NewLocalObjectStore 创建一个文件系统支持的对象存储。
func NewLocalObjectStore(root string) (*LocalObjectStore, error) {
	absRoot, errAbsolute := filepath.Abs(strings.TrimSpace(root))
	if errAbsolute != nil || strings.TrimSpace(root) == "" {
		return nil, fmt.Errorf("%w: local object root is required", ErrInvalidResource)
	}
	if errCreate := os.MkdirAll(absRoot, 0o700); errCreate != nil {
		return nil, fmt.Errorf("create local object root: %w", errCreate)
	}
	return &LocalObjectStore{root: absRoot}, nil
}

// Publish atomically moves a completed same-volume staging file into its immutable key.
// Publish 将已完成的同卷暂存文件原子移动到其不可变键。
func (s *LocalObjectStore) Publish(ctx context.Context, objectKey string, sourcePath string) error {
	if errContext := contextError(ctx); errContext != nil {
		return errContext
	}
	targetPath, errTarget := s.resolve(objectKey)
	if errTarget != nil {
		return errTarget
	}
	if strings.TrimSpace(sourcePath) == "" {
		return fmt.Errorf("%w: staging path is required", ErrInvalidResource)
	}
	if errCreate := os.MkdirAll(filepath.Dir(targetPath), 0o700); errCreate != nil {
		return fmt.Errorf("create object shard: %w", errCreate)
	}
	if _, errStat := os.Stat(targetPath); errStat == nil || !errors.Is(errStat, os.ErrNotExist) {
		return ErrResourceConflict
	}
	if errRename := os.Rename(sourcePath, targetPath); errRename != nil {
		return fmt.Errorf("publish local object: %w", errRename)
	}
	return nil
}

// Open opens one object after resolving its key inside the configured boundary.
// Open 在配置边界内解析对象键后打开对象。
func (s *LocalObjectStore) Open(ctx context.Context, objectKey string) (io.ReadCloser, error) {
	if errContext := contextError(ctx); errContext != nil {
		return nil, errContext
	}
	targetPath, errTarget := s.resolve(objectKey)
	if errTarget != nil {
		return nil, errTarget
	}
	content, errOpen := os.Open(targetPath)
	if errOpen != nil {
		return nil, fmt.Errorf("open local object: %w", errOpen)
	}
	return content, nil
}

// Delete removes one object and treats an already absent key as success.
// Delete 删除一个对象，并将已经不存在的键视为成功。
func (s *LocalObjectStore) Delete(ctx context.Context, objectKey string) error {
	if errContext := contextError(ctx); errContext != nil {
		return errContext
	}
	targetPath, errTarget := s.resolve(objectKey)
	if errTarget != nil {
		return errTarget
	}
	if errRemove := os.Remove(targetPath); errRemove != nil && !errors.Is(errRemove, os.ErrNotExist) {
		return fmt.Errorf("delete local object: %w", errRemove)
	}
	return nil
}

// resolve converts one opaque key into a path that cannot escape the store root.
// resolve 将一个不透明键转换为不可逃逸存储根目录的路径。
func (s *LocalObjectStore) resolve(objectKey string) (string, error) {
	if s == nil || strings.TrimSpace(objectKey) == "" {
		return "", fmt.Errorf("%w: object key is required", ErrInvalidResource)
	}
	cleanKey := filepath.Clean(filepath.FromSlash(objectKey))
	targetPath := filepath.Join(s.root, cleanKey)
	relative, errRelative := filepath.Rel(s.root, targetPath)
	if errRelative != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return "", fmt.Errorf("%w: object key escapes object store", ErrInvalidResource)
	}
	return targetPath, nil
}
