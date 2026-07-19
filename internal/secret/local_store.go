package secret

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	// localReferencePrefix namespaces references owned by the platform-protected local store.
	// localReferencePrefix 为平台保护的本地存储拥有的引用划分命名空间。
	localReferencePrefix = "secret://local/"
	// localSecretSuffix keeps protected files distinct from configuration and catalog files.
	// localSecretSuffix 使受保护文件与配置和目录文件保持区分。
	localSecretSuffix = ".vulcan-secret"
)

var (
	// ErrSecretDirectoryRequired reports an empty local SecretStore directory.
	// ErrSecretDirectoryRequired 表示本地 SecretStore 目录为空。
	ErrSecretDirectoryRequired = errors.New("secret directory is required")
	// ErrPlatformSecretStoreUnavailable reports a platform without an approved protection provider.
	// ErrPlatformSecretStoreUnavailable 表示当前平台没有获准的保护提供者。
	ErrPlatformSecretStoreUnavailable = errors.New("platform secret store is unavailable")
)

// protector encrypts and decrypts opaque secret bytes using an operating-system protection boundary.
// protector 使用操作系统保护边界加密和解密不透明 Secret 字节。
type protector interface {
	// Protect encrypts one plaintext secret for durable storage.
	// Protect 加密一个明文 Secret 以便持久化存储。
	Protect([]byte) ([]byte, error)
	// Unprotect decrypts one durable protected secret.
	// Unprotect 解密一个持久化受保护 Secret。
	Unprotect([]byte) ([]byte, error)
}

// LocalStore persists each provider secret in a platform-protected local file.
// LocalStore 将每个供应商 Secret 持久化到受平台保护的本地文件。
type LocalStore struct {
	// mu serializes local reference allocation and destructive file operations.
	// mu 串行化本地引用分配和破坏性文件操作。
	mu sync.RWMutex
	// directory contains only protected secret files owned by this store.
	// directory 仅包含此存储拥有的受保护 Secret 文件。
	directory string
	// protector owns the operating-system encryption and decryption boundary.
	// protector 管理操作系统加密和解密边界。
	protector protector
}

// NewLocalStore creates the durable platform-protected SecretStore used by the local process.
// NewLocalStore 创建本地进程使用的持久化平台保护 SecretStore。
func NewLocalStore(directory string) (*LocalStore, error) {
	// platformProtector is resolved explicitly so unsupported systems never fall back to plaintext.
	// platformProtector 被显式解析，因此不受支持的系统绝不会回退到明文。
	platformProtector, errProtector := newPlatformProtector()
	if errProtector != nil {
		return nil, errProtector
	}
	return newLocalStore(directory, platformProtector)
}

// newLocalStore creates one LocalStore with an injected protector for platform code and focused tests.
// newLocalStore 使用注入的保护器为平台代码和聚焦测试创建一个 LocalStore。
func newLocalStore(directory string, localProtector protector) (*LocalStore, error) {
	// normalizedDirectory is cleaned before it becomes the only file-system ownership root.
	// normalizedDirectory 在成为唯一文件系统归属根之前先完成清理。
	normalizedDirectory := strings.TrimSpace(directory)
	if normalizedDirectory == "" {
		return nil, ErrSecretDirectoryRequired
	}
	if localProtector == nil {
		return nil, errors.New("secret protector is required")
	}
	if errDirectory := os.MkdirAll(normalizedDirectory, 0o700); errDirectory != nil {
		return nil, fmt.Errorf("create secret directory: %w", errDirectory)
	}
	return &LocalStore{directory: filepath.Clean(normalizedDirectory), protector: localProtector}, nil
}

// Put protects one non-empty secret and returns an opaque same-user local reference.
// Put 保护一个非空 Secret 并返回不透明的同用户本地引用。
func (s *LocalStore) Put(ctx context.Context, value []byte) (string, error) {
	if errContext := contextError(ctx); errContext != nil {
		return "", errContext
	}
	if len(value) == 0 {
		return "", errors.New("secret value is required")
	}
	// plaintextCopy isolates caller ownership and is cleared immediately after the platform protection call completes.
	// plaintextCopy 隔离调用方所有权，并在平台保护调用完成后立即清零。
	plaintextCopy := append([]byte(nil), value...)
	defer clear(plaintextCopy)
	// protectedValue is created before reference allocation so a failed platform call creates no file.
	// protectedValue 在分配引用前创建，因此失败的平台调用不会创建文件。
	protectedValue, errProtect := s.protector.Protect(plaintextCopy)
	defer clear(protectedValue)
	if errProtect != nil {
		return "", fmt.Errorf("protect secret: %w", errProtect)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for attempts := 0; attempts < 8; attempts++ {
		reference, filename, errReference := newLocalReference()
		if errReference != nil {
			return "", errReference
		}
		// secretPath remains under the store-owned directory because filename originates from random hex only.
		// secretPath 始终位于存储拥有的目录下，因为文件名仅来自随机十六进制。
		secretPath := filepath.Join(s.directory, filename)
		if _, errStat := os.Stat(secretPath); errStat == nil {
			continue
		} else if !errors.Is(errStat, os.ErrNotExist) {
			return "", fmt.Errorf("inspect secret destination: %w", errStat)
		}
		if errWrite := writeSecretAtomically(secretPath, protectedValue); errWrite != nil {
			return "", errWrite
		}
		return reference, nil
	}
	return "", errors.New("allocate unique local secret reference")
}

// Get reads and decrypts one isolated secret copy by exact local reference.
// Get 按精确本地引用读取并解密一个隔离 Secret 副本。
func (s *LocalStore) Get(ctx context.Context, reference string) ([]byte, error) {
	if errContext := contextError(ctx); errContext != nil {
		return nil, errContext
	}
	filename, errReference := localFilename(reference)
	if errReference != nil {
		return nil, errReference
	}
	s.mu.RLock()
	// secretPath is derived only after reference validation to prevent traversal outside s.directory.
	// secretPath 仅在引用校验后派生，以防止遍历到 s.directory 之外。
	secretPath := filepath.Join(s.directory, filename)
	protectedValue, errRead := os.ReadFile(secretPath)
	s.mu.RUnlock()
	if errors.Is(errRead, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, reference)
	}
	if errRead != nil {
		return nil, fmt.Errorf("read protected secret: %w", errRead)
	}
	plainValue, errUnprotect := s.protector.Unprotect(protectedValue)
	defer clear(plainValue)
	if errUnprotect != nil {
		return nil, fmt.Errorf("unprotect secret: %w", errUnprotect)
	}
	return append([]byte(nil), plainValue...), nil
}

// Delete removes one exact protected secret file and reports missing references explicitly.
// Delete 删除一个精确受保护 Secret 文件并显式报告缺失引用。
func (s *LocalStore) Delete(ctx context.Context, reference string) error {
	if errContext := contextError(ctx); errContext != nil {
		return errContext
	}
	filename, errReference := localFilename(reference)
	if errReference != nil {
		return errReference
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// secretPath is always constrained by localFilename and the store-owned directory.
	// secretPath 始终受 localFilename 和存储拥有目录约束。
	secretPath := filepath.Join(s.directory, filename)
	if errRemove := os.Remove(secretPath); errors.Is(errRemove, os.ErrNotExist) {
		return fmt.Errorf("%w: %s", ErrNotFound, reference)
	} else if errRemove != nil {
		return fmt.Errorf("remove protected secret: %w", errRemove)
	}
	return nil
}

// newLocalReference allocates one opaque local reference and its safe file name.
// newLocalReference 分配一个不透明本地引用及其安全文件名。
func newLocalReference() (string, string, error) {
	// randomBytes contains 128 bits of entropy and never becomes secret data itself.
	// randomBytes 包含 128 位熵且自身永不成为 Secret 数据。
	randomBytes := make([]byte, 16)
	if _, errRead := rand.Read(randomBytes); errRead != nil {
		return "", "", fmt.Errorf("generate local secret reference: %w", errRead)
	}
	identifier := hex.EncodeToString(randomBytes)
	return localReferencePrefix + identifier, identifier + localSecretSuffix, nil
}

// localFilename validates one opaque local reference and derives its safe file name.
// localFilename 校验一个不透明本地引用并派生其安全文件名。
func localFilename(reference string) (string, error) {
	// identifier is isolated from the URL-like namespace before validation.
	// identifier 在校验前从类 URL 命名空间中隔离出来。
	identifier := strings.TrimPrefix(reference, localReferencePrefix)
	if identifier == reference || len(identifier) != 32 {
		return "", fmt.Errorf("%w: %s", ErrNotFound, reference)
	}
	decoded, errDecode := hex.DecodeString(identifier)
	if errDecode != nil || len(decoded) != 16 {
		return "", fmt.Errorf("%w: %s", ErrNotFound, reference)
	}
	return identifier + localSecretSuffix, nil
}

// writeSecretAtomically writes protected bytes into a same-directory temporary file before replacement.
// writeSecretAtomically 在替换前将受保护字节写入同目录临时文件。
func writeSecretAtomically(path string, data []byte) error {
	// directory is the same volume as the destination, which keeps the final rename atomic.
	// directory 与目标位于同一卷，从而保持最终重命名的原子性。
	directory := filepath.Dir(path)
	temporary, errCreate := os.CreateTemp(directory, ".vulcan-secret-")
	if errCreate != nil {
		return fmt.Errorf("create temporary protected secret: %w", errCreate)
	}
	// temporaryPath must be removed after every failure path.
	// temporaryPath 必须在每个失败路径后删除。
	temporaryPath := temporary.Name()
	defer func() {
		_ = os.Remove(temporaryPath)
	}()
	if errPermission := temporary.Chmod(0o600); errPermission != nil {
		_ = temporary.Close()
		return fmt.Errorf("restrict protected secret permissions: %w", errPermission)
	}
	if _, errWrite := temporary.Write(data); errWrite != nil {
		_ = temporary.Close()
		return fmt.Errorf("write protected secret: %w", errWrite)
	}
	if errSync := temporary.Sync(); errSync != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync protected secret: %w", errSync)
	}
	if errClose := temporary.Close(); errClose != nil {
		return fmt.Errorf("close protected secret: %w", errClose)
	}
	if errRename := os.Rename(temporaryPath, path); errRename != nil {
		return fmt.Errorf("replace protected secret: %w", errRename)
	}
	return nil
}
