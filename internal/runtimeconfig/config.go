// Package runtimeconfig owns the local control-plane configuration and API key lifecycle.
// runtimeconfig 包管理本地控制面的配置和 API 密钥生命周期。
package runtimeconfig

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

const (
	// DefaultPath is the conventional local control-plane configuration file name.
	// DefaultPath 是本地控制面配置文件的约定名称。
	DefaultPath = "vulcan-model-core.yaml"
)

var (
	// ErrConfigPathRequired reports an empty local configuration path.
	// ErrConfigPathRequired 表示本地配置路径为空。
	ErrConfigPathRequired = errors.New("runtime configuration path is required")
	// ErrManagementSecretRequired reports a configuration without a management secret.
	// ErrManagementSecretRequired 表示配置中缺少管理密钥。
	ErrManagementSecretRequired = errors.New("management secret key is required")
	// ErrAPIKeyNotFound reports an API key identifier that does not exist.
	// ErrAPIKeyNotFound 表示不存在的 API 密钥标识。
	ErrAPIKeyNotFound = errors.New("API key not found")
)

// Config is the complete YAML-backed local control-plane configuration.
// Config 是由 YAML 支撑的完整本地控制面配置。
type Config struct {
	// Management configures the management-plane credential.
	// Management 配置管理面的凭据。
	Management ManagementConfig `yaml:"management"`
	// API configures credentials accepted by the Vulcan call plane.
	// API 配置 Vulcan 调用面接受的凭据。
	API APIConfig `yaml:"api"`
}

// ManagementConfig contains the bcrypt-protected management credential.
// ManagementConfig 包含受 bcrypt 保护的管理凭据。
type ManagementConfig struct {
	// SecretKey accepts an initial plaintext value and persists only its bcrypt hash after startup.
	// SecretKey 接受初始明文值，并在启动后仅持久化其 bcrypt 散列。
	SecretKey string `yaml:"secret-key"`
}

// APIConfig contains management-editable call-plane API keys.
// APIConfig 包含可由管理面编辑的调用面 API 密钥。
type APIConfig struct {
	// Keys lists every configured call-plane API key in plaintext as explicitly requested.
	// Keys 按明确需求以明文列出全部配置的调用面 API 密钥。
	Keys []APIKey `yaml:"keys"`
}

// APIKey represents one named call-plane credential stored in the local YAML file.
// APIKey 表示存储在本地 YAML 文件中的一个具名调用面凭据。
type APIKey struct {
	// ID is the immutable management identifier for this key.
	// ID 是该密钥不可变的管理标识。
	ID string `yaml:"id" json:"id"`
	// Name is the editable human-readable management label.
	// Name 是可编辑的人类可读管理标签。
	Name string `yaml:"name" json:"name"`
	// Key is the plaintext bearer value accepted by the call plane.
	// Key 是调用面接受的明文 Bearer 值。
	Key string `yaml:"key" json:"key"`
	// Enabled controls whether this key currently authenticates call-plane requests.
	// Enabled 控制该密钥当前是否可认证调用面请求。
	Enabled bool `yaml:"enabled" json:"enabled"`
}

// APIKeyInput supplies editable fields when creating or replacing one API key.
// APIKeyInput 在创建或替换一个 API 密钥时提供可编辑字段。
type APIKeyInput struct {
	// Name is the human-readable management label.
	// Name 是人类可读的管理标签。
	Name string
	// Key is the plaintext bearer value to persist.
	// Key 是要持久化的明文 Bearer 值。
	Key string
	// Enabled controls whether the key may authenticate immediately.
	// Enabled 控制该密钥是否可立即认证。
	Enabled bool
}

// Store provides synchronized YAML-backed configuration and API key operations.
// Store 提供同步的 YAML 配置与 API 密钥操作。
type Store struct {
	// mu protects configuration snapshots and persistence mutations.
	// mu 保护配置快照和持久化变更。
	mu sync.RWMutex
	// path is the exact YAML file rewritten after approved configuration changes.
	// path 是获准配置变更后重写的精确 YAML 文件。
	path string
	// config stores the validated in-memory source of truth.
	// config 存储经过校验的内存事实来源。
	config Config
}

// Load reads one YAML configuration, hashes an initial management secret, and persists the hash.
// Load 读取一个 YAML 配置，散列初始管理密钥并持久化该散列。
func Load(path string) (*Store, error) {
	// normalizedPath is trimmed before it becomes the durable rewrite destination.
	// normalizedPath 在成为持久化重写目标前先完成裁剪。
	normalizedPath := strings.TrimSpace(path)
	if normalizedPath == "" {
		return nil, ErrConfigPathRequired
	}
	// data contains the exact caller-provided YAML configuration bytes.
	// data 包含调用方提供的精确 YAML 配置字节。
	data, errRead := os.ReadFile(normalizedPath)
	if errRead != nil {
		return nil, fmt.Errorf("read runtime configuration: %w", errRead)
	}
	// decoder rejects unknown fields so an apparent security setting cannot be silently ignored.
	// decoder 拒绝未知字段，避免看似安全的设置被静默忽略。
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	// loaded is the raw configuration decoded before normalization.
	// loaded 是规范化前解码出的原始配置。
	var loaded Config
	if errDecode := decoder.Decode(&loaded); errDecode != nil {
		return nil, fmt.Errorf("decode runtime configuration: %w", errDecode)
	}
	if errValidate := validateConfig(loaded); errValidate != nil {
		return nil, errValidate
	}
	// managementSecret is normalized once because surrounding YAML whitespace is never credential data.
	// managementSecret 仅规范化一次，因为 YAML 周围空白不是凭据数据。
	managementSecret := strings.TrimSpace(loaded.Management.SecretKey)
	loaded.Management.SecretKey = managementSecret
	// changed records whether initial plaintext must be replaced by a bcrypt hash on disk.
	// changed 记录初始明文是否必须在磁盘上替换为 bcrypt 散列。
	changed := false
	if !looksLikeBcrypt(managementSecret) {
		hashedSecret, errHash := bcrypt.GenerateFromPassword([]byte(managementSecret), bcrypt.DefaultCost)
		if errHash != nil {
			return nil, fmt.Errorf("hash management secret key: %w", errHash)
		}
		loaded.Management.SecretKey = string(hashedSecret)
		changed = true
	} else if _, errCost := bcrypt.Cost([]byte(managementSecret)); errCost != nil {
		return nil, fmt.Errorf("validate management secret key hash: %w", errCost)
	}
	// store owns the validated configuration before any later request can observe it.
	// store 在后续请求可观察配置前拥有已经校验的配置。
	store := &Store{path: normalizedPath, config: cloneConfig(loaded)}
	if changed {
		if errPersist := store.persist(loaded); errPersist != nil {
			return nil, fmt.Errorf("persist management secret key hash: %w", errPersist)
		}
	}
	return store, nil
}

// Path returns the exact local YAML file managed by this store.
// Path 返回此存储管理的精确本地 YAML 文件。
func (s *Store) Path() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.path
}

// AuthenticateManagementKey verifies one management-plane bearer value against its bcrypt hash.
// AuthenticateManagementKey 根据 bcrypt 散列校验一个管理面 Bearer 值。
func (s *Store) AuthenticateManagementKey(provided string) bool {
	// candidate is trimmed because HTTP bearer credentials must not include surrounding whitespace.
	// candidate 被裁剪，因为 HTTP Bearer 凭据不得包含首尾空白。
	candidate := strings.TrimSpace(provided)
	if candidate == "" {
		return false
	}
	s.mu.RLock()
	// secretHash is copied before the potentially expensive bcrypt comparison releases the lock.
	// secretHash 在耗时的 bcrypt 比较释放锁前完成复制。
	secretHash := s.config.Management.SecretKey
	s.mu.RUnlock()
	return bcrypt.CompareHashAndPassword([]byte(secretHash), []byte(candidate)) == nil
}

// AuthenticateAPIKey verifies one enabled call-plane API key without exposing the configured list.
// AuthenticateAPIKey 校验一个启用的调用面 API 密钥且不暴露已配置列表。
func (s *Store) AuthenticateAPIKey(provided string) bool {
	// candidate is trimmed because transport syntax treats outer whitespace as non-credential data.
	// candidate 被裁剪，因为传输语法将外围空白视为非凭据数据。
	candidate := strings.TrimSpace(provided)
	if candidate == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, configuredKey := range s.config.API.Keys {
		if configuredKey.Enabled && subtle.ConstantTimeCompare([]byte(configuredKey.Key), []byte(candidate)) == 1 {
			return true
		}
	}
	return false
}

// ListAPIKeys returns an isolated management-plane snapshot of plaintext API keys.
// ListAPIKeys 返回明文 API 密钥的隔离管理面快照。
func (s *Store) ListAPIKeys() []APIKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]APIKey(nil), s.config.API.Keys...)
}

// CreateAPIKey adds one new call-plane API key and persists the complete configuration atomically.
// CreateAPIKey 添加一个新的调用面 API 密钥并原子持久化完整配置。
func (s *Store) CreateAPIKey(input APIKeyInput) (APIKey, error) {
	if errInput := validateAPIKeyInput(input); errInput != nil {
		return APIKey{}, errInput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// next is copied before mutation so a failed YAML write never alters the live configuration.
	// next 在变更前完成复制，因此失败的 YAML 写入绝不改变活动配置。
	next := cloneConfig(s.config)
	keyID, errID := newAPIKeyID(next.API.Keys)
	if errID != nil {
		return APIKey{}, errID
	}
	// created is normalized exactly once before it becomes externally visible.
	// created 在对外可见前仅进行一次规范化。
	created := APIKey{ID: keyID, Name: strings.TrimSpace(input.Name), Key: strings.TrimSpace(input.Key), Enabled: input.Enabled}
	next.API.Keys = append(next.API.Keys, created)
	if errPersist := s.persist(next); errPersist != nil {
		return APIKey{}, errPersist
	}
	s.config = next
	return created, nil
}

// UpdateAPIKey replaces one editable call-plane API key and persists the complete configuration atomically.
// UpdateAPIKey 替换一个可编辑调用面 API 密钥并原子持久化完整配置。
func (s *Store) UpdateAPIKey(id string, input APIKeyInput) (APIKey, error) {
	if errInput := validateAPIKeyInput(input); errInput != nil {
		return APIKey{}, errInput
	}
	// normalizedID is required before acquiring the mutation lock.
	// normalizedID 在获取变更锁前必须有效。
	normalizedID := strings.TrimSpace(id)
	if normalizedID == "" {
		return APIKey{}, fmt.Errorf("%w: identifier is required", ErrAPIKeyNotFound)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneConfig(s.config)
	for index := range next.API.Keys {
		if next.API.Keys[index].ID != normalizedID {
			continue
		}
		// replacement preserves the immutable identifier while replacing every mutable field explicitly.
		// replacement 保留不可变标识，同时显式替换每一个可变字段。
		replacement := APIKey{ID: normalizedID, Name: strings.TrimSpace(input.Name), Key: strings.TrimSpace(input.Key), Enabled: input.Enabled}
		if errDuplicate := ensureUniqueKeyValue(next.API.Keys, replacement.Key, normalizedID); errDuplicate != nil {
			return APIKey{}, errDuplicate
		}
		next.API.Keys[index] = replacement
		if errPersist := s.persist(next); errPersist != nil {
			return APIKey{}, errPersist
		}
		s.config = next
		return replacement, nil
	}
	return APIKey{}, fmt.Errorf("%w: %s", ErrAPIKeyNotFound, normalizedID)
}

// DeleteAPIKey removes one call-plane API key and persists the complete configuration atomically.
// DeleteAPIKey 删除一个调用面 API 密钥并原子持久化完整配置。
func (s *Store) DeleteAPIKey(id string) error {
	// normalizedID prevents whitespace-only route values from accidentally matching nothing silently.
	// normalizedID 防止仅包含空白的路由值静默匹配不到任何内容。
	normalizedID := strings.TrimSpace(id)
	if normalizedID == "" {
		return fmt.Errorf("%w: identifier is required", ErrAPIKeyNotFound)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneConfig(s.config)
	for index, configuredKey := range next.API.Keys {
		if configuredKey.ID != normalizedID {
			continue
		}
		next.API.Keys = append(next.API.Keys[:index], next.API.Keys[index+1:]...)
		if errPersist := s.persist(next); errPersist != nil {
			return errPersist
		}
		s.config = next
		return nil
	}
	return fmt.Errorf("%w: %s", ErrAPIKeyNotFound, normalizedID)
}

// validateConfig checks YAML values before they become an authorization source.
// validateConfig 在 YAML 值成为授权来源前校验它们。
func validateConfig(config Config) error {
	if strings.TrimSpace(config.Management.SecretKey) == "" {
		return ErrManagementSecretRequired
	}
	// seenIDs prevents routes from selecting an ambiguous management record.
	// seenIDs 防止路由选择存在歧义的管理记录。
	seenIDs := make(map[string]struct{}, len(config.API.Keys))
	// seenValues prevents one bearer value from carrying two conflicting management identities.
	// seenValues 防止一个 Bearer 值承载两个冲突的管理身份。
	seenValues := make(map[string]struct{}, len(config.API.Keys))
	for _, configuredKey := range config.API.Keys {
		if errKey := validateAPIKey(configuredKey); errKey != nil {
			return errKey
		}
		if _, exists := seenIDs[configuredKey.ID]; exists {
			return fmt.Errorf("duplicate API key identifier %q", configuredKey.ID)
		}
		if _, exists := seenValues[configuredKey.Key]; exists {
			return fmt.Errorf("duplicate API key value for %q", configuredKey.ID)
		}
		seenIDs[configuredKey.ID] = struct{}{}
		seenValues[configuredKey.Key] = struct{}{}
	}
	return nil
}

// validateAPIKeyInput validates editable API key fields before creating or replacing a record.
// validateAPIKeyInput 在创建或替换记录前校验可编辑 API 密钥字段。
func validateAPIKeyInput(input APIKeyInput) error {
	return validateAPIKey(APIKey{ID: "api_input", Name: input.Name, Key: input.Key, Enabled: input.Enabled})
}

// validateAPIKey validates one persisted API key record.
// validateAPIKey 校验一个已持久化的 API 密钥记录。
func validateAPIKey(configuredKey APIKey) error {
	if strings.TrimSpace(configuredKey.ID) == "" {
		return errors.New("API key identifier is required")
	}
	if strings.TrimSpace(configuredKey.Name) == "" {
		return fmt.Errorf("API key %q name is required", configuredKey.ID)
	}
	if strings.TrimSpace(configuredKey.Key) == "" {
		return fmt.Errorf("API key %q value is required", configuredKey.ID)
	}
	return nil
}

// ensureUniqueKeyValue rejects an API key bearer value already assigned to another record.
// ensureUniqueKeyValue 拒绝已经分配给另一记录的 API 密钥 Bearer 值。
func ensureUniqueKeyValue(keys []APIKey, value string, exemptID string) error {
	for _, configuredKey := range keys {
		if configuredKey.ID != exemptID && configuredKey.Key == value {
			return fmt.Errorf("duplicate API key value for %q", configuredKey.ID)
		}
	}
	return nil
}

// newAPIKeyID allocates a collision-free random management identifier.
// newAPIKeyID 分配一个无冲突的随机管理标识。
func newAPIKeyID(keys []APIKey) (string, error) {
	// existing records current identifiers to make the cryptographic collision guard explicit.
	// existing 记录当前标识以明确执行密码学碰撞保护。
	existing := make(map[string]struct{}, len(keys))
	for _, configuredKey := range keys {
		existing[configuredKey.ID] = struct{}{}
	}
	for attempts := 0; attempts < 8; attempts++ {
		// randomBytes supplies 128 bits of entropy for a local management identifier.
		// randomBytes 为本地管理标识提供 128 位熵。
		randomBytes := make([]byte, 16)
		if _, errRead := rand.Read(randomBytes); errRead != nil {
			return "", fmt.Errorf("generate API key identifier: %w", errRead)
		}
		candidate := "api_" + hex.EncodeToString(randomBytes)
		if _, exists := existing[candidate]; !exists {
			return candidate, nil
		}
	}
	return "", errors.New("allocate unique API key identifier")
}

// persist serializes one validated configuration and replaces the YAML file atomically.
// persist 序列化一个已校验的配置并原子替换 YAML 文件。
func (s *Store) persist(config Config) error {
	if errValidate := validateConfig(config); errValidate != nil {
		return errValidate
	}
	// serialized is complete YAML rather than a partial patch so all durable fields move together.
	// serialized 是完整 YAML 而非局部补丁，因此所有持久化字段一起变更。
	serialized, errMarshal := yaml.Marshal(config)
	if errMarshal != nil {
		return fmt.Errorf("marshal runtime configuration: %w", errMarshal)
	}
	return writeAtomically(s.path, serialized)
}

// writeAtomically replaces one existing configuration file only after all new bytes reach a temporary file.
// writeAtomically 仅在全部新字节写入临时文件后替换一个已有配置文件。
func writeAtomically(path string, data []byte) error {
	// directory resolves the temporary file to the same volume as the target rename.
	// directory 将临时文件解析到与目标重命名相同的卷。
	directory := filepath.Dir(path)
	temporary, errCreate := os.CreateTemp(directory, ".vulcan-model-core-")
	if errCreate != nil {
		return fmt.Errorf("create temporary runtime configuration: %w", errCreate)
	}
	// temporaryPath is retained because Close does not remove a failed persistence artifact.
	// temporaryPath 被保留，因为 Close 不会删除失败的持久化产物。
	temporaryPath := temporary.Name()
	defer func() {
		_ = os.Remove(temporaryPath)
	}()
	if errPermission := temporary.Chmod(0o600); errPermission != nil {
		_ = temporary.Close()
		return fmt.Errorf("restrict temporary runtime configuration permissions: %w", errPermission)
	}
	if _, errWrite := temporary.Write(data); errWrite != nil {
		_ = temporary.Close()
		return fmt.Errorf("write temporary runtime configuration: %w", errWrite)
	}
	if errSync := temporary.Sync(); errSync != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync temporary runtime configuration: %w", errSync)
	}
	if errClose := temporary.Close(); errClose != nil {
		return fmt.Errorf("close temporary runtime configuration: %w", errClose)
	}
	if errRename := os.Rename(temporaryPath, path); errRename != nil {
		return fmt.Errorf("replace runtime configuration: %w", errRename)
	}
	return nil
}

// looksLikeBcrypt identifies the supported bcrypt prefix before validating its full encoding.
// looksLikeBcrypt 在校验完整编码前识别受支持的 bcrypt 前缀。
func looksLikeBcrypt(value string) bool {
	return strings.HasPrefix(value, "$2a$") || strings.HasPrefix(value, "$2b$") || strings.HasPrefix(value, "$2y$")
}

// cloneConfig isolates mutable API key slices between callers and the authoritative store.
// cloneConfig 在调用方与权威存储之间隔离可变 API 密钥切片。
func cloneConfig(config Config) Config {
	return Config{
		Management: config.Management,
		API:        APIConfig{Keys: append([]APIKey(nil), config.API.Keys...)},
	}
}
