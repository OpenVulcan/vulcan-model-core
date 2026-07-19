// Portions of this adapter are copied and adapted from CLIProxyAPI internal/runtime/executor/kimi_executor.go at commit 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66.
// 本适配器的部分逻辑复制并改编自 CLIProxyAPI 固定提交 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66 中的 internal/runtime/executor/kimi_executor.go。
// The copied scope is Kimi Coding model-prefix removal and provider-observed execution headers; protected token ownership remains native Vulcan design.
// 复制范围为 Kimi Coding 模型前缀移除及供应商已验证的执行请求头；受保护令牌所有权仍采用 Vulcan 原生设计。
package kimi

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/OpenVulcan/vulcan-model-core/internal/dependency"
	chatprofile "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/chat"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

var (
	// ErrInvalidCodingChatAdapter reports an incomplete or incompatible Kimi Coding wire adapter.
	// ErrInvalidCodingChatAdapter 表示 Kimi Coding wire 适配器不完整或不兼容。
	ErrInvalidCodingChatAdapter = errors.New("invalid Kimi Coding Chat adapter")
)

const (
	// codingExecutionUserAgent is CLIProxyAPI's exact local-build execution identity at the pinned source baseline.
	// codingExecutionUserAgent 是 CLIProxyAPI 在固定源码基线上的精确本地构建执行身份。
	codingExecutionUserAgent = "CLIProxyAPI/dev"
	// codingFallbackDeviceID is CLIProxyAPI's exact execution fallback when Kimi CLI has no persisted device identity.
	// codingFallbackDeviceID 是 Kimi CLI 没有持久化设备身份时 CLIProxyAPI 使用的精确执行回退值。
	codingFallbackDeviceID = "cli-proxy-api-device"
)

// CodingChatAdapter applies CLIProxyAPI-proven Kimi Coding wire behavior after typed OpenAI Chat projection.
// CodingChatAdapter 在类型化 OpenAI Chat 投影后应用 CLIProxyAPI 已验证的 Kimi Coding wire 行为。
type CodingChatAdapter struct {
	// secrets resolves the complete protected device-flow document only when its device identity is required.
	// secrets 仅在需要设备身份时解析完整的受保护设备授权文档。
	secrets secret.Store
}

// NewCodingChatAdapter creates a Kimi Coding adapter over the authoritative protected secret store.
// NewCodingChatAdapter 基于权威受保护 Secret Store 创建 Kimi Coding 适配器。
func NewCodingChatAdapter(secrets secret.Store) (*CodingChatAdapter, error) {
	if dependency.IsNil(secrets) {
		return nil, ErrInvalidCodingChatAdapter
	}
	return &CodingChatAdapter{secrets: secrets}, nil
}

// Adapt strips the provider-facing model prefix and returns the exact non-secret CLI execution headers.
// Adapt 移除供应商侧模型前缀并返回精确的非秘密 CLI 执行请求头。
func (a *CodingChatAdapter) Adapt(ctx context.Context, execution provider.ExecutionRequest, request *chatprofile.Request) ([]transport.Header, error) {
	if a == nil || a.secrets == nil || request == nil {
		return nil, ErrInvalidCodingChatAdapter
	}
	request.Model = stripKimiModelPrefix(request.Model)
	deviceID, errDeviceID := a.resolveDeviceID(ctx, execution)
	if errDeviceID != nil {
		return nil, errDeviceID
	}
	hostname, errHostname := os.Hostname()
	if errHostname != nil {
		hostname = "unknown"
	}
	return []transport.Header{
		{Name: "User-Agent", Value: codingExecutionUserAgent},
		{Name: "X-Msh-Platform", Value: devicePlatform},
		{Name: "X-Msh-Version", Value: deviceVersion},
		{Name: "X-Msh-Device-Name", Value: hostname},
		{Name: "X-Msh-Device-Model", Value: codingExecutionDeviceModel()},
		{Name: "X-Msh-Device-Id", Value: deviceID},
	}, nil
}

// resolveDeviceID returns the exact device-flow identity or CLIProxyAPI's API-key execution fallback.
// resolveDeviceID 返回精确的设备授权身份，或 CLIProxyAPI 的 API Key 执行回退身份。
func (a *CodingChatAdapter) resolveDeviceID(ctx context.Context, execution provider.ExecutionRequest) (string, error) {
	authMethod, exists := execution.Definition.AuthMethod(execution.Binding.Credential.AuthMethodID)
	if !exists {
		return "", fmt.Errorf("%w: authentication method %q is not declared", ErrInvalidCodingChatAdapter, execution.Binding.Credential.AuthMethodID)
	}
	switch authMethod.Type {
	case providerconfig.AuthMethodAPIKey:
		return persistedKimiDeviceID(), nil
	case providerconfig.AuthMethodDeviceFlow:
		encodedToken, errSecret := a.secrets.Get(ctx, execution.Binding.Credential.SecretRef)
		if errSecret != nil {
			return "", fmt.Errorf("%w: resolve device-flow credential: %v", ErrInvalidCodingChatAdapter, errSecret)
		}
		defer clear(encodedToken)
		token, errToken := UnmarshalToken(encodedToken)
		if errToken != nil {
			return "", fmt.Errorf("%w: decode device-flow credential: %v", ErrInvalidCodingChatAdapter, errToken)
		}
		return token.DeviceID, nil
	default:
		return "", fmt.Errorf("%w: authentication type %q is not supported", ErrInvalidCodingChatAdapter, authMethod.Type)
	}
}

// stripKimiModelPrefix copies CLIProxyAPI's exact case-insensitive Kimi Coding model-name projection.
// stripKimiModelPrefix 复制 CLIProxyAPI 精确的不区分大小写 Kimi Coding 模型名投影。
func stripKimiModelPrefix(model string) string {
	model = strings.TrimSpace(model)
	if strings.HasPrefix(strings.ToLower(model), "kimi-") {
		return model[5:]
	}
	return model
}

// persistedKimiDeviceID copies CLIProxyAPI's platform-specific Kimi CLI identity lookup and fixed fallback.
// persistedKimiDeviceID 复制 CLIProxyAPI 按平台查找 Kimi CLI 身份及固定回退值的逻辑。
func persistedKimiDeviceID() string {
	userHome, errHome := os.UserHomeDir()
	if errHome != nil {
		return codingFallbackDeviceID
	}
	// shareDirectory is the exact Kimi CLI storage root for the current operating system.
	// shareDirectory 是当前操作系统对应的精确 Kimi CLI 存储根目录。
	shareDirectory := ""
	switch runtime.GOOS {
	case "darwin":
		shareDirectory = filepath.Join(userHome, "Library", "Application Support", "kimi")
	case "windows":
		applicationData := os.Getenv("APPDATA")
		if applicationData == "" {
			applicationData = filepath.Join(userHome, "AppData", "Roaming")
		}
		shareDirectory = filepath.Join(applicationData, "kimi")
	default:
		shareDirectory = filepath.Join(userHome, ".local", "share", "kimi")
	}
	deviceID, errRead := os.ReadFile(filepath.Join(shareDirectory, "device_id"))
	if errRead != nil || strings.TrimSpace(string(deviceID)) == "" {
		return codingFallbackDeviceID
	}
	return strings.TrimSpace(string(deviceID))
}

// codingExecutionDeviceModel copies CLIProxyAPI's exact execution-time operating-system and architecture value.
// codingExecutionDeviceModel 复制 CLIProxyAPI 精确的执行时操作系统与架构值。
func codingExecutionDeviceModel() string {
	return runtime.GOOS + " " + runtime.GOARCH
}
