package google

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	// antigravityFallbackVersion is CLIProxyAPI's current proven Hub fallback version.
	// antigravityFallbackVersion 是 CLIProxyAPI 当前已验证的 Hub 回退版本。
	antigravityFallbackVersion = "2.2.1"
	// antigravityHubPlatform is the official Hub updater platform copied from CLIProxyAPI.
	// antigravityHubPlatform 是从 CLIProxyAPI 复制的官方 Hub 更新器平台。
	antigravityHubPlatform = "darwin/arm64"
	// antigravityVersionCacheTTL preserves CLIProxyAPI's six-hour version cache.
	// antigravityVersionCacheTTL 保留 CLIProxyAPI 的六小时版本缓存。
	antigravityVersionCacheTTL = 6 * time.Hour
	// antigravityFetchTimeout preserves CLIProxyAPI's manifest request timeout.
	// antigravityFetchTimeout 保留 CLIProxyAPI 的 Manifest 请求超时。
	antigravityFetchTimeout = 10 * time.Second
	// antigravityManifestResponseLimit bounds the small updater manifest response.
	// antigravityManifestResponseLimit 限制小型更新器 Manifest 响应大小。
	antigravityManifestResponseLimit = 4096
	// antigravityControlResponseLimit bounds OAuth and control-plane JSON responses.
	// antigravityControlResponseLimit 限制 OAuth 与控制面 JSON 响应大小。
	antigravityControlResponseLimit = 1 << 20
	// antigravityNodeAPIClientUA identifies the copied Node control-plane client.
	// antigravityNodeAPIClientUA 标识复制的 Node 控制面客户端。
	antigravityNodeAPIClientUA = "google-api-nodejs-client/10.3.0"
	// antigravityGoogAPIClientUA identifies the copied Google API client runtime.
	// antigravityGoogAPIClientUA 标识复制的 Google API 客户端运行时。
	antigravityGoogAPIClientUA = "gl-node/22.21.1"
)

var (
	// antigravityHubLatestManifestURL is mutable only for isolated manifest tests.
	// antigravityHubLatestManifestURL 仅为隔离的 Manifest 测试可变。
	antigravityHubLatestManifestURL = "https://antigravity-hub-auto-updater-974169037036.us-central1.run.app/manifest/latest-arm64-mac.yml"
	// cachedAntigravityVersion stores the last verified Hub version.
	// cachedAntigravityVersion 存储最后一次验证通过的 Hub 版本。
	cachedAntigravityVersion = antigravityFallbackVersion
	// antigravityVersionExpiry bounds the verified version lifetime.
	// antigravityVersionExpiry 限制已验证版本的有效期。
	antigravityVersionExpiry time.Time
	// antigravityVersionMu protects the version cache and expiry as one snapshot.
	// antigravityVersionMu 将版本缓存与过期时间作为一个快照保护。
	antigravityVersionMu sync.RWMutex
	// antigravityUpdaterOnce prevents duplicate background refresh loops.
	// antigravityUpdaterOnce 防止重复启动后台刷新循环。
	antigravityUpdaterOnce sync.Once
)

// antigravityHubUpdaterManifest is the exact manifest field consumed by CLIProxyAPI.
// antigravityHubUpdaterManifest 是 CLIProxyAPI 消费的精确 Manifest 字段。
type antigravityHubUpdaterManifest struct {
	// Version is the current official Antigravity Hub semantic version.
	// Version 是当前官方 Antigravity Hub 语义版本。
	Version string `yaml:"version"`
}

// StartAntigravityVersionUpdater starts the copied non-blocking periodic Hub version refresh.
// StartAntigravityVersionUpdater 启动复制的非阻塞周期性 Hub 版本刷新。
func StartAntigravityVersionUpdater(ctx context.Context) {
	antigravityUpdaterOnce.Do(func() {
		go runAntigravityVersionUpdater(ctx)
	})
}

// runAntigravityVersionUpdater refreshes immediately and then every half cache lifetime.
// runAntigravityVersionUpdater 立即刷新，随后每半个缓存生命周期刷新一次。
func runAntigravityVersionUpdater(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}
	ticker := time.NewTicker(antigravityVersionCacheTTL / 2)
	defer ticker.Stop()
	refreshAntigravityVersion(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refreshAntigravityVersion(ctx)
		}
	}
}

// refreshAntigravityVersion atomically replaces the cache or preserves a still-valid version on failure.
// refreshAntigravityVersion 原子替换缓存，或在失败时保留仍有效的版本。
func refreshAntigravityVersion(ctx context.Context) {
	version, errFetch := fetchAntigravityLatestVersion(ctx)
	now := time.Now()
	antigravityVersionMu.Lock()
	defer antigravityVersionMu.Unlock()
	if errFetch == nil {
		cachedAntigravityVersion = version
		antigravityVersionExpiry = now.Add(antigravityVersionCacheTTL)
		log.Printf("fetched latest Antigravity version %s", version)
		return
	}
	if cachedAntigravityVersion == "" || now.After(antigravityVersionExpiry) {
		cachedAntigravityVersion = antigravityFallbackVersion
		antigravityVersionExpiry = now.Add(antigravityVersionCacheTTL)
		log.Printf("failed to refresh Antigravity version; using fallback: %v", errFetch)
	}
}

// AntigravityLatestVersion returns a verified cached version or CLIProxyAPI's exact fallback.
// AntigravityLatestVersion 返回已验证缓存版本或 CLIProxyAPI 的精确回退版本。
func AntigravityLatestVersion() string {
	antigravityVersionMu.RLock()
	if cachedAntigravityVersion != "" && time.Now().Before(antigravityVersionExpiry) {
		version := cachedAntigravityVersion
		antigravityVersionMu.RUnlock()
		return version
	}
	antigravityVersionMu.RUnlock()
	return antigravityFallbackVersion
}

// AntigravityUserAgent returns the copied short Hub-family User-Agent.
// AntigravityUserAgent 返回复制的简短 Hub 系列 User-Agent。
func AntigravityUserAgent() string {
	return fmt.Sprintf("antigravity/hub/%s %s", AntigravityLatestVersion(), antigravityHubPlatform)
}

// AntigravityRequestUserAgent normalizes one execution User-Agent to CLIProxyAPI's short form.
// AntigravityRequestUserAgent 将执行 User-Agent 规范化为 CLIProxyAPI 的简短形式。
func AntigravityRequestUserAgent(userAgent string) string {
	return antigravityBaseUserAgent(userAgent)
}

// AntigravityLoadCodeAssistUserAgent returns the short control-plane User-Agent.
// AntigravityLoadCodeAssistUserAgent 返回简短控制面 User-Agent。
func AntigravityLoadCodeAssistUserAgent(userAgent string) string {
	return AntigravityRequestUserAgent(userAgent)
}

// AntigravityOnboardUserUserAgent returns the copied long Node control-plane User-Agent.
// AntigravityOnboardUserUserAgent 返回复制的 Node 控制面长 User-Agent。
func AntigravityOnboardUserUserAgent(userAgent string) string {
	userAgent = strings.TrimSpace(userAgent)
	if userAgent == "" {
		return AntigravityUserAgent() + " " + antigravityNodeAPIClientUA
	}
	lower := strings.ToLower(userAgent)
	if !isAntigravityFamilyUserAgent(lower) {
		return userAgent
	}
	if strings.Contains(lower, "google-api-nodejs-client/") {
		return userAgent
	}
	return antigravityBaseUserAgent(userAgent) + " " + antigravityNodeAPIClientUA
}

// AntigravityVersionFromUserAgent extracts the Hub or legacy Antigravity version prefix.
// AntigravityVersionFromUserAgent 提取 Hub 或旧版 Antigravity 版本前缀。
func AntigravityVersionFromUserAgent(userAgent string) string {
	base := antigravityBaseUserAgent(userAgent)
	lower := strings.ToLower(base)
	if strings.HasPrefix(lower, "antigravity/hub/") {
		rest := base[len("antigravity/hub/"):]
		if index := strings.IndexAny(rest, " \t"); index >= 0 {
			rest = rest[:index]
		}
		if rest = strings.TrimSpace(rest); rest != "" {
			return rest
		}
		return AntigravityLatestVersion()
	}
	const legacyPrefix = "antigravity/"
	if !strings.HasPrefix(lower, legacyPrefix) {
		return AntigravityLatestVersion()
	}
	rest := base[len(legacyPrefix):]
	if index := strings.IndexAny(rest, " \t"); index >= 0 {
		rest = rest[:index]
	}
	if rest = strings.TrimSpace(rest); rest != "" {
		return rest
	}
	return AntigravityLatestVersion()
}

// isAntigravityFamilyUserAgent reports whether one normalized value belongs to either copied UA family.
// isAntigravityFamilyUserAgent 判断规范化值是否属于任一复制的 UA 系列。
func isAntigravityFamilyUserAgent(lower string) bool {
	return strings.HasPrefix(lower, "antigravity/hub/") || strings.HasPrefix(lower, "antigravity/")
}

// antigravityBaseUserAgent removes only the copied Node suffix from an Antigravity-family User-Agent.
// antigravityBaseUserAgent 仅从 Antigravity 系列 User-Agent 移除复制的 Node 后缀。
func antigravityBaseUserAgent(userAgent string) string {
	userAgent = strings.TrimSpace(userAgent)
	if userAgent == "" {
		return AntigravityUserAgent()
	}
	lower := strings.ToLower(userAgent)
	if isAntigravityFamilyUserAgent(lower) {
		if index := strings.Index(lower, " google-api-nodejs-client/"); index >= 0 {
			if trimmed := strings.TrimSpace(userAgent[:index]); trimmed != "" {
				return trimmed
			}
		}
	}
	return userAgent
}

// fetchAntigravityLatestVersion retrieves the official Hub updater manifest with the copied timeout.
// fetchAntigravityLatestVersion 使用复制的超时获取官方 Hub 更新器 Manifest。
func fetchAntigravityLatestVersion(ctx context.Context) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	return fetchAntigravityHubLatestManifestVersion(ctx, &http.Client{Timeout: antigravityFetchTimeout})
}

// fetchAntigravityHubLatestManifestVersion validates one bounded official updater manifest.
// fetchAntigravityHubLatestManifestVersion 校验一个有界的官方更新器 Manifest。
func fetchAntigravityHubLatestManifestVersion(ctx context.Context, client *http.Client) (string, error) {
	request, errRequest := http.NewRequestWithContext(ctx, http.MethodGet, antigravityHubLatestManifestURL, nil)
	if errRequest != nil {
		return "", fmt.Errorf("build Antigravity Hub updater manifest request: %w", errRequest)
	}
	request.Header.Set("User-Agent", "electron-builder")
	request.Header.Set("Cache-Control", "no-cache")
	response, errResponse := client.Do(request)
	if errResponse != nil {
		return "", fmt.Errorf("fetch Antigravity Hub updater manifest: %w", errResponse)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Antigravity Hub updater manifest returned status %d", response.StatusCode)
	}
	raw, errRead := io.ReadAll(io.LimitReader(response.Body, antigravityManifestResponseLimit+1))
	if errRead != nil {
		return "", fmt.Errorf("read Antigravity Hub updater manifest: %w", errRead)
	}
	defer clear(raw)
	if len(raw) > antigravityManifestResponseLimit {
		return "", errors.New("Antigravity Hub updater manifest exceeds the response limit")
	}
	var manifest antigravityHubUpdaterManifest
	if errDecode := yaml.Unmarshal(raw, &manifest); errDecode != nil {
		return "", fmt.Errorf("decode Antigravity Hub updater manifest: %w", errDecode)
	}
	version := strings.TrimSpace(manifest.Version)
	if version == "" {
		return "", errors.New("Antigravity Hub updater manifest returned empty version")
	}
	if !isValidAntigravitySemVersion(version) {
		return "", fmt.Errorf("Antigravity Hub updater manifest returned invalid version %q", version)
	}
	return version, nil
}

// isValidAntigravitySemVersion preserves CLIProxyAPI's strict numeric three-part version check.
// isValidAntigravitySemVersion 保留 CLIProxyAPI 严格的三段数字版本校验。
func isValidAntigravitySemVersion(version string) bool {
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, character := range part {
			if character < '0' || character > '9' {
				return false
			}
		}
	}
	return true
}
