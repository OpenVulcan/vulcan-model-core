package google

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// overrideAntigravityVersionCacheForTest replaces global cache state and returns an exact restore function.
// overrideAntigravityVersionCacheForTest 替换全局缓存状态并返回精确恢复函数。
func overrideAntigravityVersionCacheForTest(t *testing.T, version string, expiry time.Time) func() {
	t.Helper()
	antigravityVersionMu.Lock()
	previousVersion := cachedAntigravityVersion
	previousExpiry := antigravityVersionExpiry
	cachedAntigravityVersion = version
	antigravityVersionExpiry = expiry
	antigravityVersionMu.Unlock()
	return func() {
		antigravityVersionMu.Lock()
		cachedAntigravityVersion = previousVersion
		antigravityVersionExpiry = previousExpiry
		antigravityVersionMu.Unlock()
	}
}

// overrideAntigravityManifestURLForTest replaces only the copied manifest endpoint during one test.
// overrideAntigravityManifestURLForTest 仅在单个测试期间替换复制的 Manifest 入口。
func overrideAntigravityManifestURLForTest(t *testing.T, endpoint string) func() {
	t.Helper()
	previousEndpoint := antigravityHubLatestManifestURL
	antigravityHubLatestManifestURL = endpoint
	return func() {
		antigravityHubLatestManifestURL = previousEndpoint
	}
}

// TestAntigravityLatestVersionUsesCopiedFallback verifies the exact proven fallback.
// TestAntigravityLatestVersionUsesCopiedFallback 验证精确且已验证的回退版本。
func TestAntigravityLatestVersionUsesCopiedFallback(t *testing.T) {
	restore := overrideAntigravityVersionCacheForTest(t, "", time.Time{})
	defer restore()
	if version := AntigravityLatestVersion(); version != antigravityFallbackVersion {
		t.Fatalf("AntigravityLatestVersion() = %q", version)
	}
}

// TestAntigravityUserAgentsCopyHubFamily verifies short, long, and metadata version forms.
// TestAntigravityUserAgentsCopyHubFamily 验证简短、长格式及元数据版本形态。
func TestAntigravityUserAgentsCopyHubFamily(t *testing.T) {
	restore := overrideAntigravityVersionCacheForTest(t, "3.4.5", time.Now().Add(time.Hour))
	defer restore()
	short := "antigravity/hub/3.4.5 darwin/arm64"
	if userAgent := AntigravityUserAgent(); userAgent != short {
		t.Fatalf("AntigravityUserAgent() = %q", userAgent)
	}
	long := short + " " + antigravityNodeAPIClientUA
	if userAgent := AntigravityOnboardUserUserAgent(""); userAgent != long {
		t.Fatalf("AntigravityOnboardUserUserAgent() = %q", userAgent)
	}
	if version := AntigravityVersionFromUserAgent(long); version != "3.4.5" {
		t.Fatalf("AntigravityVersionFromUserAgent() = %q", version)
	}
}

// TestFetchAntigravityHubLatestManifestVersionCopiesRequest verifies manifest headers and parsing.
// TestFetchAntigravityHubLatestManifestVersionCopiesRequest 验证 Manifest 请求头与解析行为。
func TestFetchAntigravityHubLatestManifestVersionCopiesRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("User-Agent") != "electron-builder" || request.Header.Get("Cache-Control") != "no-cache" {
			t.Errorf("manifest headers = %#v", request.Header)
		}
		_, _ = writer.Write([]byte("version: 7.8.9\n"))
	}))
	defer server.Close()
	restore := overrideAntigravityManifestURLForTest(t, server.URL)
	defer restore()
	version, errVersion := fetchAntigravityHubLatestManifestVersion(context.Background(), server.Client())
	if errVersion != nil || version != "7.8.9" {
		t.Fatalf("fetchAntigravityHubLatestManifestVersion() = %q, %v", version, errVersion)
	}
}

// TestFetchAntigravityHubLatestManifestVersionRejectsOversizedResponse verifies strict truncation detection.
// TestFetchAntigravityHubLatestManifestVersionRejectsOversizedResponse 验证严格截断检测。
func TestFetchAntigravityHubLatestManifestVersionRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(strings.Repeat("x", antigravityManifestResponseLimit+1)))
	}))
	defer server.Close()
	restore := overrideAntigravityManifestURLForTest(t, server.URL)
	defer restore()
	if _, errVersion := fetchAntigravityHubLatestManifestVersion(context.Background(), server.Client()); errVersion == nil || !strings.Contains(errVersion.Error(), "exceeds the response limit") {
		t.Fatalf("fetchAntigravityHubLatestManifestVersion() error = %v", errVersion)
	}
}
