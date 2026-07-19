package google

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/dependency"
	providertransport "github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

const (
	// vertexCloudPlatformScope is CLIProxyAPI's exact scope for Vertex service-account execution.
	// vertexCloudPlatformScope 是 CLIProxyAPI 用于 Vertex 服务账号执行的精确 Scope。
	vertexCloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"
	// vertexJWTGrantType identifies the OAuth service-account assertion exchange.
	// vertexJWTGrantType 标识 OAuth 服务账号断言交换。
	vertexJWTGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	// vertexTokenResponseLimit bounds untrusted OAuth response bodies retained in memory.
	// vertexTokenResponseLimit 限制内存中保留的不受信任 OAuth 响应体大小。
	vertexTokenResponseLimit = 1 << 20
	// vertexTokenRefreshSkew prevents an access token from being used near its provider expiry.
	// vertexTokenRefreshSkew 防止在供应商令牌临近过期时继续使用它。
	vertexTokenRefreshSkew = time.Minute
)

var (
	// errVertexCredentialInvalidated reports an access-token exchange that crossed a credential deletion boundary.
	// errVertexCredentialInvalidated 表示跨越凭据删除边界的 Access Token 交换。
	errVertexCredentialInvalidated = errors.New("Vertex credential was invalidated during token exchange")
)

// vertexJWTHeader is the exact RS256 header used for Google service-account assertions.
// vertexJWTHeader 是 Google 服务账号断言使用的精确 RS256 Header。
type vertexJWTHeader struct {
	// Algorithm fixes the signature algorithm to RSA SHA-256.
	// Algorithm 将签名算法固定为 RSA SHA-256。
	Algorithm string `json:"alg"`
	// Type identifies the compact document as a JWT.
	// Type 将紧凑文档标识为 JWT。
	Type string `json:"typ"`
	// KeyID optionally identifies the service-account private key.
	// KeyID 可选地标识服务账号私钥。
	KeyID string `json:"kid,omitempty"`
}

// vertexJWTClaims contains the exact OAuth service-account assertion claims.
// vertexJWTClaims 包含精确的 OAuth 服务账号断言 Claims。
type vertexJWTClaims struct {
	// Issuer is the service-account client email.
	// Issuer 是服务账号 Client Email。
	Issuer string `json:"iss"`
	// Scope authorizes Google Cloud Platform operations.
	// Scope 授权 Google Cloud Platform 操作。
	Scope string `json:"scope"`
	// Audience is the fixed Google OAuth token endpoint.
	// Audience 是固定的 Google OAuth Token 入口。
	Audience string `json:"aud"`
	// IssuedAt is the assertion creation Unix timestamp.
	// IssuedAt 是断言创建时的 Unix 时间戳。
	IssuedAt int64 `json:"iat"`
	// ExpiresAt is the assertion expiry Unix timestamp.
	// ExpiresAt 是断言过期 Unix 时间戳。
	ExpiresAt int64 `json:"exp"`
}

// vertexOAuthTokenResponse is the typed Google OAuth assertion-exchange response.
// vertexOAuthTokenResponse 是类型化的 Google OAuth 断言交换响应。
type vertexOAuthTokenResponse struct {
	// AccessToken authenticates Vertex execution requests.
	// AccessToken 用于认证 Vertex 执行请求。
	AccessToken string `json:"access_token"`
	// TokenType identifies the returned bearer-token scheme.
	// TokenType 标识返回的 Bearer Token Scheme。
	TokenType string `json:"token_type"`
	// ExpiresIn is the provider-reported token lifetime in seconds.
	// ExpiresIn 是供应商报告的令牌有效秒数。
	ExpiresIn int64 `json:"expires_in"`
}

// vertexCachedAccessToken stores one projected token and its absolute expiry.
// vertexCachedAccessToken 存储一个投影后的 Token 及其绝对过期时间。
type vertexCachedAccessToken struct {
	// value is the bearer token returned by Google OAuth.
	// value 是 Google OAuth 返回的 Bearer Token。
	value string
	// expiresAt is the absolute provider expiry.
	// expiresAt 是供应商绝对过期时间。
	expiresAt time.Time
}

// vertexTokenExchange coordinates concurrent requests for one immutable secret reference.
// vertexTokenExchange 协调同一不可变 Secret 引用的并发请求。
type vertexTokenExchange struct {
	// done closes after token exchange and cache publication finish.
	// done 在 Token 交换与缓存发布结束后关闭。
	done chan struct{}
	// token is the isolated result shared with exchange waiters.
	// token 是与交换等待者共享的隔离结果。
	token []byte
	// err is the exact exchange failure shared with waiters.
	// err 是与等待者共享的精确交换失败。
	err error
	// generation binds every waiter and leader result to the credential state that started the exchange.
	// generation 将每个等待者与主交换结果绑定到启动交换时的凭据状态。
	generation uint64
}

// VertexAccessTokenStore projects encrypted service-account documents to short-lived access tokens.
// VertexAccessTokenStore 将加密服务账号文档投影为短期 Access Token。
type VertexAccessTokenStore struct {
	// delegate owns encrypted Vertex credential documents.
	// delegate 管理加密 Vertex 凭据文档。
	delegate secret.Store
	// client performs only Google OAuth assertion exchanges.
	// client 仅执行 Google OAuth 断言交换。
	client *http.Client
	// now supplies deterministic wall-clock time for expiry checks.
	// now 为过期检查提供可确定的墙上时间。
	now func() time.Time
	// mu protects cache, in-flight exchange, and deletion-generation state.
	// mu 保护缓存、进行中的交换与删除代次状态。
	mu sync.Mutex
	// cache stores valid projected tokens by immutable secret reference.
	// cache 按不可变 Secret 引用存储有效的投影 Token。
	cache map[string]vertexCachedAccessToken
	// inflight deduplicates concurrent token exchanges per secret reference.
	// inflight 按 Secret 引用去重并发 Token 交换。
	inflight map[string]*vertexTokenExchange
	// generations prevent deletion racing with an exchange from resurrecting cache entries.
	// generations 防止删除与交换竞态后重新写入缓存条目。
	generations map[string]uint64
	// deleting marks references whose durable deletion has started but not finished.
	// deleting 标记已开始但尚未完成持久删除的引用。
	deleting map[string]struct{}
}

// NewVertexAccessTokenStore creates a protected service-account access-token projection.
// NewVertexAccessTokenStore 创建受保护的服务账号 Access Token 投影。
func NewVertexAccessTokenStore(delegate secret.Store, client *http.Client) (*VertexAccessTokenStore, error) {
	if dependency.IsNil(delegate) {
		return nil, errors.New("Vertex credential delegate store is required")
	}
	if client == nil {
		return nil, errors.New("Vertex OAuth HTTP client is required")
	}
	return &VertexAccessTokenStore{
		delegate:    delegate,
		client:      providertransport.CloneHTTPClientWithoutRedirects(client),
		now:         time.Now,
		cache:       make(map[string]vertexCachedAccessToken),
		inflight:    make(map[string]*vertexTokenExchange),
		generations: make(map[string]uint64),
		deleting:    make(map[string]struct{}),
	}, nil
}

// Put delegates protected credential persistence without exposing projected access tokens.
// Put 委托受保护凭据持久化且不暴露投影后的 Access Token。
func (s *VertexAccessTokenStore) Put(ctx context.Context, value []byte) (string, error) {
	return s.delegate.Put(ctx, value)
}

// Get returns one cached or freshly exchanged Google access token.
// Get 返回一个缓存的或新交换的 Google Access Token。
func (s *VertexAccessTokenStore) Get(ctx context.Context, reference string) ([]byte, error) {
	if s == nil || s.delegate == nil || s.client == nil || s.now == nil {
		return nil, errors.New("Vertex access-token store is not configured")
	}
	now := s.now()
	s.mu.Lock()
	if _, deleting := s.deleting[reference]; deleting {
		s.mu.Unlock()
		return nil, errVertexCredentialInvalidated
	}
	if cached, valid := s.cache[reference]; valid && now.Add(vertexTokenRefreshSkew).Before(cached.expiresAt) {
		token := []byte(cached.value)
		s.mu.Unlock()
		return token, nil
	}
	if exchange, running := s.inflight[reference]; running {
		if exchange.generation != s.generations[reference] {
			s.mu.Unlock()
			return nil, errVertexCredentialInvalidated
		}
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-exchange.done:
			return append([]byte(nil), exchange.token...), exchange.err
		}
	}
	generation := s.generations[reference]
	exchange := &vertexTokenExchange{done: make(chan struct{}), generation: generation}
	s.inflight[reference] = exchange
	s.mu.Unlock()

	// The shared leader outlives the initiating execution request so one disconnect cannot fail every waiter.
	// 共享主交换不随发起它的执行请求结束，避免一个连接断开导致全部等待者失败。
	token, expiresAt, errExchange := s.exchange(context.WithoutCancel(ctx), reference, now)
	s.mu.Lock()
	delete(s.inflight, reference)
	invalidated := generation != s.generations[reference]
	if invalidated {
		errExchange = errVertexCredentialInvalidated
		token = ""
	} else if errExchange == nil {
		exchange.token = []byte(token)
		s.cache[reference] = vertexCachedAccessToken{value: token, expiresAt: expiresAt}
	}
	if invalidated {
		if _, deleting := s.deleting[reference]; !deleting {
			delete(s.generations, reference)
		}
	}
	exchange.err = errExchange
	close(exchange.done)
	s.mu.Unlock()
	if errExchange != nil {
		return nil, errExchange
	}
	return []byte(token), nil
}

// Delete invalidates projected state before deleting the encrypted credential.
// Delete 在删除加密凭据前使投影状态失效。
func (s *VertexAccessTokenStore) Delete(ctx context.Context, reference string) error {
	if s == nil || s.delegate == nil {
		return errors.New("Vertex access-token store is not configured")
	}
	s.mu.Lock()
	if _, deleting := s.deleting[reference]; deleting {
		s.mu.Unlock()
		return errors.New("Vertex credential deletion is already in progress")
	}
	s.deleting[reference] = struct{}{}
	s.generations[reference]++
	delete(s.cache, reference)
	s.mu.Unlock()
	errDelete := s.delegate.Delete(ctx, reference)
	s.mu.Lock()
	delete(s.deleting, reference)
	if _, running := s.inflight[reference]; !running {
		delete(s.generations, reference)
	}
	s.mu.Unlock()
	return errDelete
}

// exchange loads one protected credential and performs the signed assertion exchange.
// exchange 加载一个受保护凭据并执行已签名断言交换。
func (s *VertexAccessTokenStore) exchange(ctx context.Context, reference string, now time.Time) (string, time.Time, error) {
	protected, errProtected := s.delegate.Get(ctx, reference)
	if errProtected != nil {
		return "", time.Time{}, errProtected
	}
	defer clear(protected)
	credential, errCredential := UnmarshalVertexCredential(protected)
	if errCredential != nil {
		return "", time.Time{}, errCredential
	}
	var serviceAccount VertexServiceAccount
	if errDecode := json.Unmarshal(credential.ServiceAccount, &serviceAccount); errDecode != nil {
		return "", time.Time{}, fmt.Errorf("decode normalized Vertex service account: %w", errDecode)
	}
	assertion, errAssertion := buildVertexJWTAssertion(serviceAccount, now)
	if errAssertion != nil {
		return "", time.Time{}, errAssertion
	}
	form := url.Values{"grant_type": []string{vertexJWTGrantType}, "assertion": []string{assertion}}
	request, errRequest := http.NewRequestWithContext(ctx, http.MethodPost, vertexTokenURL, strings.NewReader(form.Encode()))
	if errRequest != nil {
		return "", time.Time{}, fmt.Errorf("create Vertex OAuth request: %w", errRequest)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, errDo := s.client.Do(request)
	if errDo != nil {
		return "", time.Time{}, fmt.Errorf("exchange Vertex service-account assertion: %w", errDo)
	}
	if response == nil || response.Body == nil {
		return "", time.Time{}, errors.New("Vertex OAuth response body is missing")
	}
	defer response.Body.Close()
	body, errRead := io.ReadAll(io.LimitReader(response.Body, vertexTokenResponseLimit+1))
	if errRead != nil {
		return "", time.Time{}, fmt.Errorf("read Vertex OAuth response: %w", errRead)
	}
	defer clear(body)
	if len(body) > vertexTokenResponseLimit {
		return "", time.Time{}, errors.New("Vertex OAuth response exceeds the size limit")
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return "", time.Time{}, fmt.Errorf("Vertex OAuth exchange returned HTTP %d", response.StatusCode)
	}
	var tokenResponse vertexOAuthTokenResponse
	if errDecode := json.Unmarshal(body, &tokenResponse); errDecode != nil {
		return "", time.Time{}, errors.New("Vertex OAuth response is not valid JSON")
	}
	if strings.TrimSpace(tokenResponse.AccessToken) == "" || !strings.EqualFold(strings.TrimSpace(tokenResponse.TokenType), "Bearer") || tokenResponse.ExpiresIn <= 0 || tokenResponse.ExpiresIn > int64((24*time.Hour)/time.Second) {
		return "", time.Time{}, errors.New("Vertex OAuth response is incomplete")
	}
	return tokenResponse.AccessToken, now.Add(time.Duration(tokenResponse.ExpiresIn) * time.Second), nil
}

// buildVertexJWTAssertion creates and signs one Google OAuth service-account assertion.
// buildVertexJWTAssertion 创建并签名一个 Google OAuth 服务账号断言。
func buildVertexJWTAssertion(serviceAccount VertexServiceAccount, now time.Time) (string, error) {
	if errValidate := validateVertexServiceAccount(serviceAccount); errValidate != nil {
		return "", errValidate
	}
	header := vertexJWTHeader{Algorithm: "RS256", Type: "JWT", KeyID: strings.TrimSpace(serviceAccount.PrivateKeyID)}
	claims := vertexJWTClaims{
		Issuer:    strings.TrimSpace(serviceAccount.ClientEmail),
		Scope:     vertexCloudPlatformScope,
		Audience:  vertexTokenURL,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
	}
	headerJSON, errHeader := json.Marshal(header)
	if errHeader != nil {
		return "", fmt.Errorf("encode Vertex JWT header: %w", errHeader)
	}
	claimsJSON, errClaims := json.Marshal(claims)
	if errClaims != nil {
		return "", fmt.Errorf("encode Vertex JWT claims: %w", errClaims)
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encodedClaims := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := encodedHeader + "." + encodedClaims
	privateKey, errPrivateKey := parseVertexRSAPrivateKey(serviceAccount.PrivateKey)
	if errPrivateKey != nil {
		return "", errPrivateKey
	}
	digest := sha256.Sum256([]byte(signingInput))
	signature, errSign := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if errSign != nil {
		return "", fmt.Errorf("sign Vertex JWT assertion: %w", errSign)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

// parseVertexRSAPrivateKey parses the normalized PKCS#1 private key held by a protected credential.
// parseVertexRSAPrivateKey 解析受保护凭据中规范化后的 PKCS#1 私钥。
func parseVertexRSAPrivateKey(value string) (*rsa.PrivateKey, error) {
	block, trailing := pem.Decode([]byte(value))
	if block == nil || len(strings.TrimSpace(string(trailing))) != 0 || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("Vertex private key is not one normalized RSA PRIVATE KEY block")
	}
	privateKey, errParse := x509.ParsePKCS1PrivateKey(block.Bytes)
	if errParse != nil {
		return nil, fmt.Errorf("parse Vertex RSA private key: %w", errParse)
	}
	return privateKey, nil
}
