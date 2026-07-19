package google

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

// TestVertexAccessTokenStoreRefusesRedirectsWithoutMutatingCaller verifies signed assertions cannot cross token-endpoint redirects.
// TestVertexAccessTokenStoreRefusesRedirectsWithoutMutatingCaller 验证签名断言不能跨越 Token 入口重定向。
func TestVertexAccessTokenStoreRefusesRedirectsWithoutMutatingCaller(t *testing.T) {
	callerRedirectError := errors.New("caller redirect policy")
	caller := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return callerRedirectError }}
	store, errStore := NewVertexAccessTokenStore(secret.NewMemoryStore(), caller)
	if errStore != nil {
		t.Fatalf("NewVertexAccessTokenStore() error = %v", errStore)
	}
	if store.client == caller {
		t.Fatal("Vertex token store retained the caller-owned HTTP client")
	}
	if errRedirect := store.client.CheckRedirect(nil, nil); !errors.Is(errRedirect, http.ErrUseLastResponse) {
		t.Fatalf("Vertex redirect error = %v, want http.ErrUseLastResponse", errRedirect)
	}
	if errRedirect := caller.CheckRedirect(nil, nil); !errors.Is(errRedirect, callerRedirectError) {
		t.Fatalf("caller redirect error = %v, want original policy", errRedirect)
	}
}

// vertexRoundTripFunc adapts a function to an HTTP round tripper for isolated OAuth tests.
// vertexRoundTripFunc 将函数适配为 HTTP RoundTripper，用于隔离 OAuth 测试。
type vertexRoundTripFunc func(*http.Request) (*http.Response, error)

// RoundTrip executes the configured isolated request handler.
// RoundTrip 执行已配置的隔离请求处理函数。
func (f vertexRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

// TestVertexAccessTokenStoreSignsCachesAndRefreshes verifies exact JWT exchange and concurrent projection semantics.
// TestVertexAccessTokenStoreSignsCachesAndRefreshes 校验精确 JWT 交换与并发投影语义。
func TestVertexAccessTokenStoreSignsCachesAndRefreshes(t *testing.T) {
	t.Parallel()
	raw, privateKey := newVertexServiceAccountJSON(t)
	credential, errCredential := ParseVertexCredential(raw, "europe-west1")
	if errCredential != nil {
		t.Fatalf("parse Vertex credential: %v", errCredential)
	}
	protected, errProtected := MarshalVertexCredential(credential)
	if errProtected != nil {
		t.Fatalf("marshal Vertex credential: %v", errProtected)
	}
	delegate := secret.NewMemoryStore()
	reference, errPut := delegate.Put(context.Background(), protected)
	if errPut != nil {
		t.Fatalf("store Vertex credential: %v", errPut)
	}
	fixedNow := time.Date(2026, time.July, 19, 1, 2, 3, 0, time.UTC)
	currentNow := fixedNow
	var requestCount atomic.Int32
	client := &http.Client{Transport: vertexRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		call := requestCount.Add(1)
		verifyVertexTokenRequest(t, request, privateKey, currentNow)
		body := fmt.Sprintf(`{"access_token":"vertex-access-%d","token_type":"Bearer","expires_in":3600}`, call)
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: request}, nil
	})}
	store, errStore := NewVertexAccessTokenStore(delegate, client)
	if errStore != nil {
		t.Fatalf("create Vertex access-token store: %v", errStore)
	}
	store.now = func() time.Time { return currentNow }

	const concurrentReaders = 12
	var waitGroup sync.WaitGroup
	waitGroup.Add(concurrentReaders)
	errorsByReader := make(chan error, concurrentReaders)
	for index := 0; index < concurrentReaders; index++ {
		go func() {
			defer waitGroup.Done()
			token, errGet := store.Get(context.Background(), reference)
			if errGet != nil {
				errorsByReader <- errGet
				return
			}
			if string(token) != "vertex-access-1" {
				errorsByReader <- fmt.Errorf("unexpected projected token %q", token)
			}
		}()
	}
	waitGroup.Wait()
	close(errorsByReader)
	for errReader := range errorsByReader {
		t.Errorf("concurrent token projection: %v", errReader)
	}
	if requestCount.Load() != 1 {
		t.Fatalf("expected one deduplicated OAuth exchange, got %d", requestCount.Load())
	}
	currentNow = fixedNow.Add(58 * time.Minute)
	if _, errCached := store.Get(context.Background(), reference); errCached != nil {
		t.Fatalf("read cached token: %v", errCached)
	}
	if requestCount.Load() != 1 {
		t.Fatalf("valid cached token unexpectedly refreshed")
	}
	currentNow = fixedNow.Add(59*time.Minute + 30*time.Second)
	refreshed, errRefreshed := store.Get(context.Background(), reference)
	if errRefreshed != nil {
		t.Fatalf("refresh near-expiry token: %v", errRefreshed)
	}
	if string(refreshed) != "vertex-access-2" || requestCount.Load() != 2 {
		t.Fatalf("unexpected refreshed token %q after %d exchanges", refreshed, requestCount.Load())
	}
	if errDelete := store.Delete(context.Background(), reference); errDelete != nil {
		t.Fatalf("delete Vertex credential: %v", errDelete)
	}
	if _, errDeleted := store.Get(context.Background(), reference); errDeleted == nil {
		t.Fatalf("expected deleted credential lookup to fail")
	}
}

// TestVertexAccessTokenStoreLeaderCancellationDoesNotFailWaiters verifies a shared OAuth exchange survives its initiating request.
// TestVertexAccessTokenStoreLeaderCancellationDoesNotFailWaiters 验证共享 OAuth 交换不会随发起请求取消而使等待者失败。
func TestVertexAccessTokenStoreLeaderCancellationDoesNotFailWaiters(t *testing.T) {
	t.Parallel()
	raw, _ := newVertexServiceAccountJSON(t)
	credential, errCredential := ParseVertexCredential(raw, "us-central1")
	if errCredential != nil {
		t.Fatalf("parse Vertex credential: %v", errCredential)
	}
	protected, errProtected := MarshalVertexCredential(credential)
	if errProtected != nil {
		t.Fatalf("marshal Vertex credential: %v", errProtected)
	}
	delegate := secret.NewMemoryStore()
	reference, errPut := delegate.Put(context.Background(), protected)
	if errPut != nil {
		t.Fatalf("store Vertex credential: %v", errPut)
	}
	// exchangeStarted confirms the detached provider request exists before the leader is cancelled.
	// exchangeStarted 确认在主请求取消前，分离的供应商请求已经存在。
	exchangeStarted := make(chan struct{}, 2)
	// releaseExchange deterministically completes every simulated provider request.
	// releaseExchange 以确定方式完成每个模拟供应商请求。
	releaseExchange := make(chan struct{})
	var requestCount atomic.Int32
	client := &http.Client{Transport: vertexRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requestCount.Add(1)
		exchangeStarted <- struct{}{}
		<-releaseExchange
		if errContext := request.Context().Err(); errContext != nil {
			return nil, errContext
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"access_token":"shared-vertex-token","token_type":"Bearer","expires_in":3600}`)), Request: request}, nil
	})}
	store, errStore := NewVertexAccessTokenStore(delegate, client)
	if errStore != nil {
		t.Fatalf("create Vertex access-token store: %v", errStore)
	}
	// projectionResult carries one isolated caller outcome without sharing mutable token buffers.
	// projectionResult 携带一个隔离调用方结果且不共享可变 Token 缓冲区。
	type projectionResult struct {
		// token is the projected access token returned to one caller.
		// token 是返回给一个调用方的投影 Access Token。
		token string
		// err is the caller-visible projection failure.
		// err 是调用方可见的投影失败。
		err error
	}
	results := make(chan projectionResult, 2)
	leaderContext, cancelLeader := context.WithCancel(context.Background())
	go func() {
		token, errGet := store.Get(leaderContext, reference)
		results <- projectionResult{token: string(token), err: errGet}
	}()
	<-exchangeStarted
	cancelLeader()
	go func() {
		token, errGet := store.Get(context.Background(), reference)
		results <- projectionResult{token: string(token), err: errGet}
	}()
	close(releaseExchange)
	for index := 0; index < 2; index++ {
		result := <-results
		if result.err != nil || result.token != "shared-vertex-token" {
			t.Fatalf("shared Vertex projection = token %q error %v", result.token, result.err)
		}
	}
	if requestCount.Load() != 1 {
		t.Fatalf("shared Vertex projection performed %d OAuth exchanges, want 1", requestCount.Load())
	}
}

// TestVertexAccessTokenStoreDeletionInvalidatesInflightExchange verifies no caller receives a token crossing the deletion boundary.
// TestVertexAccessTokenStoreDeletionInvalidatesInflightExchange 验证任何调用方都不能收到跨越删除边界的 Token。
func TestVertexAccessTokenStoreDeletionInvalidatesInflightExchange(t *testing.T) {
	raw, _ := newVertexServiceAccountJSON(t)
	credential, errCredential := ParseVertexCredential(raw, "us-central1")
	if errCredential != nil {
		t.Fatalf("ParseVertexCredential() error = %v", errCredential)
	}
	protected, errProtected := MarshalVertexCredential(credential)
	if errProtected != nil {
		t.Fatalf("MarshalVertexCredential() error = %v", errProtected)
	}
	delegate := secret.NewMemoryStore()
	reference, errPut := delegate.Put(context.Background(), protected)
	if errPut != nil {
		t.Fatalf("Put() error = %v", errPut)
	}
	// exchangeStarted proves the OAuth request owns the old credential generation before deletion.
	// exchangeStarted 证明 OAuth 请求在删除前拥有旧凭据代次。
	exchangeStarted := make(chan struct{})
	// releaseExchange lets deletion complete before the simulated provider returns a token.
	// releaseExchange 让删除在模拟供应商返回 Token 前完成。
	releaseExchange := make(chan struct{})
	client := &http.Client{Transport: vertexRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		close(exchangeStarted)
		<-releaseExchange
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"access_token":"deleted-vertex-token","token_type":"Bearer","expires_in":3600}`)), Request: request}, nil
	})}
	store, errStore := NewVertexAccessTokenStore(delegate, client)
	if errStore != nil {
		t.Fatalf("NewVertexAccessTokenStore() error = %v", errStore)
	}
	leaderResult := make(chan error, 1)
	go func() {
		token, errGet := store.Get(context.Background(), reference)
		if len(token) != 0 {
			leaderResult <- fmt.Errorf("deleted exchange returned token %q", token)
			return
		}
		leaderResult <- errGet
	}()
	<-exchangeStarted
	if errDelete := store.Delete(context.Background(), reference); errDelete != nil {
		t.Fatalf("Delete() error = %v", errDelete)
	}
	if token, errGet := store.Get(context.Background(), reference); len(token) != 0 || !errors.Is(errGet, errVertexCredentialInvalidated) {
		t.Fatalf("Get() during invalidated exchange = token %q error %v", token, errGet)
	}
	close(releaseExchange)
	if errLeader := <-leaderResult; !errors.Is(errLeader, errVertexCredentialInvalidated) {
		t.Fatalf("leader Get() error = %v, want errVertexCredentialInvalidated", errLeader)
	}
	store.mu.Lock()
	_, hasInflight := store.inflight[reference]
	_, hasGeneration := store.generations[reference]
	_, isDeleting := store.deleting[reference]
	store.mu.Unlock()
	if hasInflight || hasGeneration || isDeleting {
		t.Fatalf("deletion state leaked: inflight=%t generation=%t deleting=%t", hasInflight, hasGeneration, isDeleting)
	}
}

// TestVertexAccessTokenStoreRejectsUnsafeResponsesWithoutLeakingBodies verifies bounded sanitized OAuth failures.
// TestVertexAccessTokenStoreRejectsUnsafeResponsesWithoutLeakingBodies 校验受限且脱敏的 OAuth 失败。
func TestVertexAccessTokenStoreRejectsUnsafeResponsesWithoutLeakingBodies(t *testing.T) {
	t.Parallel()
	raw, _ := newVertexServiceAccountJSON(t)
	credential, errCredential := ParseVertexCredential(raw, "global")
	if errCredential != nil {
		t.Fatalf("parse Vertex credential: %v", errCredential)
	}
	protected, errProtected := MarshalVertexCredential(credential)
	if errProtected != nil {
		t.Fatalf("marshal Vertex credential: %v", errProtected)
	}
	delegate := secret.NewMemoryStore()
	reference, errPut := delegate.Put(context.Background(), protected)
	if errPut != nil {
		t.Fatalf("store Vertex credential: %v", errPut)
	}
	client := &http.Client{Transport: vertexRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusUnauthorized, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"error_description":"upstream-private-detail"}`)), Request: request}, nil
	})}
	store, errStore := NewVertexAccessTokenStore(delegate, client)
	if errStore != nil {
		t.Fatalf("create Vertex access-token store: %v", errStore)
	}
	_, errGet := store.Get(context.Background(), reference)
	if errGet == nil || !strings.Contains(errGet.Error(), "HTTP 401") {
		t.Fatalf("expected typed HTTP status failure, got %v", errGet)
	}
	if strings.Contains(errGet.Error(), "upstream-private-detail") {
		t.Fatalf("OAuth failure leaked upstream response body: %v", errGet)
	}
}

// verifyVertexTokenRequest validates exact endpoint, form, claims, and RS256 signature.
// verifyVertexTokenRequest 校验精确入口、表单、Claims 与 RS256 签名。
func verifyVertexTokenRequest(t *testing.T, request *http.Request, publicKeyOwner *rsa.PrivateKey, now time.Time) {
	t.Helper()
	if request.Method != http.MethodPost || request.URL.String() != vertexTokenURL {
		t.Errorf("unexpected Vertex OAuth target: %s %s", request.Method, request.URL.String())
	}
	if request.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || request.Header.Get("Accept") != "application/json" {
		t.Errorf("unexpected Vertex OAuth headers: %#v", request.Header)
	}
	body, errRead := io.ReadAll(request.Body)
	if errRead != nil {
		t.Errorf("read Vertex OAuth form: %v", errRead)
		return
	}
	form, errForm := url.ParseQuery(string(body))
	if errForm != nil {
		t.Errorf("parse Vertex OAuth form: %v", errForm)
		return
	}
	if form.Get("grant_type") != vertexJWTGrantType || len(form) != 2 {
		t.Errorf("unexpected Vertex OAuth form: %#v", form)
	}
	parts := strings.Split(form.Get("assertion"), ".")
	if len(parts) != 3 {
		t.Errorf("Vertex assertion must contain three JWT segments")
		return
	}
	headerBytes, errHeader := base64.RawURLEncoding.DecodeString(parts[0])
	claimsBytes, errClaims := base64.RawURLEncoding.DecodeString(parts[1])
	signature, errSignature := base64.RawURLEncoding.DecodeString(parts[2])
	if errHeader != nil || errClaims != nil || errSignature != nil {
		t.Errorf("decode Vertex assertion segments: header=%v claims=%v signature=%v", errHeader, errClaims, errSignature)
		return
	}
	var header vertexJWTHeader
	if errDecode := json.Unmarshal(headerBytes, &header); errDecode != nil {
		t.Errorf("decode Vertex JWT header: %v", errDecode)
	}
	if header.Algorithm != "RS256" || header.Type != "JWT" || header.KeyID != "key-id" {
		t.Errorf("unexpected Vertex JWT header: %#v", header)
	}
	var claims vertexJWTClaims
	if errDecode := json.Unmarshal(claimsBytes, &claims); errDecode != nil {
		t.Errorf("decode Vertex JWT claims: %v", errDecode)
	}
	if claims.Issuer != "vertex@vertex-project.iam.gserviceaccount.com" || claims.Scope != vertexCloudPlatformScope || claims.Audience != vertexTokenURL || claims.IssuedAt != now.Unix() || claims.ExpiresAt != now.Add(time.Hour).Unix() {
		t.Errorf("unexpected Vertex JWT claims: %#v", claims)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if errVerify := rsa.VerifyPKCS1v15(&publicKeyOwner.PublicKey, crypto.SHA256, digest[:], signature); errVerify != nil {
		t.Errorf("verify Vertex JWT signature: %v", errVerify)
	}
}
