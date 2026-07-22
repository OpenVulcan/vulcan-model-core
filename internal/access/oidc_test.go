package access

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestOIDCVerifierPreservesIssuerAndOwnsRedirectPolicy verifies exact issuer semantics and forbids injected redirect behavior.
// TestOIDCVerifierPreservesIssuerAndOwnsRedirectPolicy 验证精确颁发者语义，并禁止注入客户端改变重定向策略。
func TestOIDCVerifierPreservesIssuerAndOwnsRedirectPolicy(t *testing.T) {
	privateKey, errKey := rsa.GenerateKey(rand.Reader, 2048)
	if errKey != nil {
		t.Fatalf("generate RSA key: %v", errKey)
	}
	var redirectedReads atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		redirectedReads.Add(1)
		exponent := big.NewInt(int64(privateKey.PublicKey.E)).Bytes()
		_ = json.NewEncoder(writer).Encode(oidcJWKS{Keys: []oidcJWK{{KeyType: "RSA", KeyID: "key", Use: "sig", Algorithm: "RS256", Modulus: base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes()), Exponent: base64.RawURLEncoding.EncodeToString(exponent)}}})
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, target.URL, http.StatusFound)
	}))
	defer redirect.Close()
	client := redirect.Client()
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return nil }
	now := time.Date(2026, 7, 22, 3, 0, 0, 0, time.UTC)
	issuer := redirect.URL + "/"
	verifier, errVerifier := NewOIDCVerifier(OIDCVerifierConfig{Issuer: issuer, Audience: "router", JWKSURL: redirect.URL, HTTPClient: client, CacheTTL: time.Minute, Now: func() time.Time { return now }})
	if errVerifier != nil {
		t.Fatalf("NewOIDCVerifier() error = %v", errVerifier)
	}
	if verifier.issuer != issuer {
		t.Fatalf("issuer = %q, want exact %q", verifier.issuer, issuer)
	}
	claims := oidcClaims{Issuer: issuer, Subject: "subject", Audience: oidcAudience{"router"}, ExpiresAt: float64(now.Add(time.Hour).Unix()), TenantID: "tenant", ProjectID: "project", Roles: []string{string(RoleCaller)}}
	if _, errVerify := verifier.Verify(context.Background(), encodeOIDCTestToken(t, privateKey, "key", claims)); errVerify == nil {
		t.Fatal("Verify() followed a metadata redirect")
	}
	if redirectedReads.Load() != 0 {
		t.Fatalf("redirect target reads = %d, want 0", redirectedReads.Load())
	}
}

// TestOIDCVerifierRateLimitsUnknownKeyRefresh verifies attacker-selected key identifiers cannot trigger a request storm.
// TestOIDCVerifierRateLimitsUnknownKeyRefresh 验证攻击者选择的密钥标识无法触发请求风暴。
func TestOIDCVerifierRateLimitsUnknownKeyRefresh(t *testing.T) {
	privateKey, errKey := rsa.GenerateKey(rand.Reader, 2048)
	if errKey != nil {
		t.Fatalf("generate RSA key: %v", errKey)
	}
	var reads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		reads.Add(1)
		exponent := big.NewInt(int64(privateKey.PublicKey.E)).Bytes()
		_ = json.NewEncoder(writer).Encode(oidcJWKS{Keys: []oidcJWK{{KeyType: "RSA", KeyID: "trusted", Use: "sig", Algorithm: "RS256", Modulus: base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes()), Exponent: base64.RawURLEncoding.EncodeToString(exponent)}}})
	}))
	defer server.Close()
	now := time.Date(2026, 7, 22, 4, 0, 0, 0, time.UTC)
	verifier, errVerifier := NewOIDCVerifier(OIDCVerifierConfig{Issuer: server.URL, Audience: "router", JWKSURL: server.URL, HTTPClient: server.Client(), CacheTTL: time.Minute, Now: func() time.Time { return now }})
	if errVerifier != nil {
		t.Fatalf("NewOIDCVerifier() error = %v", errVerifier)
	}
	claims := oidcClaims{Issuer: server.URL, Subject: "subject", Audience: oidcAudience{"router"}, ExpiresAt: float64(now.Add(time.Hour).Unix()), TenantID: "tenant", ProjectID: "project", Roles: []string{string(RoleCaller)}}
	if _, errVerify := verifier.Verify(context.Background(), encodeOIDCTestToken(t, privateKey, "trusted", claims)); errVerify != nil {
		t.Fatalf("Verify() trusted token error = %v", errVerify)
	}
	for index := 0; index < 10; index++ {
		if _, errVerify := verifier.Verify(context.Background(), encodeOIDCTestToken(t, privateKey, "unknown", claims)); errVerify == nil {
			t.Fatal("Verify() accepted an unknown key identifier")
		}
	}
	if reads.Load() != 1 {
		t.Fatalf("JWKS reads = %d, want 1", reads.Load())
	}
}

// TestOIDCVerifierValidatesRS256IdentityAndClosedClaims verifies one real signed token and rejects unsafe claim changes.
// TestOIDCVerifierValidatesRS256IdentityAndClosedClaims 验证一个真实签名 Token 并拒绝不安全的声明变更。
func TestOIDCVerifierValidatesRS256IdentityAndClosedClaims(t *testing.T) {
	privateKey, errKey := rsa.GenerateKey(rand.Reader, 2048)
	if errKey != nil {
		t.Fatalf("generate RSA key: %v", errKey)
	}
	keyID := "router-test-key"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/jwks" {
			http.NotFound(writer, request)
			return
		}
		exponent := big.NewInt(int64(privateKey.PublicKey.E)).Bytes()
		_ = json.NewEncoder(writer).Encode(oidcJWKS{Keys: []oidcJWK{{KeyType: "RSA", KeyID: keyID, Use: "sig", Algorithm: "RS256", Modulus: base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes()), Exponent: base64.RawURLEncoding.EncodeToString(exponent)}}})
	}))
	defer server.Close()
	now := time.Date(2026, 7, 22, 1, 0, 0, 0, time.UTC)
	verifier, errVerifier := NewOIDCVerifier(OIDCVerifierConfig{Issuer: server.URL, Audience: "vulcan-model-router", JWKSURL: server.URL + "/jwks", HTTPClient: server.Client(), CacheTTL: time.Minute, Now: func() time.Time { return now }})
	if errVerifier != nil {
		t.Fatalf("NewOIDCVerifier() error = %v", errVerifier)
	}
	claims := oidcClaims{Issuer: server.URL, Subject: "subject-1", Audience: oidcAudience{"vulcan-model-router"}, ExpiresAt: float64(now.Add(time.Hour).Unix()), IssuedAt: float64(now.Add(-time.Minute).Unix()), OrganizationID: "organization-1", TenantID: "tenant-1", ProjectID: "project-1", Roles: []string{string(RoleCaller)}}
	token := encodeOIDCTestToken(t, privateKey, keyID, claims)
	principal, errVerify := verifier.Verify(context.Background(), token)
	if errVerify != nil || principal.SubjectID != claims.Subject || principal.OrganizationID != claims.OrganizationID || principal.TenantID != claims.TenantID || principal.ProjectID != claims.ProjectID || len(principal.Roles) != 1 || principal.Roles[0] != RoleCaller {
		t.Fatalf("Verify() = (%+v, %v)", principal, errVerify)
	}
	claims.Audience = oidcAudience{"another-service"}
	if _, errAudience := verifier.Verify(context.Background(), encodeOIDCTestToken(t, privateKey, keyID, claims)); errAudience == nil {
		t.Fatal("Verify() accepted an incorrect audience")
	}
	claims.Audience = oidcAudience{"vulcan-model-router"}
	claims.Roles = []string{"owner"}
	if _, errRole := verifier.Verify(context.Background(), encodeOIDCTestToken(t, privateKey, keyID, claims)); errRole == nil {
		t.Fatal("Verify() accepted an unknown Router role")
	}
}

// TestOIDCVerifierRejectsExpiredAndWronglySignedTokens verifies expiry and signature are mandatory before identity use.
// TestOIDCVerifierRejectsExpiredAndWronglySignedTokens 验证在使用身份前必须通过到期时间与签名校验。
func TestOIDCVerifierRejectsExpiredAndWronglySignedTokens(t *testing.T) {
	trustedKey, errTrustedKey := rsa.GenerateKey(rand.Reader, 2048)
	if errTrustedKey != nil {
		t.Fatalf("generate trusted RSA key: %v", errTrustedKey)
	}
	untrustedKey, errUntrustedKey := rsa.GenerateKey(rand.Reader, 2048)
	if errUntrustedKey != nil {
		t.Fatalf("generate untrusted RSA key: %v", errUntrustedKey)
	}
	keyID := "trusted-key"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		exponent := big.NewInt(int64(trustedKey.PublicKey.E)).Bytes()
		_ = json.NewEncoder(writer).Encode(oidcJWKS{Keys: []oidcJWK{{KeyType: "RSA", KeyID: keyID, Use: "sig", Algorithm: "RS256", Modulus: base64.RawURLEncoding.EncodeToString(trustedKey.PublicKey.N.Bytes()), Exponent: base64.RawURLEncoding.EncodeToString(exponent)}}})
	}))
	defer server.Close()
	now := time.Date(2026, 7, 22, 2, 0, 0, 0, time.UTC)
	verifier, errVerifier := NewOIDCVerifier(OIDCVerifierConfig{Issuer: server.URL, Audience: "router", JWKSURL: server.URL, HTTPClient: server.Client(), CacheTTL: time.Minute, ClockSkew: time.Second, Now: func() time.Time { return now }})
	if errVerifier != nil {
		t.Fatalf("NewOIDCVerifier() error = %v", errVerifier)
	}
	claims := oidcClaims{Issuer: server.URL, Subject: "subject", Audience: oidcAudience{"router"}, ExpiresAt: float64(now.Add(-time.Minute).Unix()), TenantID: "tenant", ProjectID: "project", Roles: []string{string(RoleCaller)}}
	if _, errExpired := verifier.Verify(context.Background(), encodeOIDCTestToken(t, trustedKey, keyID, claims)); errExpired == nil {
		t.Fatal("Verify() accepted an expired token")
	}
	claims.ExpiresAt = float64(now.Add(time.Hour).Unix())
	if _, errSignature := verifier.Verify(context.Background(), encodeOIDCTestToken(t, untrustedKey, keyID, claims)); errSignature == nil {
		t.Fatal("Verify() accepted a token signed by an untrusted key")
	}
}

// encodeOIDCTestToken creates one compact RS256 JWT for verifier tests.
// encodeOIDCTestToken 为校验器测试创建一个紧凑 RS256 JWT。
func encodeOIDCTestToken(t *testing.T, privateKey *rsa.PrivateKey, keyID string, claims oidcClaims) string {
	t.Helper()
	headerBytes, errHeader := json.Marshal(oidcJWTHeader{Algorithm: "RS256", KeyID: keyID, Type: "JWT"})
	if errHeader != nil {
		t.Fatalf("marshal JWT header: %v", errHeader)
	}
	claimsBytes, errClaims := json.Marshal(claims)
	if errClaims != nil {
		t.Fatalf("marshal JWT claims: %v", errClaims)
	}
	header := base64.RawURLEncoding.EncodeToString(headerBytes)
	payload := base64.RawURLEncoding.EncodeToString(claimsBytes)
	signed := header + "." + payload
	digest := sha256.Sum256([]byte(signed))
	signature, errSign := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if errSign != nil {
		t.Fatalf("sign JWT: %v", errSign)
	}
	return signed + "." + base64.RawURLEncoding.EncodeToString(signature)
}
