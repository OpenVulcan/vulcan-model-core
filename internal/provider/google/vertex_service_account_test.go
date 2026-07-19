package google

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
)

// TestNormalizeVertexServiceAccountJSONPreservesFieldsAndRepairsPKCS8 verifies the copied key normalization boundary.
// TestNormalizeVertexServiceAccountJSONPreservesFieldsAndRepairsPKCS8 校验复制的密钥规范化边界。
func TestNormalizeVertexServiceAccountJSONPreservesFieldsAndRepairsPKCS8(t *testing.T) {
	t.Parallel()
	privateKey, errKey := rsa.GenerateKey(rand.Reader, 2048)
	if errKey != nil {
		t.Fatalf("generate RSA key: %v", errKey)
	}
	encodedPKCS8, errPKCS8 := x509.MarshalPKCS8PrivateKey(privateKey)
	if errPKCS8 != nil {
		t.Fatalf("marshal PKCS#8 key: %v", errPKCS8)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedPKCS8}))
	keyPEM = "\x1b[31m" + strings.ReplaceAll(keyPEM, "\n", "\r\n") + "\x1b[0m"
	payload := map[string]any{
		"type":              "service_account",
		"project_id":        "vertex-project",
		"private_key_id":    "key-id",
		"private_key":       keyPEM,
		"client_email":      "vertex@vertex-project.iam.gserviceaccount.com",
		"token_uri":         vertexTokenURL,
		"universe_domain":   "googleapis.com",
		"provider_sequence": json.Number("9007199254740993"),
	}
	raw, errMarshal := json.Marshal(payload)
	if errMarshal != nil {
		t.Fatalf("marshal fixture: %v", errMarshal)
	}
	normalized, errNormalize := NormalizeVertexServiceAccountJSON(raw)
	if errNormalize != nil {
		t.Fatalf("normalize service account: %v", errNormalize)
	}
	var document map[string]any
	if errDecode := json.Unmarshal(normalized, &document); errDecode != nil {
		t.Fatalf("decode normalized document: %v", errDecode)
	}
	if document["universe_domain"] != "googleapis.com" {
		t.Fatalf("provider-owned fields were not preserved: %#v", document)
	}
	var rawDocument map[string]json.RawMessage
	if errDecode := json.Unmarshal(normalized, &rawDocument); errDecode != nil {
		t.Fatalf("decode normalized raw document: %v", errDecode)
	}
	if string(rawDocument["provider_sequence"]) != "9007199254740993" {
		t.Fatalf("provider-owned numeric field changed: %s", rawDocument["provider_sequence"])
	}
	normalizedKey, validKey := document["private_key"].(string)
	if !validKey {
		t.Fatalf("normalized private_key has unexpected type: %#v", document["private_key"])
	}
	block, trailing := pem.Decode([]byte(normalizedKey))
	if block == nil || block.Type != "RSA PRIVATE KEY" || len(strings.TrimSpace(string(trailing))) != 0 {
		t.Fatalf("normalized key is not one PKCS#1 RSA block")
	}
	parsed, errParse := x509.ParsePKCS1PrivateKey(block.Bytes)
	if errParse != nil {
		t.Fatalf("parse normalized PKCS#1 key: %v", errParse)
	}
	if parsed.PublicKey.N.Cmp(privateKey.PublicKey.N) != 0 {
		t.Fatalf("normalization changed RSA key material")
	}
}

// TestParseVertexCredentialDerivesImmutableMetadata verifies project, identity, region, and protected-document checks.
// TestParseVertexCredentialDerivesImmutableMetadata 校验项目、身份、区域与受保护文档检查。
func TestParseVertexCredentialDerivesImmutableMetadata(t *testing.T) {
	t.Parallel()
	raw, _ := newVertexServiceAccountJSON(t)
	credential, errParse := ParseVertexCredential(raw, "")
	if errParse != nil {
		t.Fatalf("parse Vertex credential: %v", errParse)
	}
	if credential.Type != vertexCredentialType || credential.ProjectID != "vertex-project" || credential.Email != "vertex@vertex-project.iam.gserviceaccount.com" || credential.Location != vertexDefaultLocation {
		t.Fatalf("unexpected derived credential: %#v", credential)
	}
	protected, errMarshal := MarshalVertexCredential(credential)
	if errMarshal != nil {
		t.Fatalf("marshal protected credential: %v", errMarshal)
	}
	restored, errUnmarshal := UnmarshalVertexCredential(protected)
	if errUnmarshal != nil {
		t.Fatalf("unmarshal protected credential: %v", errUnmarshal)
	}
	if restored.ProjectID != credential.ProjectID || restored.Email != credential.Email || restored.Location != credential.Location {
		t.Fatalf("protected credential changed derived metadata: %#v", restored)
	}
	credential.ProjectID = "tampered-project"
	if _, errTampered := MarshalVertexCredential(credential); errTampered == nil {
		t.Fatalf("expected tampered protected metadata to be rejected")
	}
}

// TestParseVertexCredentialRejectsUntrustedTokenEndpoint verifies signed assertions cannot be redirected by uploaded JSON.
// TestParseVertexCredentialRejectsUntrustedTokenEndpoint 校验上传 JSON 无法重定向已签名断言。
func TestParseVertexCredentialRejectsUntrustedTokenEndpoint(t *testing.T) {
	t.Parallel()
	raw, _ := newVertexServiceAccountJSON(t)
	var payload map[string]any
	if errDecode := json.Unmarshal(raw, &payload); errDecode != nil {
		t.Fatalf("decode fixture: %v", errDecode)
	}
	payload["token_uri"] = "https://attacker.example/token"
	tampered, errMarshal := json.Marshal(payload)
	if errMarshal != nil {
		t.Fatalf("marshal tampered fixture: %v", errMarshal)
	}
	if _, errParse := ParseVertexCredential(tampered, "us-central1"); errParse == nil || !strings.Contains(errParse.Error(), "Google OAuth token endpoint") {
		t.Fatalf("expected untrusted token endpoint rejection, got %v", errParse)
	}
	if _, errLocation := ParseVertexCredential(raw, "us-central1.attacker.example"); errLocation == nil {
		t.Fatalf("expected unsafe location rejection")
	}
}

// newVertexServiceAccountJSON creates one valid generated RSA service-account fixture.
// newVertexServiceAccountJSON 创建一个有效的动态 RSA 服务账号 Fixture。
func newVertexServiceAccountJSON(t *testing.T) ([]byte, *rsa.PrivateKey) {
	t.Helper()
	privateKey, errKey := rsa.GenerateKey(rand.Reader, 2048)
	if errKey != nil {
		t.Fatalf("generate RSA key: %v", errKey)
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	payload := VertexServiceAccount{
		Type: "service_account", ProjectID: "vertex-project", PrivateKeyID: "key-id",
		PrivateKey: string(privateKeyPEM), ClientEmail: "vertex@vertex-project.iam.gserviceaccount.com", TokenURI: vertexTokenURL,
	}
	raw, errMarshal := json.Marshal(payload)
	if errMarshal != nil {
		t.Fatalf("marshal service-account fixture: %v", errMarshal)
	}
	return raw, privateKey
}
