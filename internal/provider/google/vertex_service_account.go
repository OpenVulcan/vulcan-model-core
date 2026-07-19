package google

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

const (
	// vertexCredentialType distinguishes protected Vertex documents from arbitrary JSON credentials.
	// vertexCredentialType 将受保护 Vertex 文档与任意 JSON 凭据区分开。
	vertexCredentialType = "vertex"
	// vertexDefaultLocation is CLIProxyAPI's exact fallback region for imported Vertex credentials.
	// vertexDefaultLocation 是 CLIProxyAPI 导入 Vertex 凭据时使用的精确回退区域。
	vertexDefaultLocation = "us-central1"
	// vertexTokenURL is the sole Google-owned OAuth endpoint accepted for system Vertex credentials.
	// vertexTokenURL 是系统 Vertex 凭据唯一接受的 Google 官方 OAuth 入口。
	vertexTokenURL = "https://oauth2.googleapis.com/token"
)

// VertexServiceAccount is the exact service-account subset required for RSA JWT token exchange.
// VertexServiceAccount 是 RSA JWT Token 交换所需的精确服务账号字段子集。
type VertexServiceAccount struct {
	// Type must identify a Google service account.
	// Type 必须标识 Google 服务账号。
	Type string `json:"type"`
	// ProjectID owns Vertex resources and endpoint paths.
	// ProjectID 拥有 Vertex 资源与入口路径。
	ProjectID string `json:"project_id"`
	// PrivateKeyID optionally identifies the signing key in the JWT header.
	// PrivateKeyID 可选地在 JWT Header 中标识签名密钥。
	PrivateKeyID string `json:"private_key_id"`
	// PrivateKey is the normalized RSA private key.
	// PrivateKey 是规范化后的 RSA 私钥。
	PrivateKey string `json:"private_key"`
	// ClientEmail is the JWT issuer.
	// ClientEmail 是 JWT 签发者。
	ClientEmail string `json:"client_email"`
	// TokenURI is the service-account OAuth token endpoint.
	// TokenURI 是服务账号 OAuth Token 入口。
	TokenURI string `json:"token_uri"`
}

// VertexCredential stores one normalized service account with its server-derived routing scope.
// VertexCredential 存储一个规范化服务账号及其由服务端派生的路由作用域。
type VertexCredential struct {
	// ServiceAccount preserves the normalized provider document for token exchange.
	// ServiceAccount 为 Token 交换保留规范化后的供应商文档。
	ServiceAccount json.RawMessage `json:"service_account"`
	// ProjectID is derived exclusively from service_account.project_id.
	// ProjectID 仅从 service_account.project_id 派生。
	ProjectID string `json:"project_id"`
	// Email is derived exclusively from service_account.client_email.
	// Email 仅从 service_account.client_email 派生。
	Email string `json:"email"`
	// Location selects the exact Google-owned regional endpoint.
	// Location 选择精确的 Google 区域入口。
	Location string `json:"location"`
	// Type distinguishes this protected document from arbitrary uploaded JSON.
	// Type 将此受保护文档与任意上传 JSON 区分开。
	Type string `json:"type"`
}

// ParseVertexCredential normalizes and validates an uploaded service-account document and routing location.
// ParseVertexCredential 规范化并校验上传的服务账号文档与路由区域。
func ParseVertexCredential(raw []byte, location string) (VertexCredential, error) {
	normalized, errNormalize := NormalizeVertexServiceAccountJSON(raw)
	if errNormalize != nil {
		return VertexCredential{}, errNormalize
	}
	var serviceAccount VertexServiceAccount
	if errDecode := json.Unmarshal(normalized, &serviceAccount); errDecode != nil {
		return VertexCredential{}, fmt.Errorf("decode Vertex service account: %w", errDecode)
	}
	if errValidate := validateVertexServiceAccount(serviceAccount); errValidate != nil {
		return VertexCredential{}, errValidate
	}
	normalizedLocation, errLocation := normalizeVertexLocation(location)
	if errLocation != nil {
		return VertexCredential{}, errLocation
	}
	return VertexCredential{ServiceAccount: append(json.RawMessage(nil), normalized...), ProjectID: strings.TrimSpace(serviceAccount.ProjectID), Email: strings.TrimSpace(serviceAccount.ClientEmail), Location: normalizedLocation, Type: vertexCredentialType}, nil
}

// MarshalVertexCredential serializes one validated protected Vertex document.
// MarshalVertexCredential 序列化一个经过校验的受保护 Vertex 文档。
func MarshalVertexCredential(credential VertexCredential) ([]byte, error) {
	validated, errValidate := ParseVertexCredential(credential.ServiceAccount, credential.Location)
	if errValidate != nil {
		return nil, errValidate
	}
	if credential.Type != vertexCredentialType || credential.ProjectID != validated.ProjectID || credential.Email != validated.Email {
		return nil, errors.New("protected Vertex credential metadata does not match its service account")
	}
	return json.Marshal(validated)
}

// UnmarshalVertexCredential parses and validates one protected Vertex document.
// UnmarshalVertexCredential 解析并校验一个受保护 Vertex 文档。
func UnmarshalVertexCredential(value []byte) (VertexCredential, error) {
	var credential VertexCredential
	if errDecode := json.Unmarshal(value, &credential); errDecode != nil {
		return VertexCredential{}, errors.New("protected Vertex credential is not a service-account document")
	}
	validated, errValidate := ParseVertexCredential(credential.ServiceAccount, credential.Location)
	if errValidate != nil {
		return VertexCredential{}, errValidate
	}
	if credential.Type != vertexCredentialType || credential.ProjectID != validated.ProjectID || credential.Email != validated.Email {
		return VertexCredential{}, errors.New("protected Vertex credential metadata does not match its service account")
	}
	return validated, nil
}

// NormalizeVertexServiceAccountJSON copies CLIProxyAPI's private-key normalization while preserving all provider fields.
// NormalizeVertexServiceAccountJSON 复制 CLIProxyAPI 的私钥规范化逻辑并保留全部供应商字段。
func NormalizeVertexServiceAccountJSON(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, errors.New("service account payload is empty")
	}
	var payload map[string]json.RawMessage
	if errDecode := json.Unmarshal(raw, &payload); errDecode != nil {
		return nil, fmt.Errorf("decode service account payload: %w", errDecode)
	}
	rawPrivateKey, existsPrivateKey := payload["private_key"]
	var privateKey string
	if !existsPrivateKey || json.Unmarshal(rawPrivateKey, &privateKey) != nil {
		return nil, errors.New("service account missing private_key")
	}
	if strings.TrimSpace(privateKey) == "" {
		return nil, errors.New("service account missing private_key")
	}
	normalizedKey, errKey := normalizeVertexPrivateKey(privateKey)
	if errKey != nil {
		return nil, errKey
	}
	encodedPrivateKey, errEncodeKey := json.Marshal(normalizedKey)
	if errEncodeKey != nil {
		return nil, fmt.Errorf("encode normalized service account private key: %w", errEncodeKey)
	}
	payload["private_key"] = encodedPrivateKey
	normalized, errMarshal := json.Marshal(payload)
	if errMarshal != nil {
		return nil, fmt.Errorf("encode normalized service account: %w", errMarshal)
	}
	return normalized, nil
}

// normalizeVertexPrivateKey sanitizes PKCS#1 or PKCS#8 text into one valid RSA PRIVATE KEY block.
// normalizeVertexPrivateKey 将 PKCS#1 或 PKCS#8 文本清理为一个有效 RSA PRIVATE KEY 块。
func normalizeVertexPrivateKey(raw string) (string, error) {
	privateKey := strings.ReplaceAll(raw, "\r\n", "\n")
	privateKey = strings.ReplaceAll(privateKey, "\r", "\n")
	privateKey = stripVertexANSIEscape(privateKey)
	privateKey = strings.ToValidUTF8(privateKey, "")
	privateKey = strings.TrimSpace(privateKey)
	normalized := privateKey
	if block, _ := pem.Decode([]byte(privateKey)); block == nil {
		rebuilt, errRebuild := rebuildVertexPEM(privateKey)
		if errRebuild != nil {
			return "", fmt.Errorf("private_key is not valid pem: %w", errRebuild)
		}
		normalized = rebuilt
	}
	block, _ := pem.Decode([]byte(normalized))
	if block == nil {
		return "", errors.New("private_key pem decode failed")
	}
	rsaBlock, errRSA := ensureVertexRSAPrivateKey(block)
	if errRSA != nil {
		return "", errRSA
	}
	return string(pem.EncodeToMemory(rsaBlock)), nil
}

// ensureVertexRSAPrivateKey validates PKCS#1 keys and converts PKCS#8 RSA keys to PKCS#1.
// ensureVertexRSAPrivateKey 校验 PKCS#1 密钥并将 PKCS#8 RSA 密钥转换为 PKCS#1。
func ensureVertexRSAPrivateKey(block *pem.Block) (*pem.Block, error) {
	if block == nil {
		return nil, errors.New("pem block is nil")
	}
	if block.Type == "RSA PRIVATE KEY" {
		if _, errParse := x509.ParsePKCS1PrivateKey(block.Bytes); errParse != nil {
			return nil, fmt.Errorf("private_key invalid rsa: %w", errParse)
		}
		return block, nil
	}
	if block.Type == "PRIVATE KEY" {
		key, errParse := x509.ParsePKCS8PrivateKey(block.Bytes)
		if errParse != nil {
			return nil, fmt.Errorf("private_key invalid pkcs8: %w", errParse)
		}
		rsaKey, validRSA := key.(*rsa.PrivateKey)
		if !validRSA {
			return nil, errors.New("private_key is not an RSA key")
		}
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}, nil
	}
	if rsaKey, errParse := x509.ParsePKCS1PrivateKey(block.Bytes); errParse == nil {
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}, nil
	}
	if key, errParse := x509.ParsePKCS8PrivateKey(block.Bytes); errParse == nil {
		if rsaKey, validRSA := key.(*rsa.PrivateKey); validRSA {
			return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}, nil
		}
	}
	return nil, errors.New("private_key uses unsupported format")
}

// rebuildVertexPEM reconstructs a PEM block after terminals or editors inserted non-base64 text.
// rebuildVertexPEM 在终端或编辑器插入非 Base64 文本后重建 PEM 块。
func rebuildVertexPEM(raw string) (string, error) {
	kind := "PRIVATE KEY"
	if strings.Contains(raw, "RSA PRIVATE KEY") {
		kind = "RSA PRIVATE KEY"
	}
	header := "-----BEGIN " + kind + "-----"
	footer := "-----END " + kind + "-----"
	start := strings.Index(raw, header)
	end := strings.Index(raw, footer)
	if start < 0 || end <= start {
		return "", errors.New("missing pem markers")
	}
	payload := filterVertexBase64(raw[start+len(header) : end])
	if payload == "" {
		return "", errors.New("private_key base64 payload empty")
	}
	der, errDecode := base64.StdEncoding.DecodeString(payload)
	if errDecode != nil {
		return "", fmt.Errorf("private_key base64 decode failed: %w", errDecode)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der})), nil
}

// filterVertexBase64 preserves only characters valid in a standard padded base64 payload.
// filterVertexBase64 仅保留标准带填充 Base64 载荷中的有效字符。
func filterVertexBase64(value string) string {
	var filtered strings.Builder
	for _, character := range value {
		switch {
		case character >= 'A' && character <= 'Z', character >= 'a' && character <= 'z', character >= '0' && character <= '9', character == '+', character == '/', character == '=':
			filtered.WriteRune(character)
		}
	}
	return filtered.String()
}

// stripVertexANSIEscape removes CSI and OSC terminal escape sequences copied with private-key text.
// stripVertexANSIEscape 移除随私钥文本复制的 CSI 与 OSC 终端转义序列。
func stripVertexANSIEscape(value string) string {
	input := []rune(value)
	output := make([]rune, 0, len(input))
	for index := 0; index < len(input); index++ {
		character := input[index]
		if character != 0x1b {
			output = append(output, character)
			continue
		}
		if index+1 >= len(input) {
			continue
		}
		switch input[index+1] {
		case ']':
			index += 2
			for index < len(input) {
				if input[index] == 0x07 {
					break
				}
				if input[index] == 0x1b && index+1 < len(input) && input[index+1] == '\\' {
					index++
					break
				}
				index++
			}
		case '[':
			index += 2
			for index < len(input) {
				if (input[index] >= 'A' && input[index] <= 'Z') || (input[index] >= 'a' && input[index] <= 'z') {
					break
				}
				index++
			}
		}
	}
	return string(output)
}

// validateVertexServiceAccount enforces the exact fields required by the approved RSA JWT exchange.
// validateVertexServiceAccount 强制校验已批准 RSA JWT 交换所需的精确字段。
func validateVertexServiceAccount(serviceAccount VertexServiceAccount) error {
	if strings.TrimSpace(serviceAccount.Type) != "service_account" || strings.TrimSpace(serviceAccount.ProjectID) == "" || strings.TrimSpace(serviceAccount.ClientEmail) == "" || strings.TrimSpace(serviceAccount.PrivateKey) == "" {
		return errors.New("Vertex service account is incomplete")
	}
	if errProject := validateVertexIdentifier("project_id", serviceAccount.ProjectID); errProject != nil {
		return errProject
	}
	tokenURL, errURL := url.Parse(strings.TrimSpace(serviceAccount.TokenURI))
	if errURL != nil || tokenURL.String() != vertexTokenURL || tokenURL.User != nil || tokenURL.RawQuery != "" || tokenURL.Fragment != "" {
		return errors.New("Vertex service account token_uri must use the Google OAuth token endpoint")
	}
	return nil
}

// normalizeVertexLocation applies CLIProxyAPI's default and rejects values that could alter the Google-owned host.
// normalizeVertexLocation 应用 CLIProxyAPI 默认值并拒绝可能改变 Google 所有 Host 的值。
func normalizeVertexLocation(location string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(location))
	if normalized == "" {
		normalized = vertexDefaultLocation
	}
	if errLocation := validateVertexIdentifier("location", normalized); errLocation != nil {
		return "", errLocation
	}
	return normalized, nil
}

// validateVertexIdentifier accepts only path- and host-safe Google project or location identifiers.
// validateVertexIdentifier 仅接受路径与 Host 安全的 Google Project 或 Location 标识。
func validateVertexIdentifier(field string, value string) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fmt.Errorf("Vertex %s is required", field)
	}
	for _, character := range trimmed {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-' {
			continue
		}
		return fmt.Errorf("Vertex %s contains unsupported characters", field)
	}
	return nil
}

// VertexBaseURL returns CLIProxyAPI's exact global or regional Vertex API origin for one normalized location.
// VertexBaseURL 为一个规范化区域返回 CLIProxyAPI 精确的全局或区域 Vertex API Origin。
func VertexBaseURL(location string) string {
	if location == "global" {
		return "https://aiplatform.googleapis.com"
	}
	return "https://" + location + "-aiplatform.googleapis.com"
}
