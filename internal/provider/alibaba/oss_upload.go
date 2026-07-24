package alibaba

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/dependency"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

var (
	// ErrInvalidOSSUploader reports incomplete dependencies, scope drift, or an invalid upload response.
	// ErrInvalidOSSUploader 表示依赖不完整、作用域漂移或上传响应无效。
	ErrInvalidOSSUploader = errors.New("invalid Alibaba OSS uploader")
)

const (
	// defaultOSSUploadPolicyBaseURL is copied from bailian-cli's REGIONS.cn upload implementation.
	// defaultOSSUploadPolicyBaseURL 从 bailian-cli 的 REGIONS.cn 上传实现复制而来。
	defaultOSSUploadPolicyBaseURL = "https://dashscope.aliyuncs.com"
	// ossUploadPolicyPath is the exact temporary-object policy endpoint copied from bailian-cli.
	// ossUploadPolicyPath 是从 bailian-cli 复制的精确临时对象策略端点。
	ossUploadPolicyPath = "/api/v1/uploads"
	// ossObjectLifetime is the documented lifetime of the returned temporary oss:// handle.
	// ossObjectLifetime 是返回的临时 oss:// 句柄的文档化有效期。
	ossObjectLifetime = 48 * time.Hour
)

// OSSUploaderOptions configures deterministic time and the copied policy origin.
// OSSUploaderOptions 配置确定性时间与复制的策略来源。
type OSSUploaderOptions struct {
	// Now returns current time for the authoritative 48-hour expiry.
	// Now 为权威 48 小时到期时间返回当前时间。
	Now func() time.Time
	// PolicyBaseURL overrides the fixed CN policy origin only for isolated tests.
	// PolicyBaseURL 仅为隔离测试覆盖固定 CN 策略来源。
	PolicyBaseURL string
}

// OSSUploader creates temporary Alibaba OSS objects for explicitly verified CN definitions.
// OSSUploader 为显式验证的 CN 定义创建临时 Alibaba OSS 对象。
type OSSUploader struct {
	// configurations resolves exact current instance, endpoint, credential, and binding facts.
	// configurations 解析精确的当前实例、入口、凭据及绑定事实。
	configurations providerconfig.Store
	// secrets resolves only the selected API key at the policy request boundary.
	// secrets 仅在策略请求边界解析选定 API Key。
	secrets secret.Store
	// client performs policy and upload requests without credential-bearing redirects.
	// client 执行策略与上传请求且不会携带凭据跟随重定向。
	client *http.Client
	// allowedDefinitions is the complete evidence-backed CN ownership set.
	// allowedDefinitions 是完整且有证据支持的 CN 归属集合。
	allowedDefinitions map[string]struct{}
	// policyBaseURL is the fixed policy origin.
	// policyBaseURL 是固定策略来源。
	policyBaseURL string
	// now returns deterministic current time.
	// now 返回确定性当前时间。
	now func() time.Time
}

// ossUploadPolicyResponse contains the exact policy response envelope copied from bailian-cli.
// ossUploadPolicyResponse 包含从 bailian-cli 复制的精确策略响应信封。
type ossUploadPolicyResponse struct {
	// Data contains temporary OSS form credentials.
	// Data 包含临时 OSS 表单凭据。
	Data ossUploadPolicy `json:"data"`
	// RequestID is decoded for tracing compatibility but never logged with credential facts.
	// RequestID 为追踪兼容而解码，但绝不会与凭据事实一起记录。
	RequestID string `json:"request_id,omitempty"`
}

// ossUploadPolicy contains the exact multipart fields returned by DashScope.
// ossUploadPolicy 包含 DashScope 返回的精确 Multipart 字段。
type ossUploadPolicy struct {
	// UploadHost is the temporary OSS form destination.
	// UploadHost 是临时 OSS 表单目标地址。
	UploadHost string `json:"upload_host"`
	// UploadDirectory is the provider-owned object prefix.
	// UploadDirectory 是供应商拥有的对象前缀。
	UploadDirectory string `json:"upload_dir"`
	// AccessKeyID is the temporary OSS form access key identifier.
	// AccessKeyID 是临时 OSS 表单 Access Key 标识。
	AccessKeyID string `json:"oss_access_key_id"`
	// Signature is the temporary OSS form signature.
	// Signature 是临时 OSS 表单签名。
	Signature string `json:"signature"`
	// Policy is the signed OSS form policy.
	// Policy 是已签名 OSS 表单策略。
	Policy string `json:"policy"`
	// ObjectACL is the required object ACL field.
	// ObjectACL 是必需对象 ACL 字段。
	ObjectACL string `json:"x_oss_object_acl"`
	// ForbidOverwrite is the required overwrite-protection field.
	// ForbidOverwrite 是必需覆盖保护字段。
	ForbidOverwrite string `json:"x_oss_forbid_overwrite"`
}

// NewOSSUploader creates one exact-target temporary OSS uploader from a closed definition set.
// NewOSSUploader 从封闭定义集合创建一个精确 Target 临时 OSS 上传器。
func NewOSSUploader(configurations providerconfig.Store, secrets secret.Store, client *http.Client, definitionIDs []string, options OSSUploaderOptions) (*OSSUploader, error) {
	if dependency.IsNil(configurations) || dependency.IsNil(secrets) || client == nil || len(definitionIDs) == 0 {
		return nil, ErrInvalidOSSUploader
	}
	allowedDefinitions := make(map[string]struct{}, len(definitionIDs))
	for _, definitionID := range definitionIDs {
		definitionID = strings.TrimSpace(definitionID)
		if definitionID == "" {
			return nil, ErrInvalidOSSUploader
		}
		if _, exists := allowedDefinitions[definitionID]; exists {
			return nil, fmt.Errorf("%w: duplicate definition %q", ErrInvalidOSSUploader, definitionID)
		}
		allowedDefinitions[definitionID] = struct{}{}
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if strings.TrimSpace(options.PolicyBaseURL) == "" {
		options.PolicyBaseURL = defaultOSSUploadPolicyBaseURL
	}
	parsedPolicyBase, errPolicyBase := url.Parse(strings.TrimSpace(options.PolicyBaseURL))
	if errPolicyBase != nil || parsedPolicyBase.Scheme != "https" || parsedPolicyBase.Host == "" || parsedPolicyBase.User != nil || parsedPolicyBase.RawQuery != "" || parsedPolicyBase.Fragment != "" {
		return nil, fmt.Errorf("%w: policy base URL must be an HTTPS origin", ErrInvalidOSSUploader)
	}
	parsedPolicyBase.Path = strings.TrimRight(parsedPolicyBase.Path, "/")
	return &OSSUploader{configurations: configurations, secrets: secrets, client: transport.CloneHTTPClientWithoutRedirects(client), allowedDefinitions: allowedDefinitions, policyBaseURL: parsedPolicyBase.String(), now: options.Now}, nil
}

// Upload copies bailian-cli's getPolicy and multipart OSS flow for one exact Alibaba target.
// Upload 为一个精确 Alibaba Target 复制 bailian-cli 的 getPolicy 与 Multipart OSS 流程。
func (u *OSSUploader) Upload(ctx context.Context, request resource.AssetUploadRequest) (resource.AssetUploadResult, error) {
	if u == nil || ctx == nil || request.Mode != catalog.MaterializationProviderObjectURI || request.SizeBytes <= 0 || request.Content == nil || strings.TrimSpace(request.Target.UpstreamModelID) == "" {
		return resource.AssetUploadResult{}, ErrInvalidOSSUploader
	}
	if _, errHash := hex.DecodeString(request.SHA256); errHash != nil || len(request.SHA256) != 64 {
		return resource.AssetUploadResult{}, fmt.Errorf("%w: resource SHA-256 is invalid", ErrInvalidOSSUploader)
	}
	_, credential, errScope := u.resolveTarget(ctx, request.Target)
	if errScope != nil {
		return resource.AssetUploadResult{}, errScope
	}
	policy, errPolicy := u.fetchPolicy(ctx, credential, request.Target.UpstreamModelID)
	if errPolicy != nil {
		return resource.AssetUploadResult{}, errPolicy
	}
	fileName := "resource-" + strings.ToLower(request.SHA256[:16]) + alibabaUploadExtension(request.MIMEType)
	objectKey := strings.TrimRight(policy.UploadDirectory, "/") + "/" + fileName
	if strings.TrimSpace(policy.UploadDirectory) == "" || strings.HasPrefix(objectKey, "/") || strings.Contains(objectKey, "../") {
		return resource.AssetUploadResult{}, fmt.Errorf("%w: upload directory is invalid", ErrInvalidOSSUploader)
	}
	if errUpload := u.uploadObject(ctx, policy, objectKey, fileName, request); errUpload != nil {
		return resource.AssetUploadResult{}, errUpload
	}
	expiresAt := u.now().UTC().Add(ossObjectLifetime)
	return resource.AssetUploadResult{Handle: "oss://" + objectKey, Kind: resource.ProviderAssetObject, ExpiresAt: &expiresAt}, nil
}

// Delete validates a temporary OSS handle; DashScope exposes no delete API and expiry performs cleanup.
// Delete 校验临时 OSS 句柄；DashScope 未提供删除 API，由到期机制执行清理。
func (u *OSSUploader) Delete(_ context.Context, target resource.AssetBindingTarget, kind resource.ProviderAssetKind, handle string) error {
	if u == nil || kind != resource.ProviderAssetObject || !strings.HasPrefix(strings.TrimSpace(handle), "oss://") {
		return ErrInvalidOSSUploader
	}
	if _, allowed := u.allowedDefinitions[target.ProviderDefinitionID]; !allowed {
		return ErrInvalidOSSUploader
	}
	return nil
}

// fetchPolicy obtains temporary form credentials using only the selected Alibaba API key.
// fetchPolicy 仅使用选定 Alibaba API Key 获取临时表单凭据。
func (u *OSSUploader) fetchPolicy(ctx context.Context, credential providerconfig.Credential, model string) (ossUploadPolicy, error) {
	policyURL, errURL := url.Parse(u.policyBaseURL)
	if errURL != nil {
		return ossUploadPolicy{}, ErrInvalidOSSUploader
	}
	policyURL.Path = path.Join(strings.TrimRight(policyURL.Path, "/"), ossUploadPolicyPath)
	query := policyURL.Query()
	query.Set("action", "getPolicy")
	query.Set("model", model)
	policyURL.RawQuery = query.Encode()
	request, errRequest := http.NewRequestWithContext(ctx, http.MethodGet, policyURL.String(), nil)
	if errRequest != nil {
		return ossUploadPolicy{}, errRequest
	}
	request.Header.Set("Content-Type", "application/json")
	secretValue, errSecret := u.secrets.Get(ctx, credential.SecretRef)
	if errSecret != nil || len(secretValue) == 0 {
		clear(secretValue)
		return ossUploadPolicy{}, fmt.Errorf("%w: credential secret is unavailable", ErrInvalidOSSUploader)
	}
	request.Header.Set("Authorization", "Bearer "+string(secretValue))
	clear(secretValue)
	response, errResponse := u.client.Do(request)
	if errResponse != nil {
		return ossUploadPolicy{}, errResponse
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return ossUploadPolicy{}, fmt.Errorf("%w: policy returned status %d", ErrInvalidOSSUploader, response.StatusCode)
	}
	reader, errBound := transport.NewBoundedResponseReader(response.Body, 1<<20)
	if errBound != nil {
		return ossUploadPolicy{}, errBound
	}
	var payload ossUploadPolicyResponse
	decoder := json.NewDecoder(reader)
	if errDecode := decoder.Decode(&payload); errDecode != nil {
		return ossUploadPolicy{}, fmt.Errorf("%w: policy response is invalid", ErrInvalidOSSUploader)
	}
	if errTrailing := decoder.Decode(&struct{}{}); !errors.Is(errTrailing, io.EOF) {
		return ossUploadPolicy{}, fmt.Errorf("%w: policy response contains trailing JSON", ErrInvalidOSSUploader)
	}
	if errValidate := validateOSSUploadPolicy(payload.Data); errValidate != nil {
		return ossUploadPolicy{}, errValidate
	}
	return payload.Data, nil
}

// uploadObject streams one exact resource through the copied signed OSS multipart form.
// uploadObject 通过复制的签名 OSS Multipart 表单流式上传一个精确资源。
func (u *OSSUploader) uploadObject(ctx context.Context, policy ossUploadPolicy, objectKey string, fileName string, request resource.AssetUploadRequest) error {
	pipeReader, pipeWriter := io.Pipe()
	multipartWriter := multipart.NewWriter(pipeWriter)
	contentType := multipartWriter.FormDataContentType()
	writeResult := make(chan error, 1)
	go func() {
		writeResult <- writeOSSMultipart(multipartWriter, pipeWriter, policy, objectKey, fileName, request)
	}()
	httpRequest, errRequest := http.NewRequestWithContext(ctx, http.MethodPost, policy.UploadHost, pipeReader)
	if errRequest != nil {
		_ = pipeReader.CloseWithError(errRequest)
		<-writeResult
		return errRequest
	}
	httpRequest.Header.Set("Content-Type", contentType)
	response, errResponse := u.client.Do(httpRequest)
	if errResponse != nil {
		_ = pipeReader.CloseWithError(errResponse)
		<-writeResult
		return errResponse
	}
	defer response.Body.Close()
	if errWrite := <-writeResult; errWrite != nil {
		return errWrite
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("%w: OSS upload returned status %d", ErrInvalidOSSUploader, response.StatusCode)
	}
	return nil
}

// writeOSSMultipart writes signed fields and verifies the exact resource byte count.
// writeOSSMultipart 写入签名字段并验证精确资源字节数。
func writeOSSMultipart(writer *multipart.Writer, pipe *io.PipeWriter, policy ossUploadPolicy, objectKey string, fileName string, request resource.AssetUploadRequest) error {
	defer pipe.Close()
	fields := []struct {
		// name is the exact OSS form field.
		// name 是精确 OSS 表单字段。
		name string
		// value is the corresponding signed value.
		// value 是对应签名值。
		value string
	}{
		{name: "OSSAccessKeyId", value: policy.AccessKeyID},
		{name: "Signature", value: policy.Signature},
		{name: "policy", value: policy.Policy},
		{name: "x-oss-object-acl", value: policy.ObjectACL},
		{name: "x-oss-forbid-overwrite", value: policy.ForbidOverwrite},
		{name: "key", value: objectKey},
		{name: "success_action_status", value: "200"},
	}
	for _, field := range fields {
		if errField := writer.WriteField(field.name, field.value); errField != nil {
			_ = writer.Close()
			return errField
		}
	}
	header := make(textproto.MIMEHeader)
	header.Set("Content-Disposition", fmt.Sprintf(`form-data; name="file"; filename="%s"`, fileName))
	header.Set("Content-Type", request.MIMEType)
	part, errPart := writer.CreatePart(header)
	if errPart != nil {
		_ = writer.Close()
		return errPart
	}
	written, errCopy := io.CopyN(part, request.Content, request.SizeBytes)
	if errCopy != nil || written != request.SizeBytes {
		_ = writer.Close()
		return fmt.Errorf("%w: resource content length differs", ErrInvalidOSSUploader)
	}
	extra := make([]byte, 1)
	if count, errExtra := request.Content.Read(extra); count != 0 || (errExtra != nil && !errors.Is(errExtra, io.EOF)) {
		_ = writer.Close()
		return fmt.Errorf("%w: resource content exceeds declared length", ErrInvalidOSSUploader)
	}
	return writer.Close()
}

// validateOSSUploadPolicy rejects missing fields and unsafe provider upload destinations.
// validateOSSUploadPolicy 拒绝缺失字段及不安全供应商上传目标。
func validateOSSUploadPolicy(policy ossUploadPolicy) error {
	if strings.TrimSpace(policy.UploadDirectory) == "" || strings.TrimSpace(policy.AccessKeyID) == "" || strings.TrimSpace(policy.Signature) == "" || strings.TrimSpace(policy.Policy) == "" || strings.TrimSpace(policy.ObjectACL) == "" || strings.TrimSpace(policy.ForbidOverwrite) == "" {
		return fmt.Errorf("%w: policy fields are incomplete", ErrInvalidOSSUploader)
	}
	uploadURL, errURL := url.Parse(strings.TrimSpace(policy.UploadHost))
	if errURL != nil || uploadURL.Scheme != "https" || uploadURL.Host == "" || uploadURL.User != nil || uploadURL.RawQuery != "" || uploadURL.Fragment != "" {
		return fmt.Errorf("%w: upload host is invalid", ErrInvalidOSSUploader)
	}
	return nil
}

// resolveTarget revalidates one frozen asset target against current Alibaba configuration.
// resolveTarget 针对当前 Alibaba 配置重新校验一个冻结资产 Target。
func (u *OSSUploader) resolveTarget(ctx context.Context, target resource.AssetBindingTarget) (providerconfig.Endpoint, providerconfig.Credential, error) {
	if _, allowed := u.allowedDefinitions[target.ProviderDefinitionID]; !allowed {
		return providerconfig.Endpoint{}, providerconfig.Credential{}, ErrInvalidOSSUploader
	}
	instance, errInstance := u.configurations.GetInstance(ctx, target.ProviderInstanceID)
	if errInstance != nil || instance.DefinitionID != target.ProviderDefinitionID || instance.Status != providerconfig.LifecycleReady {
		return providerconfig.Endpoint{}, providerconfig.Credential{}, ErrInvalidOSSUploader
	}
	endpoints, errEndpoints := u.configurations.ListEndpoints(ctx, instance.ID)
	credentials, errCredentials := u.configurations.ListCredentials(ctx, instance.ID)
	bindings, errBindings := u.configurations.ListBindings(ctx, instance.ID)
	if errEndpoints != nil || errCredentials != nil || errBindings != nil {
		return providerconfig.Endpoint{}, providerconfig.Credential{}, ErrInvalidOSSUploader
	}
	var endpoint providerconfig.Endpoint
	var credential providerconfig.Credential
	for _, candidate := range endpoints {
		if candidate.ID == target.EndpointID {
			endpoint = candidate
		}
	}
	for _, candidate := range credentials {
		if candidate.ID == target.CredentialID {
			credential = candidate
		}
	}
	if endpoint.ID == "" || endpoint.Status != providerconfig.EndpointReady || endpoint.Region != target.Region || credential.ID == "" || credential.Status != providerconfig.CredentialActive || credential.AuthMethodID != "api_key" {
		return providerconfig.Endpoint{}, providerconfig.Credential{}, ErrInvalidOSSUploader
	}
	authorized := false
	for _, binding := range bindings {
		if binding.EndpointID == endpoint.ID && binding.CredentialID == credential.ID && binding.Enabled {
			authorized = true
			break
		}
	}
	if !authorized {
		return providerconfig.Endpoint{}, providerconfig.Credential{}, ErrInvalidOSSUploader
	}
	return endpoint, credential, nil
}

// alibabaUploadExtension maps known media MIME types to safe temporary object names.
// alibabaUploadExtension 将已知媒体 MIME 类型映射为安全临时对象名称。
func alibabaUploadExtension(mimeType string) string {
	switch strings.ToLower(strings.TrimSpace(mimeType)) {
	case "image/jpeg":
		return ".jpg"
	case "image/png":
		return ".png"
	case "image/webp":
		return ".webp"
	case "audio/mpeg":
		return ".mp3"
	case "audio/wav", "audio/x-wav":
		return ".wav"
	case "video/mp4":
		return ".mp4"
	default:
		return ".bin"
	}
}
