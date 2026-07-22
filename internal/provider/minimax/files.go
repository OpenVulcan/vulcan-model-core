package minimax

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/dependency"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

var (
	// ErrInvalidFileUploader reports incomplete dependencies or an invalid exact target.
	// ErrInvalidFileUploader 表示依赖不完整或精确 Target 无效。
	ErrInvalidFileUploader = errors.New("invalid MiniMax file uploader")
)

const (
	// ProviderFileManagementActionBindingID isolates standalone FileSDK operations from model and VLM action bindings.
	// ProviderFileManagementActionBindingID 将独立 FileSDK 操作与模型及 VLM 动作 Binding 隔离。
	ProviderFileManagementActionBindingID = "minimax.files.manage"
	// fileUploadPath is copied from minimax-cli's FileSDK.
	// fileUploadPath 从 minimax-cli 的 FileSDK 复制而来。
	fileUploadPath = "/v1/files/upload"
	// fileListPath is copied from minimax-cli's FileSDK.
	// fileListPath 从 minimax-cli 的 FileSDK 复制而来。
	fileListPath = "/v1/files/list"
	// fileDeletePath is copied from minimax-cli's FileSDK.
	// fileDeletePath 从 minimax-cli 的 FileSDK 复制而来。
	fileDeletePath = "/v1/files/delete"
	// fileRetrievePath is copied from minimax-cli's FileSDK.
	// fileRetrievePath 从 minimax-cli 的 FileSDK 复制而来。
	fileRetrievePath = "/v1/files/retrieve"
)

// FileUploader owns standalone MiniMax FileSDK lifecycle operations for one selected credential and region.
// FileUploader 管理一个选定凭据与区域下的独立 MiniMax FileSDK 生命周期操作。
type FileUploader struct {
	// configurations resolves exact instance, endpoint, credential, and binding facts.
	// configurations 解析精确实例、入口、凭据与 Binding 事实。
	configurations providerconfig.Store
	// secrets resolves only the projected API key or OAuth access token.
	// secrets 仅解析投影后的 API Key 或 OAuth Access Token。
	secrets secret.Store
	// client performs requests without credential-bearing redirects.
	// client 执行请求且不携带凭据跟随重定向。
	client *http.Client
}

// fileUploadResponse is the exact successful upload response copied from minimax-cli.
// fileUploadResponse 是从 minimax-cli 复制的精确上传成功响应。
type fileUploadResponse struct {
	// BaseResponse contains the provider application status.
	// BaseResponse 包含供应商应用状态。
	BaseResponse baseResponse `json:"base_resp"`
	// File contains the created provider file.
	// File 包含已创建的供应商文件。
	File struct {
		// FileID is the private provider handle.
		// FileID 是私有供应商句柄。
		FileID string `json:"file_id"`
	} `json:"file"`
}

// fileListResponse is the exact metadata-only list response copied from minimax-cli.
// fileListResponse 是从 minimax-cli 复制的精确纯元数据列表响应。
type fileListResponse struct {
	// BaseResponse contains the provider application status.
	// BaseResponse 包含供应商应用状态。
	BaseResponse baseResponse `json:"base_resp"`
	// Files contains current files owned by the exact credential.
	// Files 包含精确凭据当前拥有的文件。
	Files []fileMetadata `json:"files"`
}

// fileRetrieveResponse is the exact metadata and temporary URL response copied from minimax-cli.
// fileRetrieveResponse 是从 minimax-cli 复制的精确元数据与临时地址响应。
type fileRetrieveResponse struct {
	// BaseResponse contains the provider application status.
	// BaseResponse 包含供应商应用状态。
	BaseResponse baseResponse `json:"base_resp"`
	// File contains one exact provider file observation.
	// File 包含一个精确供应商文件观测。
	File struct {
		fileMetadata
		// DownloadURL is a temporary provider URL that must remain inside the trusted adapter.
		// DownloadURL 是必须留在可信适配层内部的供应商临时地址。
		DownloadURL string `json:"download_url"`
	} `json:"file"`
}

// fileDeleteResponse is the exact FileSDK deletion response.
// fileDeleteResponse 是精确的 FileSDK 删除响应。
type fileDeleteResponse struct {
	// BaseResponse contains the provider application status.
	// BaseResponse 包含供应商应用状态。
	BaseResponse baseResponse `json:"base_resp"`
	// FileID is the deleted numeric provider identifier.
	// FileID 是已删除的数值型供应商标识。
	FileID uint64 `json:"file_id"`
}

// fileMetadata mirrors one MiniMax FileListResponse item.
// fileMetadata 镜像一个 MiniMax FileListResponse 项目。
type fileMetadata struct {
	// FileID is the provider-owned identifier.
	// FileID 是供应商拥有的标识。
	FileID string `json:"file_id"`
	// Bytes is the provider-reported content length.
	// Bytes 是供应商报告的正文长度。
	Bytes int64 `json:"bytes"`
	// CreatedAt is the Unix creation timestamp.
	// CreatedAt 是 Unix 创建时间戳。
	CreatedAt int64 `json:"created_at"`
	// Filename is the stored basename.
	// Filename 是已存储的基本名。
	Filename string `json:"filename"`
	// Purpose is the provider file purpose.
	// Purpose 是供应商文件用途。
	Purpose string `json:"purpose"`
}

// NewFileUploader creates one exact-target MiniMax provider-file uploader.
// NewFileUploader 创建一个精确 Target 的 MiniMax 供应商文件上传器。
func NewFileUploader(configurations providerconfig.Store, secrets secret.Store, client *http.Client) (*FileUploader, error) {
	if dependency.IsNil(configurations) || dependency.IsNil(secrets) || client == nil {
		return nil, ErrInvalidFileUploader
	}
	return &FileUploader{configurations: configurations, secrets: secrets, client: transport.CloneHTTPClientWithoutRedirects(client)}, nil
}

// Upload creates one standalone MiniMax retrieval file without implying that a model endpoint consumes its identifier.
// Upload 创建一个独立 MiniMax 检索文件，且不暗示任何模型入口会消费其标识。
func (u *FileUploader) Upload(ctx context.Context, request resource.AssetUploadRequest) (resource.AssetUploadResult, error) {
	if request.Mode != "provider_file_id" || request.Target.ActionBindingID != ProviderFileManagementActionBindingID || request.SizeBytes <= 0 || request.SizeBytes > 50<<20 {
		return resource.AssetUploadResult{}, ErrInvalidFileUploader
	}
	endpoint, credential, errScope := u.resolveTarget(ctx, request.Target)
	if errScope != nil {
		return resource.AssetUploadResult{}, errScope
	}
	content, errRead := io.ReadAll(io.LimitReader(request.Content, request.SizeBytes+1))
	if errRead != nil || int64(len(content)) != request.SizeBytes {
		return resource.AssetUploadResult{}, fmt.Errorf("%w: resource content length differs", ErrInvalidFileUploader)
	}
	defer clear(content)
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	header := make(textproto.MIMEHeader)
	header.Set("Content-Disposition", fmt.Sprintf(`form-data; name="file"; filename="%s%s"`, request.ResourceID, miniMaxFileExtension(request.MIMEType)))
	header.Set("Content-Type", request.MIMEType)
	part, errPart := writer.CreatePart(header)
	if errPart != nil {
		return resource.AssetUploadResult{}, errPart
	}
	if _, errWrite := part.Write(content); errWrite != nil {
		return resource.AssetUploadResult{}, errWrite
	}
	if errPurpose := writer.WriteField("purpose", "retrieval"); errPurpose != nil {
		return resource.AssetUploadResult{}, errPurpose
	}
	if errClose := writer.Close(); errClose != nil {
		return resource.AssetUploadResult{}, errClose
	}
	endpointURL, errURL := miniMaxFileURL(endpoint.BaseURL, fileUploadPath)
	if errURL != nil {
		return resource.AssetUploadResult{}, errURL
	}
	httpRequest, errRequest := http.NewRequestWithContext(ctx, http.MethodPost, endpointURL, bytes.NewReader(body.Bytes()))
	if errRequest != nil {
		return resource.AssetUploadResult{}, errRequest
	}
	httpRequest.Header.Set("Content-Type", writer.FormDataContentType())
	secretValue, errSecret := u.secrets.Get(ctx, credential.SecretRef)
	if errSecret != nil || len(secretValue) == 0 {
		return resource.AssetUploadResult{}, fmt.Errorf("%w: credential secret is unavailable", ErrInvalidFileUploader)
	}
	httpRequest.Header.Set("Authorization", "Bearer "+string(secretValue))
	clear(secretValue)
	response, errResponse := u.client.Do(httpRequest)
	if errResponse != nil {
		return resource.AssetUploadResult{}, errResponse
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return resource.AssetUploadResult{}, fmt.Errorf("%w: upload returned status %d", ErrInvalidFileUploader, response.StatusCode)
	}
	reader, errBound := transport.NewBoundedResponseReader(response.Body, 1<<20)
	if errBound != nil {
		return resource.AssetUploadResult{}, errBound
	}
	var payload fileUploadResponse
	if errDecode := json.NewDecoder(reader).Decode(&payload); errDecode != nil || payload.BaseResponse.StatusCode != 0 || strings.TrimSpace(payload.File.FileID) == "" {
		return resource.AssetUploadResult{}, fmt.Errorf("%w: upload response is invalid", ErrInvalidFileUploader)
	}
	return resource.AssetUploadResult{Handle: payload.File.FileID, Kind: resource.ProviderAssetFile}, nil
}

// Delete removes one just-created MiniMax file during materialization compensation.
// Delete 在物化补偿期间删除一个刚创建的 MiniMax 文件。
func (u *FileUploader) Delete(ctx context.Context, target resource.AssetBindingTarget, kind resource.ProviderAssetKind, handle string) error {
	if kind != resource.ProviderAssetFile || target.ActionBindingID != ProviderFileManagementActionBindingID {
		return ErrInvalidFileUploader
	}
	fileID, errID := strconv.ParseUint(strings.TrimSpace(handle), 10, 64)
	if errID != nil {
		return fmt.Errorf("%w: provider file identifier is not numeric", ErrInvalidFileUploader)
	}
	endpoint, credential, errScope := u.resolveTarget(ctx, target)
	if errScope != nil {
		return errScope
	}
	body, errMarshal := json.Marshal(struct {
		// FileID is the numeric MiniMax file identifier copied from FileSDK.delete.
		// FileID 是从 FileSDK.delete 复制的数字 MiniMax 文件标识。
		FileID uint64 `json:"file_id"`
	}{FileID: fileID})
	if errMarshal != nil {
		return errMarshal
	}
	endpointURL, errURL := miniMaxFileURL(endpoint.BaseURL, fileDeletePath)
	if errURL != nil {
		return errURL
	}
	httpRequest, errRequest := http.NewRequestWithContext(ctx, http.MethodPost, endpointURL, bytes.NewReader(body))
	if errRequest != nil {
		return errRequest
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	secretValue, errSecret := u.secrets.Get(ctx, credential.SecretRef)
	if errSecret != nil || len(secretValue) == 0 {
		return fmt.Errorf("%w: credential secret is unavailable", ErrInvalidFileUploader)
	}
	httpRequest.Header.Set("Authorization", "Bearer "+string(secretValue))
	clear(secretValue)
	response, errResponse := u.client.Do(httpRequest)
	if errResponse != nil {
		return errResponse
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound || response.StatusCode == http.StatusGone {
		return nil
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("%w: delete returned status %d", ErrInvalidFileUploader, response.StatusCode)
	}
	reader, errBound := transport.NewBoundedResponseReader(response.Body, 1<<20)
	if errBound != nil {
		return errBound
	}
	var payload fileDeleteResponse
	if errDecode := json.NewDecoder(reader).Decode(&payload); errDecode != nil || payload.BaseResponse.StatusCode != 0 || payload.FileID != fileID {
		return fmt.Errorf("%w: delete response is invalid", ErrInvalidFileUploader)
	}
	return nil
}

// ListProviderFiles reads metadata for one exact MiniMax instance, endpoint, and credential.
// ListProviderFiles 读取一个精确 MiniMax 实例、入口与凭据的文件元数据。
func (u *FileUploader) ListProviderFiles(ctx context.Context, instanceID string, endpointID string, credentialID string) ([]provider.ProviderFileDiagnostic, error) {
	instance, errInstance := u.configurations.GetInstance(ctx, instanceID)
	if errInstance != nil || (instance.DefinitionID != "system_minimax_api" && instance.DefinitionID != "system_minimax_cn") {
		return nil, ErrInvalidFileUploader
	}
	endpoints, errEndpoints := u.configurations.ListEndpoints(ctx, instance.ID)
	if errEndpoints != nil {
		return nil, ErrInvalidFileUploader
	}
	var selectedEndpoint providerconfig.Endpoint
	for _, candidate := range endpoints {
		if candidate.ID == endpointID {
			selectedEndpoint = candidate
			break
		}
	}
	if selectedEndpoint.ID == "" {
		return nil, ErrInvalidFileUploader
	}
	target := resource.AssetBindingTarget{ProviderDefinitionID: instance.DefinitionID, ProviderInstanceID: instance.ID, EndpointID: selectedEndpoint.ID, CredentialID: credentialID, ActionBindingID: ProviderFileManagementActionBindingID, Region: selectedEndpoint.Region}
	endpoint, credential, errScope := u.resolveTarget(ctx, target)
	if errScope != nil {
		return nil, errScope
	}
	endpointURL, errURL := miniMaxFileURL(endpoint.BaseURL, fileListPath)
	if errURL != nil {
		return nil, errURL
	}
	httpRequest, errRequest := http.NewRequestWithContext(ctx, http.MethodGet, endpointURL, nil)
	if errRequest != nil {
		return nil, errRequest
	}
	secretValue, errSecret := u.secrets.Get(ctx, credential.SecretRef)
	if errSecret != nil || len(secretValue) == 0 {
		return nil, fmt.Errorf("%w: credential secret is unavailable", ErrInvalidFileUploader)
	}
	httpRequest.Header.Set("Authorization", "Bearer "+string(secretValue))
	clear(secretValue)
	response, errResponse := u.client.Do(httpRequest)
	if errResponse != nil {
		return nil, errResponse
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("%w: list returned status %d", ErrInvalidFileUploader, response.StatusCode)
	}
	reader, errBound := transport.NewBoundedResponseReader(response.Body, 4<<20)
	if errBound != nil {
		return nil, errBound
	}
	var payload fileListResponse
	if errDecode := json.NewDecoder(reader).Decode(&payload); errDecode != nil || payload.BaseResponse.StatusCode != 0 {
		return nil, fmt.Errorf("%w: list response is invalid", ErrInvalidFileUploader)
	}
	files := make([]provider.ProviderFileDiagnostic, len(payload.Files))
	for index, file := range payload.Files {
		if strings.TrimSpace(file.FileID) == "" || strings.TrimSpace(file.Filename) == "" || strings.TrimSpace(file.Purpose) == "" || file.Bytes < 0 || file.CreatedAt <= 0 {
			return nil, fmt.Errorf("%w: list file metadata is invalid", ErrInvalidFileUploader)
		}
		files[index] = provider.ProviderFileDiagnostic{FileID: file.FileID, Filename: file.Filename, Purpose: file.Purpose, SizeBytes: file.Bytes, CreatedAt: time.Unix(file.CreatedAt, 0).UTC()}
	}
	return files, nil
}

// GetProviderFile reads one exact FileSDK metadata record and suppresses its temporary download URL.
// GetProviderFile 读取一条精确 FileSDK 元数据记录并隐藏其临时下载地址。
func (u *FileUploader) GetProviderFile(ctx context.Context, instanceID string, endpointID string, credentialID string, fileID string) (provider.ProviderFileDiagnostic, error) {
	fileID = strings.TrimSpace(fileID)
	if fileID == "" {
		return provider.ProviderFileDiagnostic{}, ErrInvalidFileUploader
	}
	instance, errInstance := u.configurations.GetInstance(ctx, instanceID)
	if errInstance != nil || (instance.DefinitionID != "system_minimax_api" && instance.DefinitionID != "system_minimax_cn") {
		return provider.ProviderFileDiagnostic{}, ErrInvalidFileUploader
	}
	endpoints, errEndpoints := u.configurations.ListEndpoints(ctx, instance.ID)
	if errEndpoints != nil {
		return provider.ProviderFileDiagnostic{}, ErrInvalidFileUploader
	}
	var selectedEndpoint providerconfig.Endpoint
	for _, candidate := range endpoints {
		if candidate.ID == endpointID {
			selectedEndpoint = candidate
			break
		}
	}
	if selectedEndpoint.ID == "" {
		return provider.ProviderFileDiagnostic{}, ErrInvalidFileUploader
	}
	target := resource.AssetBindingTarget{ProviderDefinitionID: instance.DefinitionID, ProviderInstanceID: instance.ID, EndpointID: selectedEndpoint.ID, CredentialID: credentialID, ActionBindingID: ProviderFileManagementActionBindingID, Region: selectedEndpoint.Region}
	endpoint, credential, errScope := u.resolveTarget(ctx, target)
	if errScope != nil {
		return provider.ProviderFileDiagnostic{}, errScope
	}
	endpointURL, errURL := miniMaxFileURL(endpoint.BaseURL, fileRetrievePath)
	if errURL != nil {
		return provider.ProviderFileDiagnostic{}, errURL
	}
	parsedURL, errParse := url.Parse(endpointURL)
	if errParse != nil {
		return provider.ProviderFileDiagnostic{}, ErrInvalidFileUploader
	}
	query := parsedURL.Query()
	query.Set("file_id", fileID)
	parsedURL.RawQuery = query.Encode()
	httpRequest, errRequest := http.NewRequestWithContext(ctx, http.MethodGet, parsedURL.String(), nil)
	if errRequest != nil {
		return provider.ProviderFileDiagnostic{}, errRequest
	}
	secretValue, errSecret := u.secrets.Get(ctx, credential.SecretRef)
	if errSecret != nil || len(secretValue) == 0 {
		return provider.ProviderFileDiagnostic{}, fmt.Errorf("%w: credential secret is unavailable", ErrInvalidFileUploader)
	}
	httpRequest.Header.Set("Authorization", "Bearer "+string(secretValue))
	clear(secretValue)
	response, errResponse := u.client.Do(httpRequest)
	if errResponse != nil {
		return provider.ProviderFileDiagnostic{}, errResponse
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return provider.ProviderFileDiagnostic{}, fmt.Errorf("%w: retrieve returned status %d", ErrInvalidFileUploader, response.StatusCode)
	}
	reader, errBound := transport.NewBoundedResponseReader(response.Body, 1<<20)
	if errBound != nil {
		return provider.ProviderFileDiagnostic{}, errBound
	}
	var payload fileRetrieveResponse
	if errDecode := json.NewDecoder(reader).Decode(&payload); errDecode != nil || payload.BaseResponse.StatusCode != 0 || payload.File.FileID != fileID || strings.TrimSpace(payload.File.Filename) == "" || strings.TrimSpace(payload.File.Purpose) == "" || payload.File.Bytes < 0 || payload.File.CreatedAt <= 0 {
		return provider.ProviderFileDiagnostic{}, fmt.Errorf("%w: retrieve response is invalid", ErrInvalidFileUploader)
	}
	return provider.ProviderFileDiagnostic{FileID: payload.File.FileID, Filename: payload.File.Filename, Purpose: payload.File.Purpose, SizeBytes: payload.File.Bytes, CreatedAt: time.Unix(payload.File.CreatedAt, 0).UTC(), DownloadAvailable: strings.TrimSpace(payload.File.DownloadURL) != ""}, nil
}

// resolveTarget revalidates one frozen asset target against current provider configuration.
// resolveTarget 针对当前供应商配置重新校验一个冻结资产 Target。
func (u *FileUploader) resolveTarget(ctx context.Context, target resource.AssetBindingTarget) (providerconfig.Endpoint, providerconfig.Credential, error) {
	if target.ProviderDefinitionID != "system_minimax_api" && target.ProviderDefinitionID != "system_minimax_cn" {
		return providerconfig.Endpoint{}, providerconfig.Credential{}, ErrInvalidFileUploader
	}
	instance, errInstance := u.configurations.GetInstance(ctx, target.ProviderInstanceID)
	if errInstance != nil || instance.DefinitionID != target.ProviderDefinitionID || instance.Status != providerconfig.LifecycleReady {
		return providerconfig.Endpoint{}, providerconfig.Credential{}, ErrInvalidFileUploader
	}
	endpoints, errEndpoints := u.configurations.ListEndpoints(ctx, instance.ID)
	credentials, errCredentials := u.configurations.ListCredentials(ctx, instance.ID)
	bindings, errBindings := u.configurations.ListBindings(ctx, instance.ID)
	if errEndpoints != nil || errCredentials != nil || errBindings != nil {
		return providerconfig.Endpoint{}, providerconfig.Credential{}, ErrInvalidFileUploader
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
	if endpoint.ID == "" || endpoint.Status != providerconfig.EndpointReady || endpoint.Region != target.Region || credential.ID == "" || credential.Status != providerconfig.CredentialActive {
		return providerconfig.Endpoint{}, providerconfig.Credential{}, ErrInvalidFileUploader
	}
	authorized := false
	for _, binding := range bindings {
		if binding.EndpointID == endpoint.ID && binding.CredentialID == credential.ID && binding.Enabled {
			authorized = true
			break
		}
	}
	if !authorized {
		return providerconfig.Endpoint{}, providerconfig.Credential{}, ErrInvalidFileUploader
	}
	return endpoint, credential, nil
}

// miniMaxFileURL joins one fixed MiniMax endpoint with an origin-relative file path.
// miniMaxFileURL 将一个固定 MiniMax 入口与相对 Origin 的文件路径连接。
func miniMaxFileURL(baseURL string, relativePath string) (string, error) {
	parsed, errParse := url.Parse(strings.TrimSpace(baseURL))
	if errParse != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return "", ErrInvalidFileUploader
	}
	parsed.Path = path.Join(strings.TrimRight(parsed.Path, "/"), relativePath)
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

// miniMaxFileExtension maps recognized MIME types to safe standalone FileSDK filenames.
// miniMaxFileExtension 将已识别 MIME 类型映射为安全的独立 FileSDK 文件名。
func miniMaxFileExtension(mimeType string) string {
	switch mimeType {
	case "image/jpeg":
		return ".jpg"
	case "image/png":
		return ".png"
	case "image/webp":
		return ".webp"
	case "audio/mpeg":
		return ".mp3"
	case "audio/wav":
		return ".wav"
	case "video/mp4":
		return ".mp4"
	case "application/pdf":
		return ".pdf"
	default:
		return ".bin"
	}
}
