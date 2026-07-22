package minimax

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
)

const (
	// miniMaxVoiceCatalogPath is the exact endpoint released by minimax-cli.
	// miniMaxVoiceCatalogPath 是 minimax-cli 已发布的精确端点。
	miniMaxVoiceCatalogPath = "/v1/get_voice"
	// maximumMiniMaxVoiceResponseBytes bounds one credential-scoped voice catalog.
	// maximumMiniMaxVoiceResponseBytes 限制单个凭据作用域声音目录大小。
	maximumMiniMaxVoiceResponseBytes = 4 << 20
	// miniMaxVoiceCacheLifetime preserves a successful catalog without repeatedly querying upstream.
	// miniMaxVoiceCacheLifetime 保留成功目录并避免反复查询上游。
	miniMaxVoiceCacheLifetime = 30 * time.Minute
)

// miniMaxVoiceCatalogResponse mirrors minimax-cli's VoiceListResponse.
// miniMaxVoiceCatalogResponse 镜像 minimax-cli 的 VoiceListResponse。
type miniMaxVoiceCatalogResponse struct {
	// SystemVoices contains the complete system-voice list for the selected credential.
	// SystemVoices 包含所选凭据的完整系统声音列表。
	SystemVoices []miniMaxSystemVoice `json:"system_voice"`
	// BaseResponse records application-level success.
	// BaseResponse 记录应用层成功状态。
	BaseResponse miniMaxBaseResponse `json:"base_resp"`
}

// miniMaxSystemVoice mirrors one released system voice record.
// miniMaxSystemVoice 镜像一个已发布系统声音记录。
type miniMaxSystemVoice struct {
	// VoiceID is the exact speech request value.
	// VoiceID 是精确的语音请求值。
	VoiceID string `json:"voice_id"`
	// VoiceName is the provider-authored display label.
	// VoiceName 是供应商编写的显示标签。
	VoiceName string `json:"voice_name"`
	// Description contains ordered provider-authored traits.
	// Description 包含供应商编写的有序特征。
	Description []string `json:"description"`
}

// ReadVoices retrieves and normalizes the complete MiniMax system voice catalog for one exact credential.
// ReadVoices 获取并规范化一个精确凭据的完整 MiniMax 系统声音目录。
func (d *AllowanceDriver) ReadVoices(ctx context.Context, instance providerconfig.ProviderInstance, credential providerconfig.Credential) ([]catalog.VoiceSnapshot, error) {
	if instance.DefinitionID != d.definition.ID || credential.ProviderInstanceID != instance.ID || (credential.AuthMethodID != "api_key" && credential.AuthMethodID != "device_flow") {
		return nil, fmt.Errorf("%w: MiniMax voice scope or authentication method is invalid", provider.ErrMetadataAuthentication)
	}
	apiKey, errSecret := d.secrets.Get(ctx, credential.SecretRef)
	if errSecret != nil {
		return nil, fmt.Errorf("%w: resolve MiniMax voice credential: %v", provider.ErrMetadataAuthentication, errSecret)
	}
	defer clear(apiKey)
	body := []byte(`{"voice_type":"system"}`)
	request, errRequest := http.NewRequestWithContext(ctx, http.MethodPost, d.baseURL+miniMaxVoiceCatalogPath, bytes.NewReader(body))
	if errRequest != nil {
		return nil, fmt.Errorf("create MiniMax voice request: %w", errRequest)
	}
	request.Header.Set("Authorization", "Bearer "+string(apiKey))
	request.Header.Set("Content-Type", "application/json")
	response, errResponse := d.client.Do(request)
	if errResponse != nil {
		return nil, fmt.Errorf("%w: request MiniMax voice catalog: %v", provider.ErrMetadataUnavailable, errResponse)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("%w: MiniMax selected regional endpoint rejected the voice credential", provider.ErrMetadataAuthentication)
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("%w: MiniMax voice HTTP status %d", provider.ErrMetadataUnavailable, response.StatusCode)
	}
	encoded, errRead := io.ReadAll(io.LimitReader(response.Body, maximumMiniMaxVoiceResponseBytes+1))
	if errRead != nil || len(encoded) > maximumMiniMaxVoiceResponseBytes {
		return nil, fmt.Errorf("%w: read MiniMax voice catalog", provider.ErrMetadataResponseInvalid)
	}
	defer clear(encoded)
	var payload miniMaxVoiceCatalogResponse
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	if errDecode := decoder.Decode(&payload); errDecode != nil || payload.BaseResponse.StatusCode != 0 {
		return nil, fmt.Errorf("%w: decode MiniMax voice catalog", provider.ErrMetadataResponseInvalid)
	}
	if errTrailing := rejectTrailingQuotaJSON(decoder); errTrailing != nil {
		return nil, errTrailing
	}
	observedAt := d.now().UTC()
	voices := make([]catalog.VoiceSnapshot, 0, len(payload.SystemVoices))
	seenVoiceIDs := make(map[string]struct{}, len(payload.SystemVoices))
	for index, voice := range payload.SystemVoices {
		voiceID := strings.TrimSpace(voice.VoiceID)
		voiceName := strings.TrimSpace(voice.VoiceName)
		if voiceID == "" || voiceName == "" {
			return nil, fmt.Errorf("%w: MiniMax voice row %d has no identity", provider.ErrMetadataResponseInvalid, index)
		}
		if _, duplicate := seenVoiceIDs[voiceID]; duplicate {
			return nil, fmt.Errorf("%w: duplicate MiniMax voice %q", provider.ErrMetadataResponseInvalid, voiceID)
		}
		seenVoiceIDs[voiceID] = struct{}{}
		descriptions := make([]string, 0, len(voice.Description))
		seenDescriptions := make(map[string]struct{}, len(voice.Description))
		for _, value := range voice.Description {
			description := strings.TrimSpace(value)
			if description == "" {
				continue
			}
			if _, duplicate := seenDescriptions[description]; duplicate {
				continue
			}
			seenDescriptions[description] = struct{}{}
			descriptions = append(descriptions, description)
		}
		snapshot := catalog.VoiceSnapshot{ID: miniMaxVoiceID(credential.ID, voiceID), ProviderInstanceID: instance.ID, CredentialID: credential.ID, VoiceID: voiceID, DisplayName: voiceName, Descriptions: descriptions, Source: catalog.ModelSourceProviderAPI, ObservedAt: observedAt, ExpiresAt: observedAt.Add(miniMaxVoiceCacheLifetime), Revision: 1}
		if errValidate := snapshot.Validate(); errValidate != nil {
			return nil, fmt.Errorf("%w: normalized MiniMax voice is invalid: %v", provider.ErrMetadataResponseInvalid, errValidate)
		}
		voices = append(voices, snapshot)
	}
	return voices, nil
}

// miniMaxVoiceID derives one stable credential-scoped identifier without exposing the provider voice value.
// miniMaxVoiceID 派生一个不公开供应商声音值的稳定凭据作用域标识。
func miniMaxVoiceID(credentialID string, voiceID string) string {
	digest := sha256.Sum256([]byte(voiceID))
	return "voice_minimax_" + strings.TrimPrefix(credentialID, "cred_") + "_" + hex.EncodeToString(digest[:8])
}
