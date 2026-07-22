package minimax

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestMiniMaxMusicGenerationEnablesLyricsOptimizer verifies exact non-streaming URL projection.
// TestMiniMaxMusicGenerationEnablesLyricsOptimizer 验证精确的非流式 URL 投影。
func TestMiniMaxMusicGenerationEnablesLyricsOptimizer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var upstream musicGenerationRequest
		if request.URL.Path != "/v1/music_generation" || request.Header.Get("Authorization") != "Bearer test-secret" {
			t.Errorf("request path=%q authorization=%q", request.URL.Path, request.Header.Get("Authorization"))
		}
		if errDecode := json.NewDecoder(request.Body).Decode(&upstream); errDecode != nil {
			t.Errorf("decode request: %v", errDecode)
		}
		if upstream.Model != "music-3.0" || upstream.Prompt != "Warm orchestral pop" || upstream.Lyrics != "" || !upstream.LyricsOptimizer || upstream.Stream || upstream.OutputFormat != "url" || upstream.AudioSetting.Format != "wav" {
			t.Errorf("upstream = %#v", upstream)
		}
		_, _ = io.WriteString(writer, `{"data":{"audio_url":"https://outputs.example/song.wav","status":2},"trace_id":"trace-music","base_resp":{"status_code":0,"status_msg":"success"}}`)
	}))
	defer server.Close()

	driver, execution := newMiniMaxMusicExecution(t, server.URL, MusicGenerateActionBindingID, MusicGenerateProtocolProfileID, vcp.OperationMusicGenerate, "music-3.0")
	lyricsOptimizer := true
	execution.Execution.Payload.MusicGenerate = &vcp.MusicGenerateOperation{Prompt: "Warm orchestral pop", OutputFormat: "wav", LyricsOptimizer: &lyricsOptimizer}
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if result.UpstreamResponseID != "trace-music" || len(result.GeneratedResources) != 1 || result.GeneratedResources[0].DownloadURL != "https://outputs.example/song.wav" || result.GeneratedResources[0].MIMEType != "audio/wav" {
		t.Fatalf("result = %#v", result)
	}
}

// TestMiniMaxMusicGenerationStreamsRealAudioProgress verifies native audio chunks use hex streaming and stable output identity.
// TestMiniMaxMusicGenerationStreamsRealAudioProgress 验证原生音频分片使用十六进制流式输出与稳定输出身份。
func TestMiniMaxMusicGenerationStreamsRealAudioProgress(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var upstream musicGenerationRequest
		if request.Header.Get("Accept") != "text/event-stream" || json.NewDecoder(request.Body).Decode(&upstream) != nil || !upstream.Stream || upstream.OutputFormat != "hex" {
			t.Errorf("stream request Accept=%q body=%#v", request.Header.Get("Accept"), upstream)
		}
		writer.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(writer, "data: {\"data\":{\"audio\":\"494433\",\"status\":1},\"base_resp\":{\"status_code\":0}}\n\n")
		_, _ = io.WriteString(writer, "data: {\"data\":{\"audio\":\"6d75736963\",\"status\":2},\"base_resp\":{\"status_code\":0}}\n\n")
	}))
	defer server.Close()

	driver, execution := newMiniMaxMusicExecution(t, server.URL, MusicGenerateActionBindingID, MusicGenerateProtocolProfileID, vcp.OperationMusicGenerate, "music-3.0")
	execution.Definition.ActionBindings[0].Delivery.Streaming = true
	execution.Execution.Stream = true
	execution.Execution.Payload.MusicGenerate = &vcp.MusicGenerateOperation{Prompt: "instrumental soundtrack", Instrumental: true, OutputFormat: "mp3"}
	sink := &collectingResourceSink{}
	execution.ResourceSink = sink
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if len(result.GeneratedResources) != 1 || string(result.GeneratedResources[0].Data) != "ID3music" || len(sink.observations) != 2 || sink.observations[0].PartialBytes != 3 || sink.observations[1].PartialBytes != 8 || sink.observations[1].OutputID != "music-0" {
		t.Fatalf("result=%#v progress=%#v", result, sink.observations)
	}
}

// TestMiniMaxMusicCoverKeepsProviderHandlePrivate verifies both steps of the prepared workflow.
// TestMiniMaxMusicCoverKeepsProviderHandlePrivate 验证已准备工作流的两个阶段均保持供应商句柄私有。
func TestMiniMaxMusicCoverKeepsProviderHandlePrivate(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestCount++
		if requestCount == 1 {
			var upstream musicCoverPreparationRequest
			if request.URL.Path != "/v1/music_cover_preprocess" {
				t.Errorf("preparation path = %q", request.URL.Path)
			}
			if errDecode := json.NewDecoder(request.Body).Decode(&upstream); errDecode != nil {
				t.Errorf("decode preparation request: %v", errDecode)
			}
			if upstream.Model != "music-cover" || upstream.AudioBase64 != "YXVkaW8=" || upstream.AudioURL != "" {
				t.Errorf("preparation request = %#v", upstream)
			}
			_, _ = io.WriteString(writer, `{"cover_feature_id":"private-feature","formatted_lyrics":"[Verse]\nOriginal lyrics","structure_result":"{\"num_segments\":2,\"segments\":[{\"start\":0,\"end\":10,\"label\":\"intro\"},{\"start\":10,\"end\":90,\"label\":\"verse\"}]}","audio_duration":90,"trace_id":"trace-prepare","base_resp":{"status_code":0,"status_msg":"success"}}`)
			return
		}
		var upstream musicGenerationRequest
		if request.URL.Path != "/v1/music_generation" {
			t.Errorf("cover path = %q", request.URL.Path)
		}
		if errDecode := json.NewDecoder(request.Body).Decode(&upstream); errDecode != nil {
			t.Errorf("decode cover request: %v", errDecode)
		}
		if upstream.Model != "music-cover" || upstream.CoverFeatureID != "private-feature" || upstream.Prompt != "Gentle acoustic folk cover" || upstream.Lyrics != "Ten final lyric characters" {
			t.Errorf("cover request = %#v", upstream)
		}
		_, _ = io.WriteString(writer, `{"data":{"audio_url":"https://outputs.example/cover.mp3","status":2},"trace_id":"trace-cover","base_resp":{"status_code":0,"status_msg":"success"}}`)
	}))
	defer server.Close()

	prepareDriver, prepareExecution := newMiniMaxMusicExecution(t, server.URL, MusicCoverPrepareActionBindingID, MusicCoverPrepareProtocolProfileID, vcp.OperationMusicCoverPrepare, "music-cover")
	source := vcp.MediaInput{ID: "cover-source", Kind: vcp.MediaAudio, Role: vcp.MediaRoleCoverReference, Resource: vcp.ResourceReference{ResourceID: "resource-cover"}}
	prepareExecution.Execution.Payload.MusicCoverPrepare = &vcp.MusicCoverPrepareOperation{Source: source}
	prepareExecution.MaterializedInputs = []resource.MaterializedInput{{InputID: source.ID, ResourceID: source.Resource.ResourceID, Kind: source.Kind, Role: source.Role, MIMEType: "audio/mpeg", Mode: catalog.MaterializationInlineBase64, InlineBase64: "YXVkaW8="}}
	prepared, errPrepare := prepareDriver.Execute(context.Background(), prepareExecution)
	if errPrepare != nil {
		t.Fatalf("prepare Execute() error = %v", errPrepare)
	}
	if prepared.MusicCoverPreparation == nil || prepared.MusicCoverPreparation.ProviderHandle != "private-feature" || len(prepared.MusicCoverPreparation.Structure) != 2 || prepared.MusicCoverPreparation.ExpiresAt != prepareExecution.Now.Add(24*time.Hour) {
		t.Fatalf("preparation result = %#v", prepared.MusicCoverPreparation)
	}

	coverDriver, coverExecution := newMiniMaxMusicExecution(t, server.URL, MusicCoverActionBindingID, MusicCoverProtocolProfileID, vcp.OperationMusicCover, "music-cover")
	coverExecution.Execution.Payload.MusicCover = &vcp.MusicCoverOperation{PreparationID: "router-preparation", Prompt: "Gentle acoustic folk cover", Lyrics: "Ten final lyric characters", OutputFormat: "mp3"}
	coverExecution.PreparedWorkflow = &provider.PreparedWorkflowBinding{PreparationID: "router-preparation", ProviderHandle: prepared.MusicCoverPreparation.ProviderHandle, ExpiresAt: prepared.MusicCoverPreparation.ExpiresAt}
	covered, errCover := coverDriver.Execute(context.Background(), coverExecution)
	if errCover != nil {
		t.Fatalf("cover Execute() error = %v", errCover)
	}
	if len(covered.GeneratedResources) != 1 || covered.GeneratedResources[0].DownloadURL != "https://outputs.example/cover.mp3" {
		t.Fatalf("cover result = %#v", covered)
	}
}

// TestMiniMaxMusicCoverUsesDirectAudioWithoutLyrics verifies the pinned direct URL cover path.
// TestMiniMaxMusicCoverUsesDirectAudioWithoutLyrics 验证固定源码中的无歌词直接 URL 翻唱路径。
func TestMiniMaxMusicCoverUsesDirectAudioWithoutLyrics(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var upstream musicGenerationRequest
		if request.URL.Path != "/v1/music_generation" {
			t.Errorf("cover path = %q", request.URL.Path)
		}
		if errDecode := json.NewDecoder(request.Body).Decode(&upstream); errDecode != nil {
			t.Errorf("decode cover request: %v", errDecode)
		}
		if upstream.Model != "music-cover-free" || upstream.AudioURL != "https://media.example/source.mp3" || upstream.AudioBase64 != "" || upstream.CoverFeatureID != "" || upstream.Lyrics != "" || upstream.Prompt != "Energetic electronic cover" {
			t.Errorf("cover request = %#v", upstream)
		}
		_, _ = io.WriteString(writer, `{"data":{"audio_url":"https://outputs.example/direct-cover.mp3","status":2},"trace_id":"trace-direct-cover","base_resp":{"status_code":0,"status_msg":"success"}}`)
	}))
	defer server.Close()

	driver, execution := newMiniMaxMusicExecution(t, server.URL, MusicCoverActionBindingID, MusicCoverProtocolProfileID, vcp.OperationMusicCover, "music-cover-free")
	source := vcp.MediaInput{ID: "cover-source", Kind: vcp.MediaAudio, Role: vcp.MediaRoleCoverReference, Resource: vcp.ResourceReference{ResourceID: "resource-cover"}}
	execution.Execution.Payload.MusicCover = &vcp.MusicCoverOperation{Source: &source, Prompt: "Energetic electronic cover", OutputFormat: "mp3"}
	execution.MaterializedInputs = []resource.MaterializedInput{{InputID: source.ID, ResourceID: source.Resource.ResourceID, Kind: source.Kind, Role: source.Role, MIMEType: "audio/mpeg", Mode: catalog.MaterializationDirectRemoteURL, RemoteURL: "https://media.example/source.mp3"}}
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if len(result.GeneratedResources) != 1 || result.GeneratedResources[0].DownloadURL != "https://outputs.example/direct-cover.mp3" {
		t.Fatalf("result = %#v", result)
	}
}

// TestMiniMaxMusicCoverUsesOptionalLyricsWithDirectAudio verifies the pinned CLI direct-source lyrics carrier.
// TestMiniMaxMusicCoverUsesOptionalLyricsWithDirectAudio 验证固定 CLI 的直接来源可选歌词载体。
func TestMiniMaxMusicCoverUsesOptionalLyricsWithDirectAudio(t *testing.T) {
	_, execution := newMiniMaxMusicExecution(t, "https://api.minimax.io", MusicCoverActionBindingID, MusicCoverProtocolProfileID, vcp.OperationMusicCover, "music-cover")
	source := vcp.MediaInput{ID: "cover-source", Kind: vcp.MediaAudio, Role: vcp.MediaRoleCoverReference, Resource: vcp.ResourceReference{ResourceID: "resource-cover"}}
	execution.Execution.Payload.MusicCover = &vcp.MusicCoverOperation{Source: &source, Prompt: "Energetic electronic cover", Lyrics: "Optional direct cover lyrics"}
	execution.MaterializedInputs = []resource.MaterializedInput{{InputID: source.ID, ResourceID: source.Resource.ResourceID, Kind: source.Kind, Role: source.Role, MIMEType: "audio/mpeg", Mode: catalog.MaterializationDirectRemoteURL, RemoteURL: "https://media.example/source.mp3"}}
	request, errProject := projectPreparedMusicCoverRequest(execution)
	if errProject != nil {
		t.Fatalf("projectPreparedMusicCoverRequest() error = %v", errProject)
	}
	var upstream musicGenerationRequest
	if errDecode := json.Unmarshal(request.Body, &upstream); errDecode != nil || upstream.AudioURL != "https://media.example/source.mp3" || upstream.Lyrics != "Optional direct cover lyrics" {
		t.Fatalf("request = %#v, error = %v", upstream, errDecode)
	}
}

// TestMiniMaxMusicRejectsUnsupportedAndExpiredInputs verifies explicit lossless boundaries.
// TestMiniMaxMusicRejectsUnsupportedAndExpiredInputs 验证显式无损边界。
func TestMiniMaxMusicRejectsUnsupportedAndExpiredInputs(t *testing.T) {
	driver, execution := newMiniMaxMusicExecution(t, "https://api.minimax.io", MusicGenerateActionBindingID, MusicGenerateProtocolProfileID, vcp.OperationMusicGenerate, "music-3.0")
	execution.Execution.Payload.MusicGenerate = &vcp.MusicGenerateOperation{Prompt: "music", NegativePrompt: "noise"}
	if _, errExecute := driver.Execute(context.Background(), execution); errExecute == nil {
		t.Fatal("expected unsupported negative prompt rejection")
	}
	execution.Execution.Payload.MusicGenerate = &vcp.MusicGenerateOperation{Prompt: "music"}
	if _, errProject := projectMusicGenerationRequest(execution); errProject == nil {
		t.Fatal("expected prompt-only generation without explicit lyrics_optimizer to be rejected")
	}
	coverDriver, coverExecution := newMiniMaxMusicExecution(t, "https://api.minimax.io", MusicCoverActionBindingID, MusicCoverProtocolProfileID, vcp.OperationMusicCover, "music-cover")
	coverExecution.Execution.Payload.MusicCover = &vcp.MusicCoverOperation{PreparationID: "router-preparation", Prompt: "Gentle acoustic cover", Lyrics: "Ten final lyric characters"}
	coverExecution.PreparedWorkflow = &provider.PreparedWorkflowBinding{PreparationID: "router-preparation", ProviderHandle: "private-feature", ExpiresAt: coverExecution.Now}
	if _, errExecute := coverDriver.Execute(context.Background(), coverExecution); errExecute == nil {
		t.Fatal("expected expired preparation rejection")
	}
}

// TestMiniMaxMusicModelSetsMatchPinnedCLI verifies exact generation and cover model acceptance without wildcard compatibility.
// TestMiniMaxMusicModelSetsMatchPinnedCLI 验证生成与翻唱模型精确接受且不存在通配兼容。
func TestMiniMaxMusicModelSetsMatchPinnedCLI(t *testing.T) {
	for _, model := range []string{"music-3.0", "music-2.6", "music-2.6-free", "music-2.5+", "music-2.5"} {
		driver, execution := newMiniMaxMusicExecution(t, "https://api.minimax.io", MusicGenerateActionBindingID, MusicGenerateProtocolProfileID, vcp.OperationMusicGenerate, model)
		_ = driver
		lyricsOptimizer := true
		execution.Execution.Payload.MusicGenerate = &vcp.MusicGenerateOperation{Prompt: "music", LyricsOptimizer: &lyricsOptimizer}
		if _, errProject := projectMusicGenerationRequest(execution); errProject != nil {
			t.Fatalf("generation model %q error = %v", model, errProject)
		}
	}
	if supportedMiniMaxMusicGenerationModel("music-3.0-free") {
		t.Fatal("undocumented music-3.0-free model was accepted")
	}
	for _, model := range []string{"music-cover", "music-cover-free"} {
		if !supportedMiniMaxMusicCoverModel(model) {
			t.Fatalf("cover model %q was rejected", model)
		}
	}
	if supportedMiniMaxMusicCoverModel("music-cover-plus") {
		t.Fatal("undocumented cover model was accepted")
	}
}

// newMiniMaxMusicExecution builds one exact MiniMax music action fixture.
// newMiniMaxMusicExecution 构建一个精确的 MiniMax 音乐动作夹具。
func newMiniMaxMusicExecution(t *testing.T, baseURL string, actionBindingID string, profileID string, operation vcp.OperationKind, upstreamModelID string) (*MusicActionDriver, provider.ExecutionRequest) {
	t.Helper()
	imageDriver, execution := newMiniMaxImageExecution(t, baseURL)
	driver, errDriver := NewMusicActionDriver("definition-minimax", actionBindingID, imageDriver.client)
	if errDriver != nil {
		t.Fatalf("NewMusicActionDriver() error = %v", errDriver)
	}
	action := providerconfig.ProviderActionBinding{ID: actionBindingID, Operation: operation, DriverID: "minimax", DriverVersion: "1", ProtocolProfileID: profileID, EndpointProfileID: "minimax_music", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true, Streaming: actionBindingID != MusicCoverPrepareActionBindingID}, ResourceMaterialization: []providerconfig.ResourceMaterializationMode{providerconfig.ResourceMaterializationInline, providerconfig.ResourceMaterializationDirectURL}, Revision: 1}
	execution.Definition.ProtocolProfileID = profileID
	execution.Definition.ActionBindings = []providerconfig.ProviderActionBinding{action}
	execution.Binding.Target.ChannelID = profileID
	execution.Binding.Endpoint.ChannelID = profileID
	execution.Binding.Target.ActionBindingID = actionBindingID
	execution.Binding.Target.Operation = operation
	execution.Binding.Target.UpstreamModelID = upstreamModelID
	execution.Execution.Operation = operation
	execution.Execution.Payload.ImageGenerate = nil
	execution.Execution.RequestID = "request-music"
	execution.LineageID = "lineage-music"
	return driver, execution
}
