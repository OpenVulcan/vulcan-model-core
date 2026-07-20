package alibaba

import (
	provideropenai "github.com/OpenVulcan/vulcan-model-core/internal/provider/openai"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
)

const (
	// EmbeddingActionBindingID identifies Alibaba Model Studio compatible embedding execution.
	// EmbeddingActionBindingID 标识阿里云百炼兼容 Embedding 执行。
	EmbeddingActionBindingID = "action_alibaba_embedding_create"
	// EmbeddingProtocolProfileID identifies Alibaba's documented OpenAI-compatible embedding contract.
	// EmbeddingProtocolProfileID 标识阿里云已记录的 OpenAI 兼容 Embedding 合同。
	EmbeddingProtocolProfileID = "alibaba.model_studio.embeddings.v1"
	// embeddingEndpointPath is the fixed compatible embedding resource path below each regional base URL.
	// embeddingEndpointPath 是各区域基础地址下固定的兼容 Embedding 资源路径。
	embeddingEndpointPath = "/compatible-mode/v1/embeddings"
)

// NewEmbeddingDriver creates an Alibaba-owned driver over the exact documented compatible contract.
// NewEmbeddingDriver 基于精确记录的兼容合同创建阿里云拥有的 Driver。
func NewEmbeddingDriver(definitionID string, client *transport.Client) (*provideropenai.EmbeddingActionDriver, error) {
	return provideropenai.NewCompatibleEmbeddingDriver(definitionID, EmbeddingActionBindingID, embeddingEndpointPath, client)
}
