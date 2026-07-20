package vcp

import (
	"encoding/base64"
	"fmt"
	"math"
	"strings"
)

// EmbeddingInputTask identifies the semantic purpose of vectorization.
// EmbeddingInputTask 标识向量化的语义用途。
type EmbeddingInputTask string

const (
	// EmbeddingTaskProviderDefault uses the provider model default.
	// EmbeddingTaskProviderDefault 使用供应商模型默认用途。
	EmbeddingTaskProviderDefault EmbeddingInputTask = "provider_default"
	// EmbeddingTaskQuery vectorizes a retrieval query.
	// EmbeddingTaskQuery 向量化检索查询。
	EmbeddingTaskQuery EmbeddingInputTask = "query"
	// EmbeddingTaskDocument vectorizes a retrieval document.
	// EmbeddingTaskDocument 向量化检索文档。
	EmbeddingTaskDocument EmbeddingInputTask = "document"
	// EmbeddingTaskSemanticSimilarity vectorizes semantic-similarity input.
	// EmbeddingTaskSemanticSimilarity 向量化语义相似度输入。
	EmbeddingTaskSemanticSimilarity EmbeddingInputTask = "semantic_similarity"
	// EmbeddingTaskClassification vectorizes classification input.
	// EmbeddingTaskClassification 向量化分类输入。
	EmbeddingTaskClassification EmbeddingInputTask = "classification"
	// EmbeddingTaskClustering vectorizes clustering input.
	// EmbeddingTaskClustering 向量化聚类输入。
	EmbeddingTaskClustering EmbeddingInputTask = "clustering"
	// EmbeddingTaskCodeRetrieval vectorizes code-retrieval input.
	// EmbeddingTaskCodeRetrieval 向量化代码检索输入。
	EmbeddingTaskCodeRetrieval EmbeddingInputTask = "code_retrieval"
)

// EmbeddingVectorKind identifies one closed vector representation.
// EmbeddingVectorKind 标识一种封闭向量表示。
type EmbeddingVectorKind string

const (
	// EmbeddingVectorDense contains one dense vector.
	// EmbeddingVectorDense 包含一个稠密向量。
	EmbeddingVectorDense EmbeddingVectorKind = "dense"
	// EmbeddingVectorSparse contains ordered sparse entries.
	// EmbeddingVectorSparse 包含有序稀疏条目。
	EmbeddingVectorSparse EmbeddingVectorKind = "sparse"
	// EmbeddingVectorMulti contains ordered child vectors.
	// EmbeddingVectorMulti 包含有序子向量。
	EmbeddingVectorMulti EmbeddingVectorKind = "multi_vector"
)

// EmbeddingEncoding identifies the requested vector encoding.
// EmbeddingEncoding 标识请求的向量编码。
type EmbeddingEncoding string

const (
	// EmbeddingEncodingFloat requests provider JSON numeric coordinates without inventing bit precision.
	// EmbeddingEncodingFloat 请求供应商 JSON 数值坐标且不虚构位宽精度。
	EmbeddingEncodingFloat EmbeddingEncoding = "float"
	// EmbeddingEncodingBase64 requests a provider-defined binary vector encoding.
	// EmbeddingEncodingBase64 请求供应商定义的二进制向量编码。
	EmbeddingEncodingBase64 EmbeddingEncoding = "base64"
)

// EmbeddingInput contains exactly one text or resource input.
// EmbeddingInput 只包含一个文本或资源输入。
type EmbeddingInput struct {
	// ID is stable within the ordered batch.
	// ID 在有序批次内保持稳定。
	ID string `json:"id"`
	// Text contains UTF-8 text input.
	// Text 包含 UTF-8 文本输入。
	Text *string `json:"text,omitempty"`
	// Resource contains one Router-owned media resource.
	// Resource 包含一个 Router 拥有的媒体资源。
	Resource *ResourceReference `json:"resource,omitempty"`
}

// EmbeddingOperation contains an ordered vectorization batch.
// EmbeddingOperation 包含一个有序向量化批次。
type EmbeddingOperation struct {
	// Inputs contains stable ordered input identities.
	// Inputs 包含稳定的有序输入身份。
	Inputs []EmbeddingInput `json:"inputs"`
	// InputTask identifies the requested semantic purpose.
	// InputTask 标识请求的语义用途。
	InputTask EmbeddingInputTask `json:"input_task"`
	// Dimensions optionally requests one supported dense-vector dimension.
	// Dimensions 可选地请求一个受支持稠密向量维度。
	Dimensions *int `json:"dimensions,omitempty"`
	// OutputKind requests one supported vector representation.
	// OutputKind 请求一种受支持向量表示。
	OutputKind EmbeddingVectorKind `json:"output_kind"`
	// Encoding requests one supported output encoding.
	// Encoding 请求一种受支持输出编码。
	Encoding EmbeddingEncoding `json:"encoding"`
}

// SparseEmbeddingEntry contains one ordered sparse index and value.
// SparseEmbeddingEntry 包含一个有序稀疏索引和值。
type SparseEmbeddingEntry struct {
	// Index is the provider-defined non-negative sparse dimension.
	// Index 是供应商定义的非负稀疏维度。
	Index int `json:"index"`
	// Value is the provider-reported sparse weight.
	// Value 是供应商报告的稀疏权重。
	Value float64 `json:"value"`
}

// DenseEmbedding contains one dense vector and its facts.
// DenseEmbedding 包含一个稠密向量及其事实。
type DenseEmbedding struct {
	// Values contains ordered vector coordinates.
	// Values 包含有序向量坐标。
	Values []float64 `json:"values"`
	// Base64 contains the provider-returned binary vector encoding without decoding or rewriting it.
	// Base64 包含供应商返回的二进制向量编码，且不进行解码或改写。
	Base64 string `json:"base64,omitempty"`
	// Dimensions is the exact returned vector dimension.
	// Dimensions 是返回向量的精确维度。
	Dimensions int `json:"dimensions"`
	// Normalized records provider-confirmed normalization when known.
	// Normalized 在已知时记录供应商确认的归一化事实。
	Normalized *bool `json:"normalized,omitempty"`
	// DistanceMetric records the provider-recommended distance metric when known.
	// DistanceMetric 在已知时记录供应商推荐的距离度量。
	DistanceMetric string `json:"distance_metric,omitempty"`
}

// MultiEmbeddingVector contains one ordered child vector.
// MultiEmbeddingVector 包含一个有序子向量。
type MultiEmbeddingVector struct {
	// Index preserves the provider child-vector order.
	// Index 保留供应商子向量顺序。
	Index int `json:"index"`
	// Values contains ordered vector coordinates.
	// Values 包含有序向量坐标。
	Values []float64 `json:"values"`
}

// EmbeddingItem contains exactly one returned vector representation.
// EmbeddingItem 只包含一种返回向量表示。
type EmbeddingItem struct {
	// InputID matches one request input identity.
	// InputID 匹配一个请求输入身份。
	InputID string `json:"input_id"`
	// Kind identifies the returned vector representation.
	// Kind 标识返回向量表示。
	Kind EmbeddingVectorKind `json:"kind"`
	// Dense contains dense-vector output.
	// Dense 包含稠密向量输出。
	Dense *DenseEmbedding `json:"dense,omitempty"`
	// Sparse contains ordered sparse-vector output.
	// Sparse 包含有序稀疏向量输出。
	Sparse []SparseEmbeddingEntry `json:"sparse,omitempty"`
	// MultiVector contains ordered child vectors.
	// MultiVector 包含有序子向量。
	MultiVector []MultiEmbeddingVector `json:"multi_vector,omitempty"`
	// Encoding records the actual returned encoding.
	// Encoding 记录实际返回编码。
	Encoding EmbeddingEncoding `json:"encoding"`
}

// Validate verifies ordered embedding inputs and requested output facts.
// Validate 校验有序向量输入和请求输出事实。
func (o EmbeddingOperation) Validate() error {
	if len(o.Inputs) == 0 {
		return fmt.Errorf("%w: embedding inputs are required", ErrInvalidRequest)
	}
	if !validEmbeddingInputTask(o.InputTask) {
		return fmt.Errorf("%w: invalid embedding input_task %q", ErrInvalidRequest, o.InputTask)
	}
	if o.OutputKind != EmbeddingVectorDense && o.OutputKind != EmbeddingVectorSparse && o.OutputKind != EmbeddingVectorMulti {
		return fmt.Errorf("%w: invalid embedding output_kind %q", ErrInvalidRequest, o.OutputKind)
	}
	if o.Encoding != EmbeddingEncodingFloat && o.Encoding != EmbeddingEncodingBase64 {
		return fmt.Errorf("%w: invalid embedding encoding %q", ErrInvalidRequest, o.Encoding)
	}
	if o.Dimensions != nil && *o.Dimensions <= 0 {
		return fmt.Errorf("%w: embedding dimensions must be positive", ErrInvalidRequest)
	}
	seen := make(map[string]struct{}, len(o.Inputs))
	for index := range o.Inputs {
		input := o.Inputs[index]
		if strings.TrimSpace(input.ID) == "" {
			return fmt.Errorf("%w: embedding input %d requires id", ErrInvalidRequest, index)
		}
		if _, exists := seen[input.ID]; exists {
			return fmt.Errorf("%w: duplicate embedding input id %q", ErrInvalidRequest, input.ID)
		}
		seen[input.ID] = struct{}{}
		if (input.Text == nil) == (input.Resource == nil) {
			return fmt.Errorf("%w: embedding input %q requires exactly one text or resource", ErrInvalidRequest, input.ID)
		}
		if input.Text != nil && strings.TrimSpace(*input.Text) == "" {
			return fmt.Errorf("%w: embedding input %q text is empty", ErrInvalidRequest, input.ID)
		}
		if input.Resource != nil && strings.TrimSpace(input.Resource.ResourceID) == "" {
			return fmt.Errorf("%w: embedding input %q resource_id is required", ErrInvalidRequest, input.ID)
		}
	}
	return nil
}

// Validate verifies one returned embedding, its exact representation, and finite numeric coordinates.
// Validate 校验一个返回的 Embedding、其精确表示以及有限数值坐标。
func (i EmbeddingItem) Validate() error {
	if strings.TrimSpace(i.InputID) == "" {
		return fmt.Errorf("%w: embedding result requires input_id", ErrInvalidRequest)
	}
	if i.Encoding != EmbeddingEncodingFloat && i.Encoding != EmbeddingEncodingBase64 {
		return fmt.Errorf("%w: invalid embedding result encoding %q", ErrInvalidRequest, i.Encoding)
	}
	switch i.Kind {
	case EmbeddingVectorDense:
		if i.Dense == nil || len(i.Sparse) != 0 || len(i.MultiVector) != 0 {
			return fmt.Errorf("%w: dense embedding result requires only dense output", ErrInvalidRequest)
		}
		return i.Dense.validate(i.Encoding)
	case EmbeddingVectorSparse:
		if i.Dense != nil || len(i.Sparse) == 0 || len(i.MultiVector) != 0 || i.Encoding == EmbeddingEncodingBase64 {
			return fmt.Errorf("%w: sparse embedding result requires only numeric sparse output", ErrInvalidRequest)
		}
		previous := -1
		for _, entry := range i.Sparse {
			if entry.Index < 0 || entry.Index <= previous || math.IsNaN(entry.Value) || math.IsInf(entry.Value, 0) {
				return fmt.Errorf("%w: sparse embedding entries require increasing non-negative indexes and finite values", ErrInvalidRequest)
			}
			previous = entry.Index
		}
		return nil
	case EmbeddingVectorMulti:
		if i.Dense != nil || len(i.Sparse) != 0 || len(i.MultiVector) == 0 || i.Encoding == EmbeddingEncodingBase64 {
			return fmt.Errorf("%w: multi-vector embedding result requires only numeric child vectors", ErrInvalidRequest)
		}
		for index, vector := range i.MultiVector {
			if vector.Index != index || len(vector.Values) == 0 || !finiteEmbeddingValues(vector.Values) {
				return fmt.Errorf("%w: multi-vector children require stable indexes and finite non-empty values", ErrInvalidRequest)
			}
		}
		return nil
	default:
		return fmt.Errorf("%w: invalid embedding result kind %q", ErrInvalidRequest, i.Kind)
	}
}

// validate verifies dense values or one canonical Base64 payload according to the declared encoding.
// validate 根据声明的编码校验稠密数值或一个规范 Base64 载荷。
func (d DenseEmbedding) validate(encoding EmbeddingEncoding) error {
	if d.Dimensions <= 0 {
		return fmt.Errorf("%w: dense embedding dimensions must be positive", ErrInvalidRequest)
	}
	if encoding == EmbeddingEncodingBase64 {
		if len(d.Values) != 0 || strings.TrimSpace(d.Base64) == "" {
			return fmt.Errorf("%w: Base64 dense embedding requires only encoded data", ErrInvalidRequest)
		}
		if _, errDecode := base64.StdEncoding.DecodeString(d.Base64); errDecode != nil {
			return fmt.Errorf("%w: dense embedding Base64 is invalid", ErrInvalidRequest)
		}
		return nil
	}
	if d.Base64 != "" || len(d.Values) != d.Dimensions || !finiteEmbeddingValues(d.Values) {
		return fmt.Errorf("%w: numeric dense embedding dimensions and finite values must match", ErrInvalidRequest)
	}
	return nil
}

// finiteEmbeddingValues reports whether every vector coordinate is finite.
// finiteEmbeddingValues 报告每个向量坐标是否均为有限数值。
func finiteEmbeddingValues(values []float64) bool {
	for _, value := range values {
		if math.IsNaN(value) || math.IsInf(value, 0) {
			return false
		}
	}
	return true
}

// validEmbeddingInputTask reports whether one task belongs to the closed VCP set.
// validEmbeddingInputTask 报告一个任务是否属于封闭 VCP 集合。
func validEmbeddingInputTask(task EmbeddingInputTask) bool {
	switch task {
	case EmbeddingTaskProviderDefault, EmbeddingTaskQuery, EmbeddingTaskDocument, EmbeddingTaskSemanticSimilarity, EmbeddingTaskClassification, EmbeddingTaskClustering, EmbeddingTaskCodeRetrieval:
		return true
	default:
		return false
	}
}
