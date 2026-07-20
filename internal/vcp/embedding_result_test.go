package vcp

import "testing"

// TestEmbeddingItemValidateClosesRepresentations verifies numeric and Base64 dense outputs cannot be mixed.
// TestEmbeddingItemValidateClosesRepresentations 验证数值与 Base64 稠密输出不能混用。
func TestEmbeddingItemValidateClosesRepresentations(t *testing.T) {
	valid := EmbeddingItem{InputID: "input-1", Kind: EmbeddingVectorDense, Encoding: EmbeddingEncodingFloat, Dense: &DenseEmbedding{Values: []float64{1, 2}, Dimensions: 2}}
	if errValidate := valid.Validate(); errValidate != nil {
		t.Fatalf("Validate() error = %v", errValidate)
	}
	invalid := valid
	invalid.Dense.Base64 = "AQID"
	if errValidate := invalid.Validate(); errValidate == nil {
		t.Fatal("Validate() error = nil, want mixed representation rejection")
	}
	encoded := EmbeddingItem{InputID: "input-1", Kind: EmbeddingVectorDense, Encoding: EmbeddingEncodingBase64, Dense: &DenseEmbedding{Base64: "AQID", Dimensions: 3}}
	if errValidate := encoded.Validate(); errValidate != nil {
		t.Fatalf("Base64 Validate() error = %v", errValidate)
	}
}
