package catalogdata

import "testing"

// TestEmbeddedParameterMappingsAreClosedAndReviewed verifies every committed mapping has one exact action, path, transform, and evidence revision.
// TestEmbeddedParameterMappingsAreClosedAndReviewed 验证每个已提交映射具有一个精确动作、路径、转换与证据修订。
func TestEmbeddedParameterMappingsAreClosedAndReviewed(t *testing.T) {
	mappings, errMappings := LoadParameterMappings()
	if errMappings != nil {
		t.Fatalf("LoadParameterMappings() error = %v", errMappings)
	}
	if len(mappings.Entries) < 30 {
		t.Fatalf("mapping count = %d, want complete reviewed first-wave surface", len(mappings.Entries))
	}
}

// TestParameterMappingRejectsWhitespaceAliases verifies reviewed semantic and wire paths are exact identities.
// TestParameterMappingRejectsWhitespaceAliases 验证已审核语义路径与 Wire 路径均为精确身份。
func TestParameterMappingRejectsWhitespaceAliases(t *testing.T) {
	base := ParameterMappingEntry{ID: "alibaba.test", ActionBindingID: "action_test", Operation: "conversation.respond", VCPField: "payload.conversation", OutboundJSONPath: "messages", EvidenceRevision: 1, Evidence: "test evidence"}
	for _, mutate := range []func(*ParameterMappingEntry){
		func(entry *ParameterMappingEntry) { entry.ID += " " },
		func(entry *ParameterMappingEntry) { entry.ActionBindingID += " " },
		func(entry *ParameterMappingEntry) { entry.VCPField += " " },
		func(entry *ParameterMappingEntry) { entry.OutboundJSONPath += " " },
		func(entry *ParameterMappingEntry) { entry.Transform = " singleton_array" },
		func(entry *ParameterMappingEntry) { entry.Evidence += " " },
	} {
		candidate := base
		mutate(&candidate)
		if errValidate := candidate.Validate(); errValidate == nil {
			t.Fatalf("Validate() accepted whitespace alias %#v", candidate)
		}
	}
}
