package vcp

import (
	"encoding/json"
	"fmt"
)

// CloneExecutionRequest returns an exact mutation-safe copy through the authoritative JSON contract.
// CloneExecutionRequest 通过权威 JSON 契约返回精确且防外部修改的执行请求副本。
func CloneExecutionRequest(source ExecutionRequest) (ExecutionRequest, error) {
	encoded, errEncode := json.Marshal(source)
	if errEncode != nil {
		return ExecutionRequest{}, fmt.Errorf("encode execution request clone: %w", errEncode)
	}
	// cloned is decoded into the same closed type so every slice, pointer, and RawMessage obtains independent storage.
	// cloned 被解码到相同封闭类型，因此每个切片、指针和 RawMessage 都获得独立存储。
	var cloned ExecutionRequest
	if errDecode := json.Unmarshal(encoded, &cloned); errDecode != nil {
		return ExecutionRequest{}, fmt.Errorf("decode execution request clone: %w", errDecode)
	}
	return cloned, nil
}
