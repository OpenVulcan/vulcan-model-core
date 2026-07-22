package minimax

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// rejectTrailingJSON rejects a second JSON document after one MiniMax response.
// rejectTrailingJSON 拒绝 MiniMax 响应后的第二个 JSON 文档。
func rejectTrailingJSON(decoder *json.Decoder, category error) error {
	var trailing json.RawMessage
	if errDecode := decoder.Decode(&trailing); errors.Is(errDecode, io.EOF) {
		return nil
	} else if errDecode != nil {
		return fmt.Errorf("%w: decode trailing response: %v", category, errDecode)
	}
	return fmt.Errorf("%w: trailing JSON document", category)
}
