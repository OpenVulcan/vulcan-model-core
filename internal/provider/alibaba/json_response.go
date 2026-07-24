package alibaba

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
)

// decodeAlibabaJSONResponse decodes exactly one bounded Alibaba response and rejects every trailing JSON value.
// decodeAlibabaJSONResponse 解码一个有界的阿里响应，并拒绝任何尾随 JSON 值。
// The reader is the exact successful upstream body, destination is a typed response pointer, and invalidResponse preserves the driver-specific protocol error.
// reader 是精确的成功上游响应体，destination 是强类型响应指针，invalidResponse 用于保留 Driver 专属协议错误。
func decodeAlibabaJSONResponse(reader io.Reader, destination any, invalidResponse error) error {
	if reader == nil || destination == nil || invalidResponse == nil {
		return errors.New("Alibaba response reader, destination, and protocol error are required")
	}
	bounded, errBound := transport.NewBoundedResponseReader(reader, transport.MaximumNonStreamingResponseBytes)
	if errBound != nil {
		return fmt.Errorf("%w: bound response: %w", invalidResponse, errBound)
	}
	decoder := json.NewDecoder(bounded)
	if errDecode := decoder.Decode(destination); errDecode != nil {
		return fmt.Errorf("%w: decode response: %w", invalidResponse, errDecode)
	}
	if errTrailing := decoder.Decode(&struct{}{}); !errors.Is(errTrailing, io.EOF) {
		if errTrailing != nil {
			return fmt.Errorf("%w: trailing response data: %w", invalidResponse, errTrailing)
		}
		return fmt.Errorf("%w: trailing response data", invalidResponse)
	}
	return nil
}
