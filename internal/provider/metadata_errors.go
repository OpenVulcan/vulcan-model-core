package provider

import "errors"

var (
	// ErrMetadataAuthentication reports that an upstream provider rejected the stored credential.
	// ErrMetadataAuthentication 表示上游供应商拒绝了已存储凭据。
	ErrMetadataAuthentication = errors.New("provider metadata authentication failed")
	// ErrMetadataUnavailable reports that an upstream provider could not be reached or was temporarily unavailable.
	// ErrMetadataUnavailable 表示无法连接上游供应商或上游暂时不可用。
	ErrMetadataUnavailable = errors.New("provider metadata service unavailable")
	// ErrMetadataResponseInvalid reports that an upstream provider returned an unusable metadata response.
	// ErrMetadataResponseInvalid 表示上游供应商返回了无法使用的元数据响应。
	ErrMetadataResponseInvalid = errors.New("provider metadata response is invalid")
)
