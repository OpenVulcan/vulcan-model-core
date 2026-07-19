package provider

import "errors"

var (
	// ErrAuthenticationRejected reports that an upstream authentication service rejected provider-issued credential material.
	// ErrAuthenticationRejected 表示上游认证服务拒绝了供应商签发的凭据材料。
	ErrAuthenticationRejected = errors.New("provider authentication was rejected")
	// ErrAuthenticationUnavailable reports that an upstream authentication service could not complete a request because it was unreachable or temporarily unavailable.
	// ErrAuthenticationUnavailable 表示上游认证服务因无法连接或暂时不可用而无法完成请求。
	ErrAuthenticationUnavailable = errors.New("provider authentication service is unavailable")
	// ErrAuthenticationResponseInvalid reports that an upstream authentication service returned an unusable response.
	// ErrAuthenticationResponseInvalid 表示上游认证服务返回了无法使用的响应。
	ErrAuthenticationResponseInvalid = errors.New("provider authentication response is invalid")
)
