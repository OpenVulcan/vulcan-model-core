//go:build !windows

package secret

// newPlatformProtector rejects platforms that do not yet have an approved native protection provider.
// newPlatformProtector 拒绝尚未拥有获准原生保护提供者的平台。
func newPlatformProtector() (Protector, error) {
	return nil, ErrPlatformSecretStoreUnavailable
}
