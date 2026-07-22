package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"testing"
)

// testKeyWrapper is a test-only AEAD stand-in for a non-exportable KMS or HSM wrapping key.
// testKeyWrapper 是仅用于测试的 AEAD 替身，代表不可导出的 KMS 或 HSM 包装密钥。
type testKeyWrapper struct {
	// key is test-only wrapping material and never enters production configuration.
	// key 是仅用于测试的包装材料，绝不进入生产配置。
	key []byte
}

// WrapDataKey wraps one data key through the test-only AEAD boundary.
// WrapDataKey 通过仅用于测试的 AEAD 边界包装一个数据密钥。
func (w testKeyWrapper) WrapDataKey(dataKey []byte) (WrappedDataKey, error) {
	block, errCipher := aes.NewCipher(w.key)
	if errCipher != nil {
		return WrappedDataKey{}, errCipher
	}
	gcm, errGCM := cipher.NewGCM(block)
	if errGCM != nil {
		return WrappedDataKey{}, errGCM
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, errRandom := rand.Read(nonce); errRandom != nil {
		return WrappedDataKey{}, errRandom
	}
	ciphertext := gcm.Seal(nonce, nonce, dataKey, []byte("test-key-v1"))
	return WrappedDataKey{KeyID: "test-key-v1", Ciphertext: ciphertext}, nil
}

// UnwrapDataKey unwraps one test data key only for its exact key version.
// UnwrapDataKey 仅为精确密钥版本解包一个测试数据密钥。
func (w testKeyWrapper) UnwrapDataKey(wrapped WrappedDataKey) ([]byte, error) {
	if wrapped.KeyID != "test-key-v1" {
		return nil, errors.New("unknown test key")
	}
	block, errCipher := aes.NewCipher(w.key)
	if errCipher != nil {
		return nil, errCipher
	}
	gcm, errGCM := cipher.NewGCM(block)
	if errGCM != nil {
		return nil, errGCM
	}
	if len(wrapped.Ciphertext) < gcm.NonceSize() {
		return nil, errors.New("truncated test wrapped key")
	}
	nonce := wrapped.Ciphertext[:gcm.NonceSize()]
	return gcm.Open(nil, nonce, wrapped.Ciphertext[gcm.NonceSize():], []byte(wrapped.KeyID))
}

// TestEnvelopeProtectorRoundTripAndTamperRejection verifies unique encryption, exact recovery, and authenticated metadata.
// TestEnvelopeProtectorRoundTripAndTamperRejection 验证唯一加密、精确恢复与元数据认证。
func TestEnvelopeProtectorRoundTripAndTamperRejection(t *testing.T) {
	wrappingKey := make([]byte, 32)
	if _, errRandom := rand.Read(wrappingKey); errRandom != nil {
		t.Fatalf("generate wrapping key: %v", errRandom)
	}
	protector, errProtector := NewEnvelopeProtector(testKeyWrapper{key: wrappingKey})
	if errProtector != nil {
		t.Fatalf("NewEnvelopeProtector() error = %v", errProtector)
	}
	plaintext := []byte(`{"access_token":"secret","refresh_token":"private"}`)
	first, errFirst := protector.Protect(plaintext)
	second, errSecond := protector.Protect(plaintext)
	if errFirst != nil || errSecond != nil {
		t.Fatalf("Protect() errors = (%v, %v)", errFirst, errSecond)
	}
	if string(first) == string(second) || string(first) == string(plaintext) {
		t.Fatal("Protect() did not produce unique opaque ciphertext")
	}
	recovered, errRecovered := protector.Unprotect(first)
	if errRecovered != nil || string(recovered) != string(plaintext) {
		t.Fatalf("Unprotect() = (%q, %v)", recovered, errRecovered)
	}
	for _, index := range []int{4, len(first) / 2, len(first) - 1} {
		tampered := append([]byte(nil), first...)
		tampered[index] ^= 0x01
		if _, errTampered := protector.Unprotect(tampered); errTampered == nil {
			t.Fatalf("Unprotect() accepted tampering at byte %d", index)
		}
	}
}

// TestEnvelopeProtectorRejectsInvalidBoundaries verifies empty, oversized, and malformed payloads fail closed.
// TestEnvelopeProtectorRejectsInvalidBoundaries 验证空、超限与畸形载荷全部关闭失败。
func TestEnvelopeProtectorRejectsInvalidBoundaries(t *testing.T) {
	protector, errProtector := NewEnvelopeProtector(testKeyWrapper{key: make([]byte, 32)})
	if errProtector != nil {
		t.Fatalf("NewEnvelopeProtector() error = %v", errProtector)
	}
	if _, errEmpty := protector.Protect(nil); errEmpty == nil {
		t.Fatal("Protect() accepted empty plaintext")
	}
	if _, errLarge := protector.Protect(make([]byte, maximumEnvelopePlaintextBytes+1)); errLarge == nil {
		t.Fatal("Protect() accepted oversized plaintext")
	}
	if _, errMalformed := protector.Unprotect([]byte("plaintext")); errMalformed == nil {
		t.Fatal("Unprotect() accepted malformed data")
	}
}
