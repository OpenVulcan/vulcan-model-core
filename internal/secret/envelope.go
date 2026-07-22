package secret

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	// envelopeDataKeyBytes is the AES-256 data-encryption key size.
	// envelopeDataKeyBytes 是 AES-256 数据加密密钥长度。
	envelopeDataKeyBytes = 32
	// maximumEnvelopeKeyIDBytes bounds operator-controlled key identifiers in protected files.
	// maximumEnvelopeKeyIDBytes 限制受保护文件中操作员控制的密钥标识长度。
	maximumEnvelopeKeyIDBytes = 1024
	// maximumWrappedDataKeyBytes bounds KMS or HSM ciphertext metadata.
	// maximumWrappedDataKeyBytes 限制 KMS 或 HSM 密钥密文元数据长度。
	maximumWrappedDataKeyBytes = 64 << 10
	// maximumEnvelopePlaintextBytes bounds one credential document before allocation.
	// maximumEnvelopePlaintextBytes 限制单个凭据文档在分配前的明文长度。
	maximumEnvelopePlaintextBytes = 4 << 20
)

var (
	// envelopeMagic identifies the exact durable envelope format and version.
	// envelopeMagic 标识精确的持久信封格式与版本。
	envelopeMagic = [4]byte{'V', 'S', 'K', 1}
)

// WrappedDataKey contains one KMS or HSM wrapped data key and its immutable key-version identifier.
// WrappedDataKey 包含一个 KMS 或 HSM 包装的数据密钥及其不可变密钥版本标识。
type WrappedDataKey struct {
	// KeyID identifies the exact wrapping-key version required for later decryption.
	// KeyID 标识后续解密所需的精确包装密钥版本。
	KeyID string
	// Ciphertext is the provider-produced wrapped data key and never plaintext key material.
	// Ciphertext 是提供者生成的包装数据密钥，绝不是明文密钥材料。
	Ciphertext []byte
}

// KeyWrapper isolates provider-specific KMS, HSM, or key-vault operations from local durable storage.
// KeyWrapper 将供应商特定 KMS、HSM 或密钥库操作与本地持久存储隔离。
type KeyWrapper interface {
	// WrapDataKey encrypts one freshly generated 256-bit data key and returns its immutable key version.
	// WrapDataKey 加密一个新生成的 256 位数据密钥并返回其不可变密钥版本。
	WrapDataKey([]byte) (WrappedDataKey, error)
	// UnwrapDataKey decrypts one data key only through the exact recorded key version.
	// UnwrapDataKey 仅通过记录的精确密钥版本解密一个数据密钥。
	UnwrapDataKey(WrappedDataKey) ([]byte, error)
}

// EnvelopeProtector protects each secret with a unique AES-256-GCM data key wrapped by an external key boundary.
// EnvelopeProtector 使用由外部密钥边界包装的唯一 AES-256-GCM 数据密钥保护每个 Secret。
type EnvelopeProtector struct {
	// wrapper owns all access to the non-exportable wrapping key.
	// wrapper 拥有对不可导出包装密钥的全部访问权。
	wrapper KeyWrapper
	// random supplies cryptographically secure data keys and nonces.
	// random 提供密码学安全的数据密钥与 Nonce。
	random io.Reader
}

// NewEnvelopeProtector creates a KMS/HSM-ready protector without accepting a plaintext master key.
// NewEnvelopeProtector 创建一个可用于 KMS/HSM 的保护器，且不接受明文主密钥。
func NewEnvelopeProtector(wrapper KeyWrapper) (*EnvelopeProtector, error) {
	if wrapper == nil {
		return nil, errors.New("secret key wrapper is required")
	}
	return &EnvelopeProtector{wrapper: wrapper, random: rand.Reader}, nil
}

// Protect encrypts one bounded secret with a fresh data key and authenticates all wrapping metadata.
// Protect 使用新数据密钥加密一个受限 Secret，并认证全部包装元数据。
func (p *EnvelopeProtector) Protect(plaintext []byte) ([]byte, error) {
	if p == nil || p.wrapper == nil || p.random == nil {
		return nil, errors.New("envelope protector is not initialized")
	}
	if len(plaintext) == 0 || len(plaintext) > maximumEnvelopePlaintextBytes {
		return nil, errors.New("secret plaintext size is outside the allowed boundary")
	}
	// dataKey is unique per secret and is cleared after both encryption and wrapping complete.
	// dataKey 对每个 Secret 唯一，并在加密与包装完成后清零。
	dataKey := make([]byte, envelopeDataKeyBytes)
	defer clear(dataKey)
	if _, errRandom := io.ReadFull(p.random, dataKey); errRandom != nil {
		return nil, fmt.Errorf("generate envelope data key: %w", errRandom)
	}
	wrapped, errWrap := p.wrapper.WrapDataKey(dataKey)
	if errWrap != nil {
		return nil, fmt.Errorf("wrap envelope data key: %w", errWrap)
	}
	defer clear(wrapped.Ciphertext)
	if errWrapped := validateWrappedDataKey(wrapped); errWrapped != nil {
		return nil, errWrapped
	}
	block, errCipher := aes.NewCipher(dataKey)
	if errCipher != nil {
		return nil, fmt.Errorf("create envelope cipher: %w", errCipher)
	}
	gcm, errGCM := cipher.NewGCM(block)
	if errGCM != nil {
		return nil, fmt.Errorf("create envelope AEAD: %w", errGCM)
	}
	// nonce is unique for the unique random data key and is stored in clear text as required by GCM.
	// nonce 对唯一随机数据密钥保持唯一，并按 GCM 要求以明文保存。
	nonce := make([]byte, gcm.NonceSize())
	if _, errRandom := io.ReadFull(p.random, nonce); errRandom != nil {
		return nil, fmt.Errorf("generate envelope nonce: %w", errRandom)
	}
	header, errHeader := encodeEnvelopeHeader(wrapped, nonce)
	if errHeader != nil {
		return nil, errHeader
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, header)
	protected := make([]byte, 0, len(header)+len(ciphertext))
	protected = append(protected, header...)
	protected = append(protected, ciphertext...)
	clear(ciphertext)
	return protected, nil
}

// Unprotect authenticates envelope metadata, unwraps the exact data key, and decrypts one bounded secret.
// Unprotect 认证信封元数据、解包精确数据密钥并解密一个受限 Secret。
func (p *EnvelopeProtector) Unprotect(protected []byte) ([]byte, error) {
	if p == nil || p.wrapper == nil {
		return nil, errors.New("envelope protector is not initialized")
	}
	wrapped, nonce, headerLength, errDecode := decodeEnvelopeHeader(protected)
	if errDecode != nil {
		return nil, errDecode
	}
	defer clear(wrapped.Ciphertext)
	defer clear(nonce)
	dataKey, errUnwrap := p.wrapper.UnwrapDataKey(wrapped)
	defer clear(dataKey)
	if errUnwrap != nil {
		return nil, fmt.Errorf("unwrap envelope data key: %w", errUnwrap)
	}
	if len(dataKey) != envelopeDataKeyBytes {
		return nil, errors.New("unwrapped envelope data key has an invalid length")
	}
	block, errCipher := aes.NewCipher(dataKey)
	if errCipher != nil {
		return nil, fmt.Errorf("create envelope cipher: %w", errCipher)
	}
	gcm, errGCM := cipher.NewGCM(block)
	if errGCM != nil {
		return nil, fmt.Errorf("create envelope AEAD: %w", errGCM)
	}
	if len(nonce) != gcm.NonceSize() || len(protected)-headerLength < gcm.Overhead() {
		return nil, errors.New("protected secret envelope has invalid ciphertext dimensions")
	}
	plaintext, errOpen := gcm.Open(nil, nonce, protected[headerLength:], protected[:headerLength])
	if errOpen != nil {
		return nil, errors.New("protected secret envelope authentication failed")
	}
	if len(plaintext) == 0 || len(plaintext) > maximumEnvelopePlaintextBytes {
		clear(plaintext)
		return nil, errors.New("secret plaintext size is outside the allowed boundary")
	}
	return plaintext, nil
}

// validateWrappedDataKey verifies one closed wrapping result before it enters a durable envelope.
// validateWrappedDataKey 在包装结果进入持久信封前校验其封闭结构。
func validateWrappedDataKey(wrapped WrappedDataKey) error {
	keyID := strings.TrimSpace(wrapped.KeyID)
	if keyID == "" || keyID != wrapped.KeyID || len(keyID) > maximumEnvelopeKeyIDBytes || len(wrapped.Ciphertext) == 0 || len(wrapped.Ciphertext) > maximumWrappedDataKeyBytes {
		return errors.New("wrapped envelope data key is outside the allowed boundary")
	}
	return nil
}

// encodeEnvelopeHeader encodes and authenticates the exact key version, wrapped key, and nonce.
// encodeEnvelopeHeader 编码并认证精确密钥版本、包装密钥与 Nonce。
func encodeEnvelopeHeader(wrapped WrappedDataKey, nonce []byte) ([]byte, error) {
	if errWrapped := validateWrappedDataKey(wrapped); errWrapped != nil {
		return nil, errWrapped
	}
	if len(nonce) == 0 || len(nonce) > 255 {
		return nil, errors.New("envelope nonce length is invalid")
	}
	header := bytes.NewBuffer(make([]byte, 0, 11+len(wrapped.KeyID)+len(wrapped.Ciphertext)+len(nonce)))
	header.Write(envelopeMagic[:])
	_ = binary.Write(header, binary.BigEndian, uint16(len(wrapped.KeyID)))
	_ = binary.Write(header, binary.BigEndian, uint32(len(wrapped.Ciphertext)))
	header.WriteByte(byte(len(nonce)))
	header.WriteString(wrapped.KeyID)
	header.Write(wrapped.Ciphertext)
	header.Write(nonce)
	return header.Bytes(), nil
}

// decodeEnvelopeHeader parses one bounded durable envelope without allocating attacker-selected unbounded slices.
// decodeEnvelopeHeader 解析一个受限持久信封，且不分配攻击者选择的无界切片。
func decodeEnvelopeHeader(protected []byte) (WrappedDataKey, []byte, int, error) {
	const fixedHeaderBytes = 11
	if len(protected) < fixedHeaderBytes || !bytes.Equal(protected[:len(envelopeMagic)], envelopeMagic[:]) {
		return WrappedDataKey{}, nil, 0, errors.New("protected secret envelope format is invalid")
	}
	keyIDLength := int(binary.BigEndian.Uint16(protected[4:6]))
	wrappedLength := int(binary.BigEndian.Uint32(protected[6:10]))
	nonceLength := int(protected[10])
	if keyIDLength == 0 || keyIDLength > maximumEnvelopeKeyIDBytes || wrappedLength == 0 || wrappedLength > maximumWrappedDataKeyBytes || nonceLength == 0 {
		return WrappedDataKey{}, nil, 0, errors.New("protected secret envelope dimensions are invalid")
	}
	headerLength := fixedHeaderBytes + keyIDLength + wrappedLength + nonceLength
	if headerLength < fixedHeaderBytes || headerLength > len(protected) {
		return WrappedDataKey{}, nil, 0, errors.New("protected secret envelope is truncated")
	}
	keyIDEnd := fixedHeaderBytes + keyIDLength
	wrappedEnd := keyIDEnd + wrappedLength
	wrapped := WrappedDataKey{KeyID: string(protected[fixedHeaderBytes:keyIDEnd]), Ciphertext: append([]byte(nil), protected[keyIDEnd:wrappedEnd]...)}
	if errWrapped := validateWrappedDataKey(wrapped); errWrapped != nil {
		return WrappedDataKey{}, nil, 0, errWrapped
	}
	nonce := append([]byte(nil), protected[wrappedEnd:headerLength]...)
	return wrapped, nonce, headerLength, nil
}
