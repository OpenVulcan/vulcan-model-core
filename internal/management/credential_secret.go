package management

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

// persistCredentialSecretReplacement atomically points credential metadata at a protected replacement and reports every cleanup failure.
// persistCredentialSecretReplacement 以原子方式将凭据元数据指向受保护替代值，并报告每个清理失败。
func persistCredentialSecretReplacement(ctx context.Context, configurations providerconfig.Store, secrets secret.Store, credential providerconfig.Credential, encoded []byte) (providerconfig.Credential, error) {
	replacementReference, errPut := secrets.Put(ctx, encoded)
	if errPut != nil {
		return providerconfig.Credential{}, errPut
	}
	previousReference := credential.SecretRef
	credential.SecretRef = replacementReference
	credential.Fingerprint = credentialFingerprint(encoded)
	credential.Revision++
	if errSave := configurations.SaveCredential(ctx, credential); errSave != nil {
		if errDelete := secrets.Delete(context.WithoutCancel(ctx), replacementReference); errDelete != nil {
			return providerconfig.Credential{}, fmt.Errorf("save replacement credential metadata: %v; compensate replacement secret: %w", errSave, errDelete)
		}
		return providerconfig.Credential{}, errSave
	}
	if errDelete := secrets.Delete(context.WithoutCancel(ctx), previousReference); errDelete != nil {
		return credential, fmt.Errorf("persisted replacement credential but could not delete superseded secret: %w", errDelete)
	}
	return credential, nil
}

// credentialFingerprint derives the sole irreversible credential identity accepted by management workflows.
// credentialFingerprint 派生管理工作流唯一接受的不可逆凭据身份。
func credentialFingerprint(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
