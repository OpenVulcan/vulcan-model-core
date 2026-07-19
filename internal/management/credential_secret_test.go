package management

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

// recordingCredentialStore captures the exact credential passed to persistence without requiring unrelated repository fixtures.
// recordingCredentialStore 捕获传入持久化的精确凭据，且不需要无关 Repository Fixture。
type recordingCredentialStore struct {
	providerconfig.Store
	// saved is the latest credential accepted by SaveCredential.
	// saved 是 SaveCredential 最近接受的凭据。
	saved providerconfig.Credential
	// saveError is the deterministic persistence failure returned by SaveCredential.
	// saveError 是 SaveCredential 返回的确定性持久化失败。
	saveError error
}

// SaveCredential records or rejects one exact replacement metadata document.
// SaveCredential 记录或拒绝一个精确的替代元数据文档。
func (s *recordingCredentialStore) SaveCredential(_ context.Context, credential providerconfig.Credential) error {
	if s.saveError != nil {
		return s.saveError
	}
	s.saved = credential
	return nil
}

// replacementDeleteFailureStore records the latest replacement reference and fails only its compensating deletion.
// replacementDeleteFailureStore 记录最新替代引用，并且只让该引用的补偿删除失败。
type replacementDeleteFailureStore struct {
	secret.Store
	// replacementReference is the latest reference created through this wrapper.
	// replacementReference 是通过此 Wrapper 创建的最新引用。
	replacementReference string
	// deleteError is returned when compensation targets the replacement reference.
	// deleteError 在补偿操作指向替代引用时返回。
	deleteError error
}

// Put delegates protection and records the exact replacement reference.
// Put 委托保护操作并记录精确替代引用。
func (s *replacementDeleteFailureStore) Put(ctx context.Context, value []byte) (string, error) {
	reference, errPut := s.Store.Put(ctx, value)
	if errPut == nil {
		s.replacementReference = reference
	}
	return reference, errPut
}

// Delete fails replacement compensation while delegating every other deletion.
// Delete 让替代值补偿删除失败，并委托所有其他删除。
func (s *replacementDeleteFailureStore) Delete(ctx context.Context, reference string) error {
	if reference == s.replacementReference {
		return s.deleteError
	}
	return s.Store.Delete(ctx, reference)
}

// TestPersistCredentialSecretReplacementCommitsThenDeletes verifies the new reference is durable before the old secret is removed.
// TestPersistCredentialSecretReplacementCommitsThenDeletes 验证新引用持久化后才删除旧 Secret。
func TestPersistCredentialSecretReplacementCommitsThenDeletes(t *testing.T) {
	ctx := context.Background()
	secrets := secret.NewMemoryStore()
	previousReference, errPrevious := secrets.Put(ctx, []byte("previous"))
	if errPrevious != nil {
		t.Fatalf("put previous secret: %v", errPrevious)
	}
	configurations := &recordingCredentialStore{}
	credential, errPersist := persistCredentialSecretReplacement(ctx, configurations, secrets, providerconfig.Credential{ID: "cred-refresh", SecretRef: previousReference, Revision: 4}, []byte("replacement"))
	if errPersist != nil {
		t.Fatalf("persistCredentialSecretReplacement() error = %v", errPersist)
	}
	if credential.SecretRef == previousReference || credential.SecretRef == "" || credential.Revision != 5 || configurations.saved.SecretRef != credential.SecretRef {
		t.Fatalf("persisted credential = %#v, recorded = %#v", credential, configurations.saved)
	}
	if secrets.Count() != 1 {
		t.Fatalf("secret count = %d, want 1", secrets.Count())
	}
	if _, errOld := secrets.Get(ctx, previousReference); !errors.Is(errOld, secret.ErrNotFound) {
		t.Fatalf("previous secret error = %v, want not found", errOld)
	}
}

// TestPersistCredentialSecretReplacementReportsCompensationFailure verifies no failed cleanup is hidden behind the metadata error.
// TestPersistCredentialSecretReplacementReportsCompensationFailure 验证补偿清理失败不会被元数据错误掩盖。
func TestPersistCredentialSecretReplacementReportsCompensationFailure(t *testing.T) {
	ctx := context.Background()
	delegate := secret.NewMemoryStore()
	previousReference, errPrevious := delegate.Put(ctx, []byte("previous"))
	if errPrevious != nil {
		t.Fatalf("put previous secret: %v", errPrevious)
	}
	saveError := errors.New("save metadata failed")
	deleteError := errors.New("delete replacement failed")
	configurations := &recordingCredentialStore{saveError: saveError}
	secrets := &replacementDeleteFailureStore{Store: delegate, deleteError: deleteError}
	_, errPersist := persistCredentialSecretReplacement(ctx, configurations, secrets, providerconfig.Credential{ID: "cred-refresh", SecretRef: previousReference, Revision: 4}, []byte("replacement"))
	if !errors.Is(errPersist, deleteError) || !strings.Contains(errPersist.Error(), saveError.Error()) {
		t.Fatalf("persistCredentialSecretReplacement() error = %v, want save and compensation failures", errPersist)
	}
	if delegate.Count() != 2 {
		t.Fatalf("secret count = %d, want explicit orphan evidence 2", delegate.Count())
	}
}
