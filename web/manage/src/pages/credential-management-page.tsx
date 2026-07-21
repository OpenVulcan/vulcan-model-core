import { ProviderManagementPage } from "@/pages/provider-management-page";

// CredentialManagementPageProps identifies the authenticated management session used for credential operations.
// CredentialManagementPageProps 标识用于凭据操作的已认证管理会话。
interface CredentialManagementPageProps {
  // managementAuthToken authorizes management API requests without persistent page storage.
  // managementAuthToken 授权管理 API 请求且不进行页面持久化存储。
  managementAuthToken: string;
}

// CredentialManagementPage renders the separated provider tree and account credential workspace.
// CredentialManagementPage 渲染拆分后的供应商树与账号凭据工作区。
export function CredentialManagementPage({
  managementAuthToken,
}: CredentialManagementPageProps) {
  return (
    <ProviderManagementPage
      managementAuthToken={managementAuthToken}
      mode="credential"
    />
  );
}
