// rememberCredentialStorageKey identifies the persisted opt-in preference for browser credential storage.
// rememberCredentialStorageKey 标识浏览器凭证存储的持久化选择偏好。
const rememberCredentialStorageKey =
  "vulcan-model-router.management.remember-credential"

// managementAuthTokenStorageKey identifies the server-validated management credential stored after successful login.
// managementAuthTokenStorageKey 标识登录成功后存储的、已经服务端验证的管理凭证。
const managementAuthTokenStorageKey =
  "vulcan-model-router.management.auth-token"

// StoredManagementCredential represents the exact remembered-login state read from browser localStorage.
// StoredManagementCredential 表示从浏览器 localStorage 读取的精确记忆登录状态。
export interface StoredManagementCredential {
  // rememberCredential indicates whether the user opted into persistent browser credential storage.
  // rememberCredential 表示用户是否选择持久化浏览器凭证存储。
  rememberCredential: boolean
  // authToken contains a previously validated token only when the remember preference remains enabled.
  // authToken 仅在保存偏好仍启用时包含此前已验证的令牌。
  authToken: string
}

// readStoredManagementCredential reads the remembered preference and its associated validated token.
// readStoredManagementCredential 读取记忆偏好及其关联的已验证令牌。
// Returns an empty token when remembering is disabled or no validated token has been stored.
// 当保存功能未启用或不存在已验证令牌时返回空令牌。
export function readStoredManagementCredential(): StoredManagementCredential {
  // rememberCredential is true only for the exact value written by the opt-in checkbox.
  // rememberCredential 仅在值与勾选框写入的精确值一致时为 true。
  const rememberCredential =
    window.localStorage.getItem(rememberCredentialStorageKey) === "true"
  // authToken is ignored unless the user explicitly retained the remember preference.
  // authToken 会在用户未明确保留保存偏好时被忽略。
  const authToken = rememberCredential
    ? (window.localStorage.getItem(managementAuthTokenStorageKey) ?? "")
    : ""

  return {
    rememberCredential,
    authToken,
  }
}

// setRememberCredentialPreference persists the checkbox state without storing an unvalidated credential.
// setRememberCredentialPreference 持久化勾选状态，但不会存储未经验证的凭证。
// rememberCredential is the user's current explicit storage choice.
// rememberCredential 是用户当前明确选择的存储状态。
export function setRememberCredentialPreference(
  rememberCredential: boolean,
): void {
  if (rememberCredential) {
    // staleTokenCleanup guarantees that checking the option cannot reactivate an orphaned credential.
    // staleTokenCleanup 确保勾选该选项不会重新激活孤立的旧凭证。
    clearStoredManagementAuthToken()
    window.localStorage.setItem(rememberCredentialStorageKey, "true")
    return
  }

  clearStoredManagementCredential()
}

// saveRememberedManagementCredential stores a token only after the management API has accepted it.
// saveRememberedManagementCredential 仅在管理 API 接受令牌后存储该令牌。
// authToken is the trimmed, server-validated management credential.
// authToken 是已去除首尾空白且经服务端验证的管理凭证。
export function saveRememberedManagementCredential(authToken: string): void {
  window.localStorage.setItem(rememberCredentialStorageKey, "true")
  window.localStorage.setItem(managementAuthTokenStorageKey, authToken)
}

// clearStoredManagementAuthToken removes an invalid credential while retaining the user's checked preference.
// clearStoredManagementAuthToken 删除无效凭证，同时保留用户的勾选偏好。
export function clearStoredManagementAuthToken(): void {
  window.localStorage.removeItem(managementAuthTokenStorageKey)
}

// clearStoredManagementCredential removes both the persisted credential and its remember preference.
// clearStoredManagementCredential 同时删除持久化凭证及其保存偏好。
export function clearStoredManagementCredential(): void {
  window.localStorage.removeItem(managementAuthTokenStorageKey)
  window.localStorage.removeItem(rememberCredentialStorageKey)
}
