import { useCallback, useEffect, useRef, useState } from "react"

import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import {
  Field,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { useI18n } from "@/i18n"
import {
  clearStoredManagementAuthToken,
  clearStoredManagementCredential,
  readStoredManagementCredential,
  saveRememberedManagementCredential,
  setRememberCredentialPreference,
} from "@/lib/management-credential-storage"
import { cn } from "@/lib/utils"

// LoginFormProps defines the in-memory handoff of a server-validated management auth token.
// LoginFormProps 定义已通过服务端验证的管理 Auth token 的内存交接。
interface LoginFormProps extends Omit<React.ComponentProps<"form">, "onSubmit"> {
  // onAuthenticated receives the trimmed token only after the management API accepts it.
  // onAuthenticated 仅在管理 API 接受令牌后接收去除空白的令牌。
  onAuthenticated: (authToken: string) => void
}

// AuthenticationErrorKey identifies one localizable login-verification outcome.
// AuthenticationErrorKey 标识一种可本地化的登录验证结果。
type AuthenticationErrorKey =
  | "login.error.empty"
  | "login.error.invalid"
  | "login.error.unavailable"
  | "login.error.validation"

// LoginForm validates one management auth token through the protected local management API.
// LoginForm 通过受保护的本地管理 API 验证单一管理 Auth token。
export function LoginForm({
  className,
  onAuthenticated,
  ...props
}: LoginFormProps) {
  // t resolves all authored login text into the current interface language.
  // t 将所有已编写登录文案解析为当前界面语言。
  const { t } = useI18n()
  // initialStoredCredential captures the persisted opt-in state once for this login-page mount.
  // initialStoredCredential 在本次登录页挂载时仅捕获一次持久化选择状态。
  const [initialStoredCredential] = useState(readStoredManagementCredential)
  // authToken holds the current credential input or the previously validated remembered credential.
  // authToken 保存当前输入凭证或此前已验证并保存的凭证。
  const [authToken, setAuthToken] = useState(initialStoredCredential.authToken)
  // rememberCredential mirrors the persisted checkbox choice independently from token validity.
  // rememberCredential 独立于令牌有效性反映持久化勾选选择。
  const [rememberCredential, setRememberCredential] = useState(
    initialStoredCredential.rememberCredential,
  )
  // rememberCredentialRef exposes the latest opt-in choice to an in-flight asynchronous validation response.
  // rememberCredentialRef 向进行中的异步验证响应暴露最新保存选择。
  const rememberCredentialRef = useRef(
    initialStoredCredential.rememberCredential,
  )
  // authenticationError reports a non-sensitive validation result without echoing the token.
  // authenticationError 报告不泄露令牌内容的验证结果。
  const [authenticationError, setAuthenticationError] =
    useState<AuthenticationErrorKey | null>(null)
  // isSubmitting prevents concurrent token verification requests.
  // isSubmitting 防止并发令牌验证请求。
  const [isSubmitting, setIsSubmitting] = useState(false)
  // hasAutoValidatedStoredCredential prevents duplicate validation during React development effect replay.
  // hasAutoValidatedStoredCredential 防止 React 开发环境副作用重放造成重复验证。
  const hasAutoValidatedStoredCredential = useRef(false)

  // verifyAuthToken validates one credential, persists only an accepted opt-in token, and reports exact failure classes.
  // verifyAuthToken 验证单个凭证，仅持久化已接受且用户选择保存的令牌，并报告精确失败类型。
  // normalizedToken is the non-empty trimmed credential sent to the protected management route.
  // normalizedToken 是发送到受保护管理路由的非空且已去除首尾空白的凭证。
  const verifyAuthToken = useCallback(
    async (normalizedToken: string) => {
      setAuthenticationError(null)
      setIsSubmitting(true)

      try {
        // response comes from the smallest authenticated read-only management route.
        // response 来自最小的、已认证只读管理路由。
        const response = await fetch("/vulcan/manage/protocol-profiles", {
          headers: {
            Authorization: `Bearer ${normalizedToken}`,
          },
        })
        if (!response.ok) {
          if (response.status === 401) {
            clearStoredManagementAuthToken()
            setAuthToken("")
            setAuthenticationError("login.error.invalid")
            return
          }

          setAuthenticationError("login.error.validation")
          return
        }

        if (rememberCredentialRef.current) {
          saveRememberedManagementCredential(normalizedToken)
        } else {
          clearStoredManagementCredential()
        }
        onAuthenticated(normalizedToken)
      } catch {
        setAuthenticationError("login.error.unavailable")
      } finally {
        setIsSubmitting(false)
      }
    },
    [onAuthenticated],
  )

  // autoValidateStoredCredential verifies a remembered token once when the login page opens.
  // autoValidateStoredCredential 会在登录页打开时对已保存令牌执行一次验证。
  useEffect(() => {
    if (
      hasAutoValidatedStoredCredential.current ||
      initialStoredCredential.authToken === ""
    ) {
      return
    }

    hasAutoValidatedStoredCredential.current = true
    void verifyAuthToken(initialStoredCredential.authToken)
  }, [initialStoredCredential.authToken, verifyAuthToken])

  // handleRememberCredentialChange persists only the user's choice and immediately removes any token when disabled.
  // handleRememberCredentialChange 仅持久化用户选择，并在关闭时立即删除任何已保存令牌。
  // checked is the exact boolean state emitted by the checkbox primitive.
  // checked 是勾选框基础组件发出的精确布尔状态。
  function handleRememberCredentialChange(checked: boolean) {
    rememberCredentialRef.current = checked
    setRememberCredential(checked)
    setRememberCredentialPreference(checked)
  }

  // handleSubmit verifies the management Bearer token before handing it to the in-memory application session.
  // handleSubmit 会在将管理 Bearer token 交给内存应用会话前验证该令牌。
  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    // concurrentSubmissionGuard prevents Enter-key submission from bypassing the disabled login button.
    // concurrentSubmissionGuard 防止回车提交绕过已禁用的登录按钮。
    if (isSubmitting) {
      return
    }

    // normalizedToken removes accidental outer whitespace without accepting an empty credential.
    // normalizedToken 移除意外的首尾空白，同时不接受空凭据。
    const normalizedToken = authToken.trim()
    if (normalizedToken === "") {
      setAuthenticationError("login.error.empty")
      return
    }

    await verifyAuthToken(normalizedToken)
  }

  return (
    <form
      className={cn("flex flex-col gap-6", className)}
      onSubmit={handleSubmit}
      {...props}
    >
      <FieldGroup>
        <div className="flex flex-col items-center gap-1 text-center">
          <h1 className="text-2xl font-bold">{t("login.title")}</h1>
          <p className="text-sm text-balance text-muted-foreground">
            {t("login.description")}
          </p>
        </div>
        <Field>
          <FieldLabel htmlFor="auth-token">
            {t("login.authToken")}
          </FieldLabel>
          <Input
            id="auth-token"
            name="auth-token"
            type="password"
            placeholder={t("login.placeholder")}
            autoComplete="off"
            spellCheck={false}
            autoFocus
            disabled={isSubmitting}
            className="select-text"
            value={authToken}
            onChange={(event) => setAuthToken(event.target.value)}
            aria-invalid={authenticationError !== null}
            required
          />
          {authenticationError !== null ? (
            <p className="text-sm text-destructive" role="alert">
              {t(authenticationError)}
            </p>
          ) : null}
        </Field>
        <Field>
          <div className="flex items-start gap-3">
            <Checkbox
              id="remember-credential"
              checked={rememberCredential}
              disabled={isSubmitting}
              onCheckedChange={handleRememberCredentialChange}
              aria-describedby={
                rememberCredential ? "remember-credential-warning" : undefined
              }
            />
            <div className="grid gap-1.5">
              <FieldLabel htmlFor="remember-credential">
                {t("login.rememberCredential")}
              </FieldLabel>
              {rememberCredential ? (
                <p
                  id="remember-credential-warning"
                  className="text-xs leading-relaxed text-amber-700 dark:text-amber-400"
                  role="note"
                >
                  {t("login.rememberCredentialWarning")}
                </p>
              ) : null}
            </div>
          </div>
        </Field>
        <Field>
          <Button type="submit" disabled={isSubmitting}>
            {isSubmitting ? t("login.verifying") : t("login.submit")}
          </Button>
        </Field>
      </FieldGroup>
    </form>
  )
}
