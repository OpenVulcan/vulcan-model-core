import { useEffect, useState } from "react"

import { TooltipProvider } from "@/components/ui/tooltip"
import { clearStoredManagementCredential } from "@/lib/management-credential-storage"
import { DashboardPage } from "@/pages/dashboard-page"
import { LoginPage } from "@/pages/login-page"

// App holds the active validated token in memory while the login form separately owns explicit credential persistence.
// App 在内存中保存当前已验证令牌，而登录表单单独管理用户明确选择的凭证持久化。
export function App() {
  // managementAuthToken is the active in-memory session credential accepted by the management API.
  // managementAuthToken 是管理 API 已接受的当前内存会话凭证。
  const [managementAuthToken, setManagementAuthToken] = useState("")

  // synchronizeUnauthenticatedRoute ensures a fresh page opens the dedicated login route before authentication.
  // synchronizeUnauthenticatedRoute 确保新页面会在认证前打开专用登录路由。
  useEffect(() => {
    if (
      managementAuthToken === "" &&
      window.location.pathname !== "/login"
    ) {
      window.history.replaceState(null, "", "/login")
    }
  }, [managementAuthToken])

  // handleAuthenticated records the verified token in memory and moves the application to the dashboard route.
  // handleAuthenticated 在内存中记录已验证令牌，并将应用切换到仪表盘路由。
  function handleAuthenticated(authToken: string) {
    setManagementAuthToken(authToken)
    window.history.replaceState(null, "", "/")
  }

  // handleLogout removes both active and explicitly remembered credentials before returning to login.
  // handleLogout 会在返回登录页前同时删除当前凭证和用户明确保存的凭证。
  function handleLogout() {
    clearStoredManagementCredential()
    setManagementAuthToken("")
    window.history.replaceState(null, "", "/login")
  }

  // currentPath is read during render because route changes are initiated by the authenticated callbacks above.
  // currentPath 会在渲染时读取，因为路由变更由上方认证回调发起。
  const currentPath = window.location.pathname
  const isAuthenticated = managementAuthToken !== ""

  return (
    <TooltipProvider>
      {isAuthenticated && currentPath !== "/login" ? (
        <DashboardPage onLogout={handleLogout} />
      ) : (
        <LoginPage onAuthenticated={handleAuthenticated} />
      )}
    </TooltipProvider>
  )
}
