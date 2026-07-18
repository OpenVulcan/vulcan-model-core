import { useState } from "react"
import { Navigate, Route, Routes, useLocation, useNavigate } from "react-router-dom"

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
  // location is the browser-router-owned source of truth for refresh and history navigation.
  // location 是浏览器路由拥有的刷新与历史导航事实来源。
  const location = useLocation()
  // navigate changes authenticated routes without manually duplicating browser history state.
  // navigate 在不手工复制浏览器历史状态的情况下切换已认证路由。
  const navigate = useNavigate()

  // handleAuthenticated records the verified token in memory and moves the application to the dashboard route.
  // handleAuthenticated 在内存中记录已验证令牌，并将应用切换到仪表盘路由。
  function handleAuthenticated(authToken: string) {
    setManagementAuthToken(authToken)
    navigate("/", { replace: true })
  }

  // handleLogout removes both active and explicitly remembered credentials before returning to login.
  // handleLogout 会在返回登录页前同时删除当前凭证和用户明确保存的凭证。
  function handleLogout() {
    clearStoredManagementCredential()
    setManagementAuthToken("")
    navigate("/login", { replace: true })
  }

  // handleNavigate changes authenticated page state without broadening credential persistence.
  // handleNavigate 在不扩大凭证持久化范围的情况下切换已认证页面状态。
  function handleNavigate(path: string) {
    navigate(path)
  }
  const isAuthenticated = managementAuthToken !== ""

  return (
    <TooltipProvider>
      <Routes>
        <Route
          path="/login"
          element={isAuthenticated ? <Navigate to="/" replace /> : <LoginPage onAuthenticated={handleAuthenticated} />}
        />
        <Route
          path="/*"
          element={isAuthenticated ? (
            <DashboardPage
              currentPath={location.pathname}
              managementAuthToken={managementAuthToken}
              onNavigate={handleNavigate}
              onLogout={handleLogout}
            />
          ) : <Navigate to="/login" replace />}
        />
      </Routes>
    </TooltipProvider>
  )
}
