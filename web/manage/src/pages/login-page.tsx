import { BrandMark } from "@/components/brand-mark"
import { LanguageToggle } from "@/components/language-toggle"
import { LoginForm } from "@/components/login-form"
import { RouterBrandPanel } from "@/components/router-brand-panel"

// LoginPageProps defines the server-validated token handoff to the application route shell.
// LoginPageProps 定义服务端验证通过后向应用路由外壳交接令牌的契约。
interface LoginPageProps {
  // onAuthenticated receives a management token after protected API validation succeeds.
  // onAuthenticated 在受保护 API 验证成功后接收管理令牌。
  onAuthenticated: (authToken: string) => void
}

// LoginPage renders the shadcn login-02 two-column composition with Vulcan branding.
// LoginPage 使用 Vulcan 品牌渲染 shadcn login-02 双栏布局。
export function LoginPage({ onAuthenticated }: LoginPageProps) {
  return (
    <div className="relative grid min-h-svh select-none lg:grid-cols-2">
      <div className="absolute top-6 right-6 z-10 md:top-10 md:right-10">
        <LanguageToggle className="bg-background/90 shadow-sm backdrop-blur-sm" />
      </div>
      <div className="flex flex-col gap-4 p-6 md:p-10">
        <div className="flex justify-center md:justify-start">
          <BrandMark size="login" />
        </div>
        <div className="flex flex-1 items-center justify-center">
          <div className="w-full max-w-xs">
            <LoginForm onAuthenticated={onAuthenticated} />
          </div>
        </div>
      </div>
      <div className="relative hidden bg-muted lg:block">
        <RouterBrandPanel />
      </div>
    </div>
  )
}
