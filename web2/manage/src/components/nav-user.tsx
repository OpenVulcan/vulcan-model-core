import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog"
import { Avatar } from "@/components/ui/avatar"
import {
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/components/ui/sidebar"
import vulcanCodeLogo from "@/assets/vulcan-code-logo.svg"
import { useI18n } from "@/i18n"
import { LogOutIcon } from "lucide-react"

// NavUserProps defines the visible administrator identity and the confirmed logout action.
// NavUserProps 定义可见的管理员身份与确认后的退出登录动作。
interface NavUserProps {
  // user supplies the administrator identity displayed in the sidebar footer.
  // user 提供侧栏底部展示的管理员身份。
  user: {
    name: string
    email: string
  }
  // onLogout executes only after the administrator confirms the alert dialog.
  // onLogout 仅在管理员确认提示框后执行。
  onLogout: () => void
}

// NavUser renders a direct logout trigger instead of a user-action dropdown menu.
// NavUser 渲染直接退出登录入口，而非用户操作下拉菜单。
export function NavUser({ user, onLogout }: NavUserProps) {
  const { t } = useI18n()
  return (
    <SidebarMenu>
      <SidebarMenuItem>
        <AlertDialog>
          <AlertDialogTrigger
            render={
              <SidebarMenuButton
                aria-label={t("logout.label")}
                size="lg"
                className="aria-expanded:bg-muted"
                tooltip={t("logout.label")}
              >
                <Avatar className="size-8 rounded-lg">
                  <img
                    src={vulcanCodeLogo}
                    alt="VulcanCode"
                    className="size-full object-contain"
                  />
                </Avatar>
                <div className="grid flex-1 text-left text-sm leading-tight">
                  <span className="truncate font-medium">{user.name}</span>
                  <span className="truncate text-xs text-foreground/70">
                    {user.email}
                  </span>
                </div>
                <LogOutIcon className="ml-auto size-4" aria-hidden="true" />
              </SidebarMenuButton>
            }
          />
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>
                {t("logout.title")}
              </AlertDialogTitle>
              <AlertDialogDescription>
                {t("logout.description")}
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel>{t("logout.cancel")}</AlertDialogCancel>
              <AlertDialogAction onClick={onLogout}>
                {t("logout.confirm")}
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      </SidebarMenuItem>
    </SidebarMenu>
  )
}
