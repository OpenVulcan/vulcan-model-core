import { LanguagesIcon } from "lucide-react"

import { Button } from "@/components/ui/button"
import { useI18n } from "@/i18n"
import { cn } from "@/lib/utils"

// LanguageToggleProps defines optional visual placement styling for a page-level manual language control.
// LanguageToggleProps 定义页面级手动语言控件的可选视觉定位样式。
interface LanguageToggleProps {
  // className augments the shared control styling for login or dashboard placement.
  // className 为登录页或仪表盘位置补充共享控件样式。
  className?: string
}

// LanguageToggle switches between English and Chinese while showing the available target language.
// LanguageToggle 在英文和中文之间切换，同时展示可切换到的目标语言。
export function LanguageToggle({ className }: LanguageToggleProps) {
  const { locale, t, toggleLocale } = useI18n()
  // targetLanguageLabel communicates the one alternate language available through this two-language toggle.
  // targetLanguageLabel 表示此双语切换控件可用的唯一另一种语言。
  const targetLanguageLabel = locale === "zh" ? "EN" : "中文"
  // toggleLabel gives the icon-only portion of the control an accessible action description.
  // toggleLabel 为控件的纯图标部分提供可访问的操作描述。
  const toggleLabel =
    locale === "zh" ? t("language.switchToEnglish") : t("language.switchToChinese")

  return (
    <Button
      type="button"
      variant="outline"
      size="sm"
      className={cn("gap-2", className)}
      onClick={toggleLocale}
      aria-label={toggleLabel}
      title={toggleLabel}
    >
      <LanguagesIcon className="size-4" aria-hidden="true" />
      <span>{targetLanguageLabel}</span>
    </Button>
  )
}
