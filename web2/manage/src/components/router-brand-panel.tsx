import vulcanCodeLogo from "@/assets/vulcan-code-logo.svg"
import { useI18n } from "@/i18n"

// RouterBrandPanel composes the source VulcanCode SVG into the login-page brand backdrop.
// RouterBrandPanel 将源 VulcanCode SVG 组合为登录页品牌背景图。
export function RouterBrandPanel() {
  const { t } = useI18n()
  return (
    <div className="relative isolate h-full overflow-hidden bg-[#061735] text-white">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_20%_20%,rgba(18,169,254,0.42),transparent_38%),radial-gradient(circle_at_80%_80%,rgba(1,86,247,0.5),transparent_44%)]" />
      <div className="absolute inset-0 bg-[linear-gradient(135deg,rgba(255,255,255,0.08)_1px,transparent_1px)] bg-[size:28px_28px] opacity-30" />
      <img
        src={vulcanCodeLogo}
        alt=""
        aria-hidden="true"
        className="absolute -right-28 -top-24 size-[42rem] rotate-[-14deg] opacity-25"
      />
      <div className="absolute inset-12 rounded-[2rem] border border-white/15" />
      <div className="relative flex h-full flex-col justify-between p-12 xl:p-16">
        <div className="flex items-center gap-4 text-base font-medium tracking-[0.2em] text-cyan-100 uppercase">
          <img
            src={vulcanCodeLogo}
            alt="VulcanCode"
            className="size-16 shrink-0"
          />
          {t("brand.platform")}
        </div>
        <div className="max-w-xl">
          <p className="mb-5 text-sm font-semibold tracking-[0.28em] text-cyan-200 uppercase">
            {t("brand.controlPlane")}
          </p>
          <h2 className="text-5xl font-semibold tracking-[-0.045em] text-balance xl:text-6xl">
            VulcanModelRouter
          </h2>
          <p className="mt-6 max-w-md text-lg leading-8 text-slate-200">
            {t("brand.description")}
          </p>
        </div>
      </div>
    </div>
  )
}
