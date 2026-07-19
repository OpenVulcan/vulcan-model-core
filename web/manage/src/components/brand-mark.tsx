import * as React from "react"

import vulcanCodeLogo from "@/assets/vulcan-code-logo.svg"
import { cn } from "@/lib/utils"

// BrandMarkProps defines the compact sidebar and enlarged login-page presentations of the same logo.
// BrandMarkProps 定义同一 Logo 的紧凑侧栏与放大登录页展示方式。
interface BrandMarkProps extends React.ComponentProps<"div"> {
  // size selects the context-specific logo scale without changing the shared transparent SVG asset.
  // size 选择上下文对应的 Logo 尺寸，而不改变共享透明 SVG 资源。
  size?: "compact" | "login"
}

// BrandMark renders the transparent shared VulcanCode icon with the VulcanModelRouter product name.
// BrandMark 使用透明共享 VulcanCode 图标渲染 VulcanModelRouter 产品名称。
export function BrandMark({
  className,
  size = "compact",
  ...props
}: BrandMarkProps) {
  return (
    <div
      className={cn(
        "flex items-center",
        size === "login" ? "gap-3" : "gap-2",
        className,
      )}
      {...props}
    >
      <img
        src={vulcanCodeLogo}
        alt="VulcanCode"
        className={cn("shrink-0", size === "login" ? "size-12" : "size-7")}
      />
      <span
        className={cn(
          "font-semibold tracking-tight",
          size === "login" ? "text-2xl" : "text-base",
        )}
      >
        VulcanModelRouter
      </span>
    </div>
  )
}
