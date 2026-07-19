import * as React from "react"
import { Dialog as DialogPrimitive } from "@base-ui/react/dialog"

import { cn } from "@/lib/utils"

// Dialog groups every modal dialog part without rendering an extra element.
// Dialog 组合所有模态对话框部件且不渲染额外元素。
function Dialog(props: DialogPrimitive.Root.Props) {
  return <DialogPrimitive.Root data-slot="dialog" {...props} />
}

// DialogTrigger opens its owning dialog from an explicit control.
// DialogTrigger 从显式控件打开所属对话框。
function DialogTrigger(props: DialogPrimitive.Trigger.Props) {
  return <DialogPrimitive.Trigger data-slot="dialog-trigger" {...props} />
}

// DialogPortal renders modal layers outside the application stacking context.
// DialogPortal 在应用层叠上下文之外渲染模态层。
function DialogPortal(props: DialogPrimitive.Portal.Props) {
  return <DialogPrimitive.Portal data-slot="dialog-portal" {...props} />
}

// DialogOverlay blocks and visually separates the background management page.
// DialogOverlay 阻挡并在视觉上分隔后台管理页面。
function DialogOverlay({ className, ...props }: DialogPrimitive.Backdrop.Props) {
  return (
    <DialogPrimitive.Backdrop
      data-slot="dialog-overlay"
      className={cn(
        "fixed inset-0 z-50 bg-black/35 backdrop-blur-[2px] duration-150 data-open:animate-in data-open:fade-in-0 data-closed:animate-out data-closed:fade-out-0",
        className,
      )}
      {...props}
    />
  )
}

// DialogContent renders a centered, scroll-bounded modal workspace.
// DialogContent 渲染一个居中且限制滚动范围的模态工作区。
function DialogContent({ className, ...props }: DialogPrimitive.Popup.Props) {
  return (
    <DialogPortal>
      <DialogOverlay />
      <DialogPrimitive.Viewport className="fixed inset-0 z-50 grid place-items-center overflow-y-auto p-4">
        <DialogPrimitive.Popup
          data-slot="dialog-content"
          className={cn(
            "relative grid max-h-[calc(100vh-2rem)] w-full max-w-4xl gap-5 overflow-y-auto rounded-xl bg-popover p-5 text-popover-foreground shadow-2xl ring-1 ring-foreground/10 outline-none duration-150 data-open:animate-in data-open:fade-in-0 data-open:zoom-in-95 data-closed:animate-out data-closed:fade-out-0 data-closed:zoom-out-95 sm:p-6",
            className,
          )}
          {...props}
        />
      </DialogPrimitive.Viewport>
    </DialogPortal>
  )
}

// DialogHeader aligns navigation, title content, and close actions.
// DialogHeader 对齐导航、标题内容和关闭操作。
function DialogHeader({ className, ...props }: React.ComponentProps<"div">) {
  return <div data-slot="dialog-header" className={cn("flex items-start gap-3", className)} {...props} />
}

// DialogTitle supplies the accessible modal heading.
// DialogTitle 提供可访问的模态标题。
function DialogTitle({ className, ...props }: DialogPrimitive.Title.Props) {
  return (
    <DialogPrimitive.Title data-slot="dialog-title" className={cn("text-lg font-semibold", className)} {...props} />
  )
}

// DialogDescription supplies optional accessible supporting text.
// DialogDescription 提供可选的可访问辅助文本。
function DialogDescription({ className, ...props }: DialogPrimitive.Description.Props) {
  return (
    <DialogPrimitive.Description
      data-slot="dialog-description"
      className={cn("text-sm text-muted-foreground", className)}
      {...props}
    />
  )
}

// DialogClose closes the dialog through its controlled root lifecycle.
// DialogClose 通过受控根节点生命周期关闭对话框。
function DialogClose(props: DialogPrimitive.Close.Props) {
  return <DialogPrimitive.Close data-slot="dialog-close" {...props} />
}

export {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogOverlay,
  DialogPortal,
  DialogTitle,
  DialogTrigger,
}
