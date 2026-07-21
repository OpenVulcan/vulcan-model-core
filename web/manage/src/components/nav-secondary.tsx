"use client"

import * as React from "react"

import {
  SidebarGroup,
  SidebarGroupContent,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/components/ui/sidebar"

export function NavSecondary({
  items,
  currentPath,
  onNavigate,
  ...props
}: {
  items: {
    title: string
    url: string
    icon: React.ReactNode
  }[]
  // currentPath identifies the secondary destination selected by the route shell.
  // currentPath 标识路由外壳选择的次级导航目标。
  currentPath: string
  onNavigate?: (path: string) => void
} & React.ComponentPropsWithoutRef<typeof SidebarGroup>) {
  return (
    <SidebarGroup {...props}>
      <SidebarGroupContent>
        <SidebarMenu>
          {items.map((item) => (
            <SidebarMenuItem key={item.title}>
              <SidebarMenuButton
                isActive={currentPath === item.url}
                className="data-active:bg-primary data-active:text-primary-foreground data-active:font-semibold data-active:hover:bg-primary data-active:hover:text-primary-foreground"
                render={
                  <a
                    href={item.url}
                    aria-current={currentPath === item.url ? "page" : undefined}
                    onClick={(event) => {
                      if (onNavigate && item.url.startsWith("/")) {
                        event.preventDefault()
                        onNavigate(item.url)
                      }
                    }}
                  />
                }
              >
                {item.icon}
                <span>{item.title}</span>
              </SidebarMenuButton>
            </SidebarMenuItem>
          ))}
        </SidebarMenu>
      </SidebarGroupContent>
    </SidebarGroup>
  )
}
