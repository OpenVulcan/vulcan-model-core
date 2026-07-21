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
  onNavigate,
  ...props
}: {
  items: {
    title: string
    url: string
    icon: React.ReactNode
  }[]
  onNavigate?: (path: string) => void
} & React.ComponentPropsWithoutRef<typeof SidebarGroup>) {
  return (
    <SidebarGroup {...props}>
      <SidebarGroupContent>
        <SidebarMenu>
          {items.map((item) => (
            <SidebarMenuItem key={item.title}>
              <SidebarMenuButton
                render={
                  <a
                    href={item.url}
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
