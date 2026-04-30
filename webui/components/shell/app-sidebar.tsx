"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarGroup,
  SidebarGroupLabel,
  SidebarGroupContent,
} from "@/components/ui/sidebar";
import {
  LayoutDashboard,
  Puzzle,
  Settings,
  Server,
  BookOpen,
  GitBranch,
} from "lucide-react";

const navItems = [
  {
    title: "仪表盘",
    href: "/",
    icon: LayoutDashboard,
  },
  {
    title: "插件中心",
    href: "/plugins",
    icon: Puzzle,
  },
  {
    title: "系统配置",
    href: "/settings",
    icon: Settings,
  },
];

export function AppSidebar() {
  const pathname = usePathname();

  return (
    <Sidebar variant="inset">
      <SidebarHeader className="h-14 justify-center border-b border-sidebar-border px-3 py-1">
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton asChild className="h-9 rounded-lg px-2">
              <Link href="/">
                <div className="flex aspect-square size-8 items-center justify-center rounded-lg bg-primary text-primary-foreground">
                  <Server className="size-4" />
                </div>
                <div className="flex flex-col gap-0.5 leading-none">
                  <span className="font-semibold">ForgeDNS</span>
                  <span className="text-xs text-muted-foreground">控制台</span>
                </div>
              </Link>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>

      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupLabel>导航</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {navItems.map((item) => (
                <SidebarMenuItem key={item.href}>
                  <SidebarMenuButton asChild isActive={pathname === item.href}>
                    <Link href={item.href}>
                      <item.icon className="size-4" />
                      <span>{item.title}</span>
                    </Link>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>

      <SidebarFooter className="border-t border-sidebar-border">
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton asChild>
              <a
                href="https://forgedns.cn"
                target="_blank"
                rel="noopener noreferrer"
                className="text-muted-foreground"
              >
                <BookOpen className="size-4" />
                <span>文档站</span>
              </a>
            </SidebarMenuButton>
          </SidebarMenuItem>
          <SidebarMenuItem>
            <SidebarMenuButton asChild>
              <a
                href="https://github.com/SvenShi/forgedns"
                target="_blank"
                rel="noopener noreferrer"
                className="text-muted-foreground"
              >
                <GitBranch className="size-4" />
                <span>GitHub</span>
              </a>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarFooter>
    </Sidebar>
  );
}
