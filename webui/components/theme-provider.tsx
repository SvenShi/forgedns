"use client";

import * as React from "react";
import { ThemeProvider as NextThemesProvider, useTheme } from "next-themes";

function ThemeProvider({
  children,
  ...props
}: React.ComponentProps<typeof NextThemesProvider>) {
  return (
    <NextThemesProvider
      attribute="class"
      defaultTheme="system"
      enableSystem
      disableTransitionOnChange
      {...props}
    >
      <ThemeFavicon />
      {children}
    </NextThemesProvider>
  );
}

function ThemeFavicon() {
  const { resolvedTheme } = useTheme();

  React.useEffect(() => {
    if (!resolvedTheme) {
      return;
    }

    const href =
      resolvedTheme === "dark" ? "/logo-dark.png" : "/logo-light.png";
    let icon = document.querySelector<HTMLLinkElement>(
      "link[data-oxidns-theme-icon]",
    );

    if (!icon) {
      icon = document.createElement("link");
      icon.rel = "icon";
      icon.dataset.oxidnsThemeIcon = "true";
      document.head.appendChild(icon);
    }

    icon.type = "image/png";
    icon.media = "";
    icon.href = href;
  }, [resolvedTheme]);

  return null;
}

export { ThemeProvider };
