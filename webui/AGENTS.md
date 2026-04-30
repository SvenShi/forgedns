# WebUI Guidelines

## Structure & Commands

- `webui/` contains the Next.js-based management console for ForgeDNS. Treat it as a separate frontend workspace that mirrors the plugin model exposed by the Rust server.
- `app/` uses the Next App Router. The `(console)` route group owns the console shell, dashboard, plugin center, settings page, and full-screen config editor mode.
- `components/` contains feature components, while `components/ui/` contains shadcn/Radix-style primitives. Prefer composing existing primitives before adding new low-level UI.
- `components/plugins/` contains plugin-center rendering. Generic card/detail templates live there, and per-plugin overrides live under `components/plugins/kinds/`.
- `lib/plugin-definitions.ts` is the source of truth for WebUI plugin kinds, labels, icons, descriptions, and config schemas.
- `lib/store.ts` contains the current client state model with Zustand. Backend API wiring should replace mock actions behind this store shape where possible instead of scattering fetch logic through views.
- `pnpm dev` runs the WebUI development server with Turbopack.
- `pnpm build` builds the WebUI for production.
- `pnpm typecheck` runs TypeScript validation.
- `pnpm lint` runs ESLint for the WebUI.
- `pnpm format` formats TypeScript and TSX with Prettier and Tailwind class ordering.

## Coding Style

- WebUI code is TypeScript + React. Use `PascalCase` for components, `camelCase` for props/functions, and colocate feature-only helpers near the feature.
- Prefer named exports for shared WebUI components and helpers.
- Use the `@/` path alias for WebUI imports instead of deep relative paths.
- Keep WebUI files client/server explicit: add `"use client"` only for components that need hooks, browser state, event handlers, Zustand, or theme APIs.
- Keep user-facing WebUI copy in Chinese unless the surrounding UI is already intentionally English, while plugin type names such as `Server`, `Executor`, `Matcher`, and `Provider` may remain as canonical labels.
- Use `lucide-react` icons for toolbar actions, navigation, and plugin visuals when an icon exists.

## Architecture & Extension Principles

- Preserve the console shell flow: `app/(console)/layout.tsx -> AppSidebar/AppHeader -> page content -> PluginDetailSheet`, with `ConfigEditorView` taking over the main area when `editorMode` is enabled.
- Keep global UI state in `useAppStore` until backend integration introduces a clearer API boundary. Avoid duplicating selected plugin, drawer state, editor mode, or restart/save flags in page-local stores.
- Treat `PluginInstance` in `lib/types.ts` as the UI model for live plugin instances. Keep its `type` aligned with ForgeDNS plugin categories: `server`, `executor`, `matcher`, and `provider`.
- Add new plugin kinds to `pluginKindDefinitions` first. The catalog, create dialog, generic cards, and detail drawer resolve names, descriptions, icons, and config forms from those definitions.
- Use `ConfigField` schemas for plugin configuration instead of hand-built one-off forms whenever possible. This keeps create/edit behavior consistent and preserves YAML/plugin concepts like references, arrays, objects, records, durations, and JSON fields.
- Use `referenceTypes`, `referencePrefix`, and `allowInvert` for fields that point to other plugins or matcher expressions. Do not encode `$tag` and `!$tag` handling in individual plugin components unless the schema editor cannot represent the shape.
- Put optional custom plugin visuals in `components/plugins/kinds/<kind>.tsx` and register them in `components/plugins/registry.ts`. If a custom component does not add meaningful clarity, rely on `PluginCardTemplate` and `PluginDetailTemplate`.
- Keep plugin cards focused on scanability: name, category, kind, status/primary metric, and compact operational controls. Push detailed configuration, charts, and destructive actions into the detail sheet.
- Keep `CreatePluginDialog` catalog-driven. Search should cover kind, display name, description, type label, and config fields so operators can find plugins by the concept they remember.
- When replacing mock data with real APIs, keep network calls outside low-level UI primitives and preserve optimistic UI only where the backend operation is reversible or clearly reported.

## Design Principles

- The WebUI is an operational DNS console, not a marketing site. Prioritize dense, calm, scan-friendly screens over decorative layouts.
- Preserve the current visual language: dark mode by default, light mode supported, OKLCH design tokens in `app/globals.css`, teal/green primary accents, restrained borders, muted surfaces, and compact spacing.
- Use shadcn/Radix primitives from `components/ui/` for buttons, dialogs, sheets, tabs, tables, inputs, tooltips, badges, sidebars, and forms. Extend primitives only when repeated product behavior needs it.
- Prefer full-width work surfaces and simple sections. Use cards for individual repeated items, metrics, dialogs, and framed editor/helper panels; avoid nesting cards inside cards.
- Keep navigation persistent and predictable: sidebar for main sections, header for breadcrumbs and global actions, sheets/dialogs for focused secondary workflows.
- Use icon buttons with tooltips for compact global actions such as theme switching, restart, view mode, and editor mode. Include `sr-only` text for icon-only buttons.
- Keep typography compact: page headings around `text-lg`, operational labels at `text-sm`/`text-xs`, plugin tags and config keys in mono where useful. Do not use oversized hero typography inside the console.
- Ensure responsive behavior for desktop and narrow screens with stable grids (`sm`, `lg`, `xl`) and fixed-width side panels only when there is enough viewport room. Avoid layouts where labels, buttons, or badges can overlap.
- Use semantic status color sparingly: primary for active/healthy emphasis, destructive for dangerous actions, yellow/amber only for unsaved or warning states, muted foreground for secondary metadata.
- Do not add gradient blobs, decorative illustrations, or broad one-color themes. The interface should feel like a precise control surface for ForgeDNS.

## Testing & Documentation

- For WebUI behavior changes, run at least `pnpm typecheck`. Also run `pnpm lint` when changing shared components, route layouts, or plugin form logic.
- For visual WebUI changes, verify the affected route in both light and dark themes, and check narrow and desktop widths for overflow, clipped labels, and broken grid/card layouts.
- If a Rust plugin is added, renamed, or its config shape changes, update `lib/plugin-definitions.ts` and any relevant WebUI plugin kind component in the same change so the console stays aligned with runtime behavior.
- If WebUI architecture, styling tokens, plugin schema conventions, or console workflows change, update this `AGENTS.md`.
