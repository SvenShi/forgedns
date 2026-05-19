import type { Monaco } from "@monaco-editor/react";
import {
  getPluginKindDefinition,
  pluginKindDefinitions,
  type ConfigField,
  type ConfigFieldChild,
} from "@/lib/plugin-definitions";
import type { PluginInstance, PluginType } from "@/lib/types";
import { PLUGIN_TYPE_LABELS } from "@/lib/types";

export type OxiDnsYamlEditorVariant =
  | "config"
  | "plugin-args"
  | "sequence"
  | "generic";

export interface OxiDnsYamlEditorContext {
  variant: OxiDnsYamlEditorVariant;
  plugins?: PluginInstance[];
  pluginKind?: string;
  fields?: ConfigField[];
  currentPluginName?: string;
}

export interface OxiDnsYamlDiagnostic {
  message: string;
  severity?: "error" | "warning" | "info";
  line?: number;
  column?: number;
  end_line?: number;
  end_column?: number;
}

type MonacoApi = Monaco;
type CompletionProvider = Parameters<
  MonacoApi["languages"]["registerCompletionItemProvider"]
>[1];
type CompletionProviderFn = NonNullable<
  CompletionProvider["provideCompletionItems"]
>;
type HoverProvider = Parameters<MonacoApi["languages"]["registerHoverProvider"]>[1];
type HoverProviderFn = NonNullable<HoverProvider["provideHover"]>;
type MonacoModel = Parameters<CompletionProviderFn>[0];
type MonacoPosition = Parameters<CompletionProviderFn>[1];
type MonacoRange = {
  startLineNumber: number;
  startColumn: number;
  endLineNumber: number;
  endColumn: number;
};
type CompletionItem = Awaited<ReturnType<CompletionProviderFn>> extends {
  suggestions: infer Items;
}
  ? Items extends Array<infer Item>
    ? Item
    : never
  : never;

const contextByModel = new Map<string, OxiDnsYamlEditorContext>();
let registered = false;

const topLevelKeys = ["include", "runtime", "api", "log", "plugins", "init_order"];
const sequenceControls = ["accept", "return", "reject", "mark", "jump", "goto"];
const logLevels = ["off", "trace", "debug", "info", "warn", "error"];

// Sub-keys for top-level config sections derived from the Rust config structs.
function configSubKeysForPath(path: string[]): string[] | null {
  const [p0, p1, p2] = path;
  if (p0 === "log") return p1 ? null : ["level", "file", "rotation"];
  if (p0 === "runtime") return p1 ? null : ["worker_threads"];
  if (p0 === "api") {
    if (!p1) return ["http"];
    if (p1 === "http") {
      if (!p2) return ["listen", "ssl", "auth", "cors", "webui"];
      if (p2 === "ssl") return ["cert", "key", "client_ca", "require_client_cert"];
      if (p2 === "auth") return ["type", "username", "password"];
      if (p2 === "cors") return ["allowed_origins"];
      if (p2 === "webui") return ["root", "index"];
    }
  }
  return null;
}

export function registerOxiDnsYamlLanguage(monaco: MonacoApi) {
  // defineTheme is idempotent: always run so that editors created before
  // onMount fires (e.g. via the theme prop on first render) get the correct
  // custom theme rather than falling back to vs-dark / vs.
  // Dark theme — Catppuccin Macchiato palette, teal mapped to the OxiDNS brand.
  //
  // Hierarchy by visual weight:
  //   key (teal, brightest) > string/value (green) > number (yellow) >
  //   keyword/bool (mauve) > default text > comment (muted, recedes) >
  //   delimiter (surface, near-invisible)
  monaco.editor.defineTheme("oxidns-yaml-dark", {
    base: "vs-dark",
    inherit: true,
    rules: [
      { token: "", foreground: "cad3f5" },                           // Text
      { token: "comment", foreground: "5b6078", fontStyle: "italic" }, // Overlay0 — recedes
      { token: "key", foreground: "8bd5ca" },                        // Teal  — structure
      { token: "string", foreground: "a6da95" },                     // Green — scalar values
      { token: "string.value", foreground: "a6da95" },               // Green — quoted values
      { token: "number", foreground: "eed49f" },                     // Yellow — numerics
      { token: "keyword", foreground: "c6a0f6" },                    // Mauve  — true/false/null
      { token: "delimiter", foreground: "363a4f" },                  // Surface0 — near-invisible
      { token: "tag", foreground: "f5a97f" },                        // Peach  — YAML !! tags
      { token: "type", foreground: "91d7e3" },                       // Sky    — type annotations
    ],
    colors: {
      "editor.background": "#00000000",
      "editor.foreground": "#cad3f5",
      "editorGutter.background": "#00000000",
      "editorLineNumber.foreground": "#494d64",
      "editorLineNumber.activeForeground": "#b8c0e0",
      "editorIndentGuide.background1": "#363a4f",
      "editorIndentGuide.activeBackground1": "#494d64",
      "editorCursor.foreground": "#8bd5ca",
      "editor.selectionBackground": "#8bd5ca28",
      "editorSuggestWidget.background": "#1e2030",
      "editorSuggestWidget.border": "#363a4f",
      "editorSuggestWidget.selectedBackground": "#2a2d4a",
      "editorStickyScroll.background": "#1e2030",
      "editorStickyScroll.border": "#363a4f",
      "editorStickyScrollHover.background": "#181926",
      "editorStickyScrollGutter.background": "#1e2030",
    },
  });

  // Light theme — Catppuccin Latte palette, teal mapped to the OxiDNS brand.
  monaco.editor.defineTheme("oxidns-yaml-light", {
    base: "vs",
    inherit: true,
    rules: [
      { token: "", foreground: "4c4f69" },                           // Text
      { token: "comment", foreground: "9ca0b0", fontStyle: "italic" }, // Overlay0 — recedes
      { token: "key", foreground: "179299" },                        // Teal  — structure
      { token: "string", foreground: "40a02b" },                     // Green — scalar values
      { token: "string.value", foreground: "40a02b" },               // Green — quoted values
      { token: "number", foreground: "df8e1d" },                     // Yellow — numerics
      { token: "keyword", foreground: "8839ef" },                    // Mauve  — true/false/null
      { token: "delimiter", foreground: "ccd0da" },                  // Surface0 — near-invisible
      { token: "tag", foreground: "fe640b" },                        // Peach  — YAML !! tags
      { token: "type", foreground: "04a5e5" },                       // Sky    — type annotations
    ],
    colors: {
      "editor.background": "#00000000",
      "editor.foreground": "#4c4f69",
      "editorGutter.background": "#00000000",
      "editorLineNumber.foreground": "#9ca0b0",
      "editorLineNumber.activeForeground": "#6c6f85",
      "editorIndentGuide.background1": "#ccd0da",
      "editorIndentGuide.activeBackground1": "#bcc0cc",
      "editorCursor.foreground": "#179299",
      "editor.selectionBackground": "#17929920",
      "editorSuggestWidget.background": "#eff1f5",
      "editorSuggestWidget.border": "#ccd0da",
      "editorSuggestWidget.selectedBackground": "#d6f0ee",
      "editorStickyScroll.background": "#e6e9ef",
      "editorStickyScroll.border": "#ccd0da",
      "editorStickyScrollHover.background": "#dce0e8",
      "editorStickyScrollGutter.background": "#e6e9ef",
    },
  });

  // Language providers only need to be registered once per Monaco instance.
  if (registered) return;
  registered = true;

  monaco.languages.registerCompletionItemProvider("yaml", {
    triggerCharacters: ["$", "!", ":", " ", "-", '"', "'"],
    provideCompletionItems(model: MonacoModel, position: MonacoPosition) {
      const context = contextByModel.get(model.uri.toString()) ?? {
        variant: "generic",
      };
      return {
        suggestions: buildCompletionItems(monaco, model, position, context),
      };
    },
  });

  monaco.languages.registerHoverProvider("yaml", {
    provideHover(model: MonacoModel, position: MonacoPosition) {
      const context = contextByModel.get(model.uri.toString());
      if (!context) return null;
      return buildHover(monaco, model, position, context);
    },
  });
}

export function setOxiDnsYamlModelContext(
  model: MonacoModel,
  context: OxiDnsYamlEditorContext,
) {
  contextByModel.set(model.uri.toString(), context);
}

export function clearOxiDnsYamlModelContext(model: MonacoModel) {
  contextByModel.delete(model.uri.toString());
}

export function updateOxiDnsYamlMarkers(
  monaco: MonacoApi,
  model: MonacoModel,
  context: OxiDnsYamlEditorContext,
  backendDiagnostics: OxiDnsYamlDiagnostic[] = [],
) {
  const markers = [
    ...buildLocalDiagnosticMarkers(monaco, model, context),
    ...backendDiagnostics.map((diagnostic) =>
      markerFromBackendDiagnostic(monaco, model, diagnostic),
    ),
  ];
  monaco.editor.setModelMarkers(model, "oxidns-yaml", markers);
}

function buildCompletionItems(
  monaco: MonacoApi,
  model: MonacoModel,
  position: MonacoPosition,
  context: OxiDnsYamlEditorContext,
): CompletionItem[] {
  const line = model.getLineContent(position.lineNumber);
  const prefix = line.slice(0, position.column - 1);
  const path = getYamlPath(model, position.lineNumber);
  const range = getReplacementRange(monaco, position, prefix);
  const valueKey = getValueKey(prefix);
  const suggestions: CompletionItem[] = [];

  if (isReferencePrefix(prefix)) {
    suggestions.push(
      ...pluginReferenceSuggestions(
        monaco,
        context,
        range,
        expectedReferenceTypes(context, path, valueKey),
        prefix.trimEnd().endsWith("!$"),
      ),
    );
  }

  if (isKeyPosition(prefix)) {
    suggestions.push(...keySuggestions(monaco, context, range, path));
  }

  if (valueKey === "type") {
    suggestions.push(...pluginKindSuggestions(monaco, range));
  }

  if (valueKey === "level" && context.variant === "config" && path.includes("log")) {
    suggestions.push(...logLevelSuggestions(monaco, range));
  }

  const field = findFieldForKey(context.fields, valueKey);
  if (field) {
    suggestions.push(...fieldValueSuggestions(monaco, context, field, range));
  }

  if (shouldSuggestSequenceExpressions(context, path, valueKey)) {
    const types = expectedReferenceTypes(context, path, valueKey);
    suggestions.push(...quickSetupSuggestions(monaco, range, types));
    suggestions.push(...pluginReferenceSuggestions(monaco, context, range, types));
    if (types?.includes("executor")) {
      suggestions.push(...controlSuggestions(monaco, range));
      // jump/goto <tag>: when the user has already typed "jump " or "goto "
      // replace from the keyword start so the full expression is inserted.
      const jumpCtx = detectJumpGotoExec(prefix);
      if (jumpCtx) {
        const jumpRange = new monaco.Range(
          position.lineNumber,
          position.column - jumpCtx.prefixLength,
          position.lineNumber,
          position.column,
        );
        suggestions.push(...jumpGotoTagSuggestions(monaco, context, jumpRange, jumpCtx.keyword));
      }
    }
  }

  return dedupeSuggestions(suggestions);
}

function buildHover(
  monaco: MonacoApi,
  model: MonacoModel,
  position: MonacoPosition,
  context: OxiDnsYamlEditorContext,
): ReturnType<HoverProviderFn> {
  const token = getTokenAtPosition(model, position);
  if (!token) return null;
  const clean = token.replace(/^!?\$/, "");
  const plugin = context.plugins?.find((entry) => entry.name === clean);
  if (plugin) {
    return {
      range: new monaco.Range(
        position.lineNumber,
        tokenStartColumn(model, position, token),
        position.lineNumber,
        tokenStartColumn(model, position, token) + token.length,
      ),
      contents: [
        { value: `**${plugin.name}**` },
        {
          value: `${PLUGIN_TYPE_LABELS[plugin.type]} / \`${plugin.pluginKind}\``,
        },
      ],
    };
  }

  const definition = getPluginKindDefinition(clean);
  if (definition) {
    return {
      contents: [
        { value: `**${definition.kind}**` },
        {
          value: `${PLUGIN_TYPE_LABELS[definition.type]} · ${definition.description}`,
        },
      ],
    };
  }

  return null;
}

function buildLocalDiagnosticMarkers(
  monaco: MonacoApi,
  model: MonacoModel,
  context: OxiDnsYamlEditorContext,
) {
  const markers: Parameters<MonacoApi["editor"]["setModelMarkers"]>[2] = [];
  const pluginTags = new Set((context.plugins ?? []).map((plugin) => plugin.name));
  const knownPluginKinds = new Set(pluginKindDefinitions.map((definition) => definition.kind));

  for (let lineNumber = 1; lineNumber <= model.getLineCount(); lineNumber += 1) {
    const line = model.getLineContent(lineNumber);
    const commentStart = line.indexOf("#");
    const checkText = commentStart >= 0 ? line.slice(0, commentStart) : line;

    for (const match of checkText.matchAll(/!?\$([A-Za-z0-9_.-]+)/g)) {
      const tag = match[1];
      if (!tag || pluginTags.has(tag)) continue;
      const startColumn = (match.index ?? 0) + 1;
      markers.push({
        severity: monaco.MarkerSeverity.Warning,
        message: `引用的插件 '${tag}' 不存在`,
        startLineNumber: lineNumber,
        startColumn,
        endLineNumber: lineNumber,
        endColumn: startColumn + match[0].length,
        source: "OxiDNS",
      });
    }

    if (context.variant === "config" && getYamlPath(model, lineNumber).includes("plugins")) {
      const typeMatch = checkText.match(/^(\s*)type\s*:\s*["']?([A-Za-z0-9_-]+)/);
      const pluginKind = typeMatch?.[2];
      if (pluginKind && !knownPluginKinds.has(pluginKind)) {
        const startColumn = (typeMatch?.[0].lastIndexOf(pluginKind) ?? 0) + 1;
        markers.push({
          severity: monaco.MarkerSeverity.Warning,
          message: `插件类型 '${pluginKind}' 不存在`,
          startLineNumber: lineNumber,
          startColumn,
          endLineNumber: lineNumber,
          endColumn: startColumn + pluginKind.length,
          source: "OxiDNS",
        });
      }
    }

    // Validate jump/goto targets in sequence exec expressions.
    const jumpGotoMatch = checkText.match(/\b(jump|goto)\s+([A-Za-z0-9_.-]+)/);
    if (jumpGotoMatch) {
      const tag = jumpGotoMatch[2];
      if (!pluginTags.has(tag)) {
        const tagStart =
          (jumpGotoMatch.index ?? 0) + jumpGotoMatch[0].length - jumpGotoMatch[2].length;
        const startColumn = tagStart + 1;
        markers.push({
          severity: monaco.MarkerSeverity.Warning,
          message: `引用的插件 '${tag}' 不存在`,
          startLineNumber: lineNumber,
          startColumn,
          endLineNumber: lineNumber,
          endColumn: startColumn + tag.length,
          source: "OxiDNS",
        });
      }
    }
  }

  return markers;
}

function markerFromBackendDiagnostic(
  monaco: MonacoApi,
  model: MonacoModel,
  diagnostic: OxiDnsYamlDiagnostic,
) {
  const message = diagnostic.message;
  if (diagnostic.line && diagnostic.column) {
    return {
      severity: markerSeverity(monaco, diagnostic.severity),
      message,
      startLineNumber: diagnostic.line,
      startColumn: diagnostic.column,
      endLineNumber: diagnostic.end_line ?? diagnostic.line,
      endColumn:
        diagnostic.end_column ??
        Math.max(diagnostic.column + 1, model.getLineMaxColumn(diagnostic.line)),
      source: "OxiDNS",
    };
  }

  const target =
    quotedMatch(message, /Unknown plugin type:\s*([^\s]+)/) ??
    quotedMatch(message, /Unknown plugin type '([^']+)'/) ??
    quotedMatch(message, /Duplicate plugin tag '([^']+)'/) ??
    quotedMatch(message, /references missing plugin '([^']+)'/) ??
    quotedMatch(message, /but '([^']+)' is/) ??
    quotedMatch(message, /plugin type '([^']+)'/);
  const located = target ? locateToken(model, target) : null;

  return {
    severity: monaco.MarkerSeverity.Error,
    message,
    startLineNumber: located?.lineNumber ?? 1,
    startColumn: located?.startColumn ?? 1,
    endLineNumber: located?.lineNumber ?? 1,
    endColumn: located?.endColumn ?? Math.max(2, model.getLineMaxColumn(1)),
    source: "OxiDNS",
  };
}

function markerSeverity(
  monaco: MonacoApi,
  severity: OxiDnsYamlDiagnostic["severity"],
) {
  if (severity === "warning") return monaco.MarkerSeverity.Warning;
  if (severity === "info") return monaco.MarkerSeverity.Info;
  return monaco.MarkerSeverity.Error;
}

function quotedMatch(message: string, pattern: RegExp) {
  return message.match(pattern)?.[1] ?? null;
}

function locateToken(model: MonacoModel, token: string) {
  const needles = [`$${token}`, token];
  for (let lineNumber = 1; lineNumber <= model.getLineCount(); lineNumber += 1) {
    const line = model.getLineContent(lineNumber);
    for (const needle of needles) {
      const index = line.indexOf(needle);
      if (index >= 0) {
        return {
          lineNumber,
          startColumn: index + 1,
          endColumn: index + needle.length + 1,
        };
      }
    }
  }
  return null;
}

function keySuggestions(
  monaco: MonacoApi,
  context: OxiDnsYamlEditorContext,
  range: MonacoRange,
  path: string[],
): CompletionItem[] {
  if (context.variant === "config") {
    if (path.length <= 1) {
      return topLevelKeys.map((key) => keyCompletion(monaco, key, range));
    }
    const subKeys = configSubKeysForPath(path);
    if (subKeys !== null) {
      return subKeys.map((key) => keyCompletion(monaco, key, range));
    }
  }

  const fields =
    context.variant === "plugin-args"
      ? fieldsForPath(context.fields, path)
      : context.fields;
  return (fields ?? []).map((field) => keyCompletion(monaco, field.key, range));
}

function pluginKindSuggestions(
  monaco: MonacoApi,
  range: MonacoRange,
): CompletionItem[] {
  return pluginKindDefinitions.map((definition) => ({
    label: definition.kind,
    kind: monaco.languages.CompletionItemKind.Class,
    insertText: definition.kind,
    range,
    detail: PLUGIN_TYPE_LABELS[definition.type],
    documentation: definition.description,
    sortText: `0-${definition.type}-${definition.kind}`,
  }));
}

function logLevelSuggestions(monaco: MonacoApi, range: MonacoRange): CompletionItem[] {
  return logLevels.map((level) => ({
    label: level,
    kind: monaco.languages.CompletionItemKind.EnumMember,
    insertText: level,
    range,
    detail: "日志级别",
    sortText: `0-${level}`,
  }));
}

function pluginReferenceSuggestions(
  monaco: MonacoApi,
  context: OxiDnsYamlEditorContext,
  range: MonacoRange,
  referenceTypes?: PluginType[],
  inverted = false,
): CompletionItem[] {
  const prefix = inverted ? "!$" : "$";
  return (context.plugins ?? [])
    .filter((plugin) => plugin.name !== context.currentPluginName)
    .filter(
      (plugin) =>
        !referenceTypes ||
        referenceTypes.length === 0 ||
        referenceTypes.includes(plugin.type),
    )
    .map((plugin) => ({
      label: `${prefix}${plugin.name}`,
      kind: monaco.languages.CompletionItemKind.Reference,
      insertText: `${prefix}${plugin.name}`,
      range,
      detail: `${PLUGIN_TYPE_LABELS[plugin.type]} / ${plugin.pluginKind}`,
      documentation: getPluginKindDefinition(plugin.pluginKind)?.description,
      sortText: `1-${plugin.type}-${plugin.name}`,
    }));
}

function quickSetupSuggestions(
  monaco: MonacoApi,
  range: MonacoRange,
  types?: PluginType[],
): CompletionItem[] {
  return pluginKindDefinitions
    .filter((definition) => definition.quickSetup)
    .filter(
      (definition) =>
        !types || types.length === 0 || types.includes(definition.type),
    )
    .map((definition) => ({
      label: definition.kind,
      kind: monaco.languages.CompletionItemKind.Function,
      insertText: definition.quickSetup?.paramPlaceholder
        ? `${definition.kind} `
        : definition.kind,
      range,
      detail: `快捷表达式 · ${PLUGIN_TYPE_LABELS[definition.type]}`,
      documentation:
        definition.quickSetup?.paramPlaceholder ?? definition.description,
      sortText: `2-${definition.type}-${definition.kind}`,
    }));
}

function controlSuggestions(
  monaco: MonacoApi,
  range: MonacoRange,
): CompletionItem[] {
  return sequenceControls.map((control) => ({
    label: control,
    kind: monaco.languages.CompletionItemKind.Keyword,
    insertText: control,
    range,
    detail: "sequence control",
    sortText: `3-${control}`,
  }));
}

// Detects whether the line prefix ends with "jump " or "goto " (plus optional
// partial tag chars), signalling that the user wants to complete a target tag.
function detectJumpGotoExec(
  prefix: string,
): { keyword: "jump" | "goto"; prefixLength: number } | null {
  const match = prefix.match(/\b(jump|goto)\s+([A-Za-z0-9_.-]*)$/);
  if (!match) return null;
  return {
    keyword: match[1] as "jump" | "goto",
    // Length from start of "jump"/"goto" to current cursor position — used to
    // compute the replacement range so the full "jump <tag>" is substituted.
    prefixLength: match[0].length,
  };
}

function jumpGotoTagSuggestions(
  monaco: MonacoApi,
  context: OxiDnsYamlEditorContext,
  range: MonacoRange,
  keyword: "jump" | "goto",
): CompletionItem[] {
  return (context.plugins ?? [])
    .filter((plugin) => plugin.name !== context.currentPluginName)
    .filter((plugin) => plugin.type === "executor")
    .map((plugin) => ({
      label: `${keyword} ${plugin.name}`,
      kind: monaco.languages.CompletionItemKind.Reference,
      insertText: `${keyword} ${plugin.name}`,
      range,
      detail: `${PLUGIN_TYPE_LABELS[plugin.type]} / ${plugin.pluginKind}`,
      documentation: getPluginKindDefinition(plugin.pluginKind)?.description,
      sortText: `0-${keyword}-${plugin.name}`,
    }));
}

function fieldValueSuggestions(
  monaco: MonacoApi,
  context: OxiDnsYamlEditorContext,
  field: ConfigField,
  range: MonacoRange,
): CompletionItem[] {
  if (field.type === "select") {
    return (
      field.options?.map((option) => ({
        label: option.value,
        kind: monaco.languages.CompletionItemKind.EnumMember,
        insertText: option.value,
        range,
        detail: option.label,
      })) ?? []
    );
  }

  if (field.type !== "reference") return [];

  const prefix = field.referencePrefix ?? "";
  return (context.plugins ?? [])
    .filter(
      (plugin) =>
        !field.referenceTypes ||
        field.referenceTypes.length === 0 ||
        field.referenceTypes.includes(plugin.type),
    )
    .filter(
      (plugin) =>
        !field.referencePlugins ||
        field.referencePlugins.length === 0 ||
        field.referencePlugins.includes(plugin.pluginKind),
    )
    .flatMap((plugin) => {
      const base = {
        kind: monaco.languages.CompletionItemKind.Reference,
        range,
        detail: `${PLUGIN_TYPE_LABELS[plugin.type]} / ${plugin.pluginKind}`,
      };
      const items: CompletionItem[] = [
        {
          ...base,
          label: `${prefix}${plugin.name}`,
          insertText: `${prefix}${plugin.name}`,
          sortText: `1-${plugin.type}-${plugin.name}`,
        },
      ];
      if (field.allowInvert || field.referenceTypes?.includes("matcher")) {
        items.push({
          ...base,
          label: `!${prefix}${plugin.name}`,
          insertText: `!${prefix}${plugin.name}`,
          sortText: `1-invert-${plugin.type}-${plugin.name}`,
        });
      }
      return items;
    });
}

function keyCompletion(
  monaco: MonacoApi,
  key: string,
  range: MonacoRange,
): CompletionItem {
  return {
    label: key,
    kind: monaco.languages.CompletionItemKind.Property,
    insertText: `${key}: `,
    range,
    sortText: `0-${key}`,
  };
}

function expectedReferenceTypes(
  context: OxiDnsYamlEditorContext,
  path: string[],
  valueKey: string | null,
): PluginType[] | undefined {
  const field = findFieldForKey(context.fields, valueKey);
  if (field?.referenceTypes?.length) return field.referenceTypes;

  const joined = path.join(".");
  if (valueKey === "matches" || joined.includes("matches")) return ["matcher"];
  if (
    valueKey === "exec" ||
    valueKey === "entry" ||
    valueKey === "primary" ||
    valueKey === "secondary" ||
    valueKey === "executors" ||
    joined.includes("executors")
  ) {
    return ["executor"];
  }
  if (valueKey?.includes("provider") || joined.includes("provider")) {
    return ["provider"];
  }
  if (context.variant === "sequence") return ["matcher", "executor"];
  return undefined;
}

function shouldSuggestSequenceExpressions(
  context: OxiDnsYamlEditorContext,
  path: string[],
  valueKey: string | null,
) {
  if (context.variant === "sequence") return true;
  if (context.pluginKind === "sequence" || context.pluginKind === "cron") {
    const joined = path.join(".");
    return (
      valueKey === "matches" ||
      valueKey === "exec" ||
      valueKey === "executors" ||
      joined.includes("matches") ||
      joined.includes("executors")
    );
  }
  return false;
}

function fieldsForPath(
  fields: ConfigField[] | undefined,
  path: string[],
): ConfigField[] | undefined {
  if (!fields || path.length === 0) return fields;
  const normalizedPath = path.filter((part) => part !== "args");
  let current: ConfigField[] | undefined = fields;

  for (const key of normalizedPath.slice(0, -1)) {
    const field = current?.find((entry) => entry.key === key);
    current = childFields(field);
    if (!current) break;
  }

  return current ?? fields;
}

function childFields(field: ConfigField | undefined): ConfigField[] | undefined {
  if (!field) return undefined;
  if (field.type === "object") return field.fields;
  if (field.type === "array") {
    if (field.item?.type === "object") return field.item.fields;
    const objectOption = field.itemOptions?.find(
      (item): item is Extract<ConfigFieldChild, { type: "object" }> =>
        item.type === "object",
    );
    return objectOption?.fields;
  }
  return undefined;
}

function findFieldForKey(
  fields: ConfigField[] | undefined,
  key: string | null,
): ConfigField | undefined {
  if (!fields || !key) return undefined;
  for (const field of fields) {
    if (field.key === key) return field;
    const nested = findFieldForKey(childFields(field), key);
    if (nested) return nested;
  }
  return undefined;
}

function getYamlPath(model: MonacoModel, lineNumber: number) {
  const stack: Array<{ indent: number; key: string }> = [];
  for (let index = 1; index <= lineNumber; index += 1) {
    const raw = model.getLineContent(index);
    const match = raw.match(/^(\s*)(?:-\s*)?([A-Za-z0-9_-]+)\s*:/);
    if (!match) continue;
    const indent = match[1].length;
    const key = match[2];
    while (stack.length && stack[stack.length - 1].indent >= indent) {
      stack.pop();
    }
    stack.push({ indent, key });
  }
  return stack.map((item) => item.key);
}

function getReplacementRange(
  monaco: MonacoApi,
  position: MonacoPosition,
  prefix: string,
): MonacoRange {
  const match = prefix.match(/!?[$]?[A-Za-z0-9_.-]*$/);
  const token = match?.[0] ?? "";
  return new monaco.Range(
    position.lineNumber,
    position.column - token.length,
    position.lineNumber,
    position.column,
  );
}

function getValueKey(prefix: string) {
  const match = prefix.match(/(?:^|\s)([A-Za-z0-9_-]+)\s*:\s*[^:]*$/);
  return match?.[1] ?? null;
}

function isKeyPosition(prefix: string) {
  const trimmed = prefix.trimStart();
  return !trimmed || /^-\s*[A-Za-z0-9_-]*$/.test(trimmed) || /^[A-Za-z0-9_-]*$/.test(trimmed);
}

function isReferencePrefix(prefix: string) {
  return /(?:^|\s)!?\$[A-Za-z0-9_.-]*$/.test(prefix);
}

function getTokenAtPosition(
  model: MonacoModel,
  position: MonacoPosition,
) {
  const line = model.getLineContent(position.lineNumber);
  const left = line.slice(0, position.column - 1);
  const right = line.slice(position.column - 1);
  const leftMatch = left.match(/!?[$]?[A-Za-z0-9_.-]*$/);
  const rightMatch = right.match(/^[A-Za-z0-9_.-]*/);
  const token = `${leftMatch?.[0] ?? ""}${rightMatch?.[0] ?? ""}`;
  return token || null;
}

function tokenStartColumn(
  model: MonacoModel,
  position: MonacoPosition,
  token: string,
) {
  const line = model.getLineContent(position.lineNumber);
  const before = line.slice(0, position.column - 1);
  const leftMatch = before.match(/!?[$]?[A-Za-z0-9_.-]*$/);
  return position.column - (leftMatch?.[0].length ?? token.length);
}

function dedupeSuggestions(items: CompletionItem[]) {
  const seen = new Set<string>();
  return items.filter((item) => {
    const key = String(item.label);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
