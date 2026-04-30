"use client";

import {
  getPluginCatalogItem,
  renderPluginKindIcon,
} from "@/components/plugins/catalog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import type { ConfigField, ConfigFieldChild } from "@/lib/plugin-definitions";
import type { PluginInstance, PluginType } from "@/lib/types";
import { PLUGIN_TYPE_LABELS } from "@/lib/types";
import { ChevronDown, Info, Minus, Plus, Search } from "lucide-react";
import { useState } from "react";

type ArrayItemSyntax = "value" | "plugin" | "quick" | "domain";

interface ArrayItemValue {
  id: string;
  syntax: ArrayItemSyntax;
  value: string;
  invert?: boolean;
  referenceTypes?: PluginType[];
}

interface SchemaArrayOptionValue {
  id: string;
  optionKey: string;
  value: unknown;
}

interface RecordItemValue {
  id: string;
  key: string;
  value: string;
}

interface PluginConfigFieldsEditorProps {
  fields: ConfigField[];
  plugins: PluginInstance[];
  values: Record<string, unknown>;
  onChange: (values: Record<string, unknown>) => void;
  defaultArrayObjectCollapsed?: boolean;
  readOnly?: boolean;
}

const arraySyntaxLabels: Record<ArrayItemSyntax, string> = {
  value: "值",
  plugin: "插件",
  quick: "表达式",
  domain: "域名规则",
};

export function createDefaultPluginConfigValues(fields: ConfigField[]) {
  const defaults: Record<string, unknown> = {};
  fields.forEach((field) => {
    if (field.default !== undefined) {
      defaults[field.key] = field.default;
    } else if (field.type === "array") {
      defaults[field.key] = [];
    } else if (field.type === "object" && field.fields) {
      defaults[field.key] = createDefaultPluginConfigValues(field.fields);
    } else if (field.type === "record") {
      defaults[field.key] = [];
    } else if (field.type === "json") {
      defaults[field.key] = "";
    }
  });
  return defaults;
}

export function createPluginConfigFormValues(
  fields: ConfigField[],
  config: Record<string, unknown>,
) {
  const values = createDefaultPluginConfigValues(fields);

  fields.forEach((field) => {
    const value = config[field.key];
    if (value === undefined) return;

    if (field.type === "array") {
      values[field.key] = normalizeArrayFieldValue(value, field);
    } else if (field.type === "object" && field.fields) {
      values[field.key] =
        value && typeof value === "object" && !Array.isArray(value)
          ? createPluginConfigFormValues(
              field.fields,
              value as Record<string, unknown>,
            )
          : createDefaultPluginConfigValues(field.fields);
    } else if (field.type === "record") {
      values[field.key] = normalizeRecordValue(value);
    } else if (field.type === "json") {
      values[field.key] =
        typeof value === "string" ? value : JSON.stringify(value, null, 2);
    } else {
      values[field.key] = value;
    }
  });

  return values;
}

export function serializePluginConfigValues(
  fields: ConfigField[],
  values: Record<string, unknown>,
) {
  const config: Record<string, unknown> = {};

  fields.forEach((field) => {
    const value = values[field.key];
    if (field.type === "array" && Array.isArray(value)) {
      const serialized = serializeArrayFieldValue(value, field);
      if (serialized.length > 0 || field.required)
        config[field.key] = serialized;
    } else if (field.type === "array" && typeof value === "string") {
      const serialized = value
        .split("\n")
        .map((v) => v.trim())
        .filter(Boolean);
      if (serialized.length > 0 || field.required)
        config[field.key] = serialized;
    } else if (
      field.type === "json" &&
      typeof value === "string" &&
      value.trim()
    ) {
      try {
        config[field.key] = JSON.parse(value);
      } catch {
        config[field.key] = value;
      }
    } else if (field.type === "object" && field.fields) {
      const serialized =
        value && typeof value === "object" && !Array.isArray(value)
          ? serializePluginConfigValues(
              field.fields,
              value as Record<string, unknown>,
            )
          : {};
      if (!isEmptyConfigValue(serialized) || field.required) {
        config[field.key] = serialized;
      }
    } else if (field.type === "record" && Array.isArray(value)) {
      const serialized = serializeRecordValue(value as RecordItemValue[]);
      if (!isEmptyConfigValue(serialized) || field.required) {
        config[field.key] = serialized;
      }
    } else if (field.asArray && value !== undefined && value !== "") {
      config[field.key] = [value];
    } else if (value !== undefined && value !== "") {
      config[field.key] = value;
    }
  });

  return config;
}

export function isPluginConfigFormValid(
  fields: ConfigField[],
  values: Record<string, unknown>,
) {
  return fields.every((field) => {
    if (!field.required) return true;
    const value = values[field.key];
    if (Array.isArray(value)) return value.length > 0;
    return value !== undefined && value !== "";
  });
}

export function PluginConfigFieldsEditor({
  fields,
  plugins,
  values,
  onChange,
  defaultArrayObjectCollapsed = false,
  readOnly = false,
}: PluginConfigFieldsEditorProps) {
  const updateConfig = (key: string, value: unknown) => {
    onChange({ ...values, [key]: value });
  };

  if (fields.length === 0) {
    return (
      <div className="rounded-lg border border-dashed p-4 text-sm text-muted-foreground">
        此插件没有独立配置项。
      </div>
    );
  }

  return (
    <FieldGroup>
      {fields.map((field) => (
        <Field key={field.key}>
          <ConfigFieldLabel field={field} />
          <ConfigFieldControl
            field={field}
            plugins={plugins}
            value={values[field.key]}
            onChange={(value) => updateConfig(field.key, value)}
            defaultArrayObjectCollapsed={defaultArrayObjectCollapsed}
            readOnly={readOnly}
          />
        </Field>
      ))}
    </FieldGroup>
  );
}

function ConfigFieldLabel({ field }: { field: ConfigField }) {
  return (
    <FieldLabel className="flex items-center gap-1.5">
      <span>{field.label}</span>
      {field.required && <span className="text-destructive">*</span>}
      {field.description && (
        <Tooltip>
          <TooltipTrigger asChild>
            <button
              type="button"
              className="inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-muted-foreground transition-colors hover:bg-muted hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              aria-label={`${field.label} 配置说明`}
            >
              <Info className="h-3.5 w-3.5" />
            </button>
          </TooltipTrigger>
          <TooltipContent
            side="top"
            align="start"
            className="max-w-80 text-xs leading-relaxed"
          >
            {field.description}
          </TooltipContent>
        </Tooltip>
      )}
    </FieldLabel>
  );
}

function ConfigFieldControl({
  field,
  plugins,
  value,
  onChange,
  defaultArrayObjectCollapsed,
  readOnly,
}: {
  field: ConfigField;
  plugins: PluginInstance[];
  value: unknown;
  onChange: (value: unknown) => void;
  defaultArrayObjectCollapsed: boolean;
  readOnly: boolean;
}) {
  switch (field.type) {
    case "text":
      return (
        <Input
          value={(value as string) || ""}
          onChange={(e) => onChange(e.target.value)}
          placeholder={field.placeholder}
          className="font-mono text-sm"
          disabled={readOnly}
        />
      );
    case "number":
      return (
        <Input
          type="number"
          value={(value as number) ?? ""}
          onChange={(e) =>
            onChange(e.target.value ? Number(e.target.value) : "")
          }
          placeholder={field.placeholder}
          className="font-mono text-sm"
          disabled={readOnly}
        />
      );
    case "textarea":
      return (
        <Textarea
          value={(value as string) || ""}
          onChange={(e) => onChange(e.target.value)}
          placeholder={field.placeholder}
          className="min-h-[80px] font-mono text-sm"
          disabled={readOnly}
        />
      );
    case "array":
      if (field.item || field.itemOptions) {
        return (
          <SchemaArrayFieldEditor
            field={field}
            plugins={plugins}
            value={Array.isArray(value) ? value : []}
            onChange={onChange}
            defaultArrayObjectCollapsed={defaultArrayObjectCollapsed}
            readOnly={readOnly}
          />
        );
      }

      return (
        <ArrayFieldEditor
          field={field}
          plugins={plugins}
          value={normalizeArrayValue(value)}
          onChange={onChange}
          readOnly={readOnly}
        />
      );
    case "duration":
      return (
        <Input
          value={(value as string) || ""}
          onChange={(e) => onChange(e.target.value)}
          placeholder={field.placeholder || "3s"}
          className="font-mono text-sm"
          disabled={readOnly}
        />
      );
    case "json":
      return (
        <Textarea
          value={(value as string) || ""}
          onChange={(e) => onChange(e.target.value)}
          placeholder={field.placeholder}
          className="min-h-[120px] font-mono text-sm"
          disabled={readOnly}
        />
      );
    case "object":
      if (!field.fields) return null;
      return (
        <ObjectFieldEditor
          fields={field.fields}
          plugins={plugins}
          value={
            value && typeof value === "object" && !Array.isArray(value)
              ? (value as Record<string, unknown>)
              : createDefaultPluginConfigValues(field.fields)
          }
          onChange={onChange}
          defaultArrayObjectCollapsed={defaultArrayObjectCollapsed}
          readOnly={readOnly}
        />
      );
    case "record":
      return (
        <RecordFieldEditor
          field={field}
          value={Array.isArray(value) ? (value as RecordItemValue[]) : []}
          onChange={onChange}
          readOnly={readOnly}
        />
      );
    case "select":
      return (
        <Select
          value={(value as string) || ""}
          onValueChange={onChange}
          disabled={readOnly}
        >
          <SelectTrigger>
            <SelectValue placeholder="请选择" />
          </SelectTrigger>
          <SelectContent>
            {field.options?.map((opt) => (
              <SelectItem key={opt.value} value={opt.value}>
                {opt.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      );
    case "switch":
      return (
        <Switch
          checked={!!value}
          onCheckedChange={onChange}
          disabled={readOnly}
        />
      );
    case "reference":
      const referenceValue = stripInvertPrefix(value);
      const referenceInverted =
        typeof value === "string" && value.startsWith("!");
      const referenceCanInvert =
        field.allowInvert || field.referenceTypes?.includes("matcher") || false;

      return (
        <div className="flex items-center gap-2">
          <PluginReferencePicker
            plugins={plugins}
            value={referenceValue}
            referenceTypes={field.referenceTypes}
            referencePlugins={field.referencePlugins}
            disabled={readOnly}
            onChange={(nextValue) =>
              onChange(
                `${referenceInverted ? "!" : ""}${field.referencePrefix ?? ""}${nextValue}`,
              )
            }
          />
          {referenceCanInvert && (
            <label className="flex shrink-0 items-center gap-2 text-xs text-muted-foreground">
              <Switch
                checked={referenceInverted}
                disabled={readOnly || !referenceValue}
                onCheckedChange={(checked) =>
                  onChange(
                    `${checked ? "!" : ""}${field.referencePrefix ?? ""}${stripReferencePrefix(referenceValue)}`,
                  )
                }
              />
              取反
            </label>
          )}
        </div>
      );
    default:
      return null;
  }
}

function ArrayFieldEditor({
  field,
  plugins,
  value,
  onChange,
  readOnly,
}: {
  field: ConfigField;
  plugins: PluginInstance[];
  value: ArrayItemValue[];
  onChange: (items: ArrayItemValue[]) => void;
  readOnly: boolean;
}) {
  const addItem = () => {
    onChange([
      ...value,
      {
        id: createArrayItemId(),
        syntax: inferDefaultSyntax(field),
        value: "",
        referenceTypes: inferReferenceTypes(field),
      },
    ]);
  };

  const updateItem = (id: string, patch: Partial<ArrayItemValue>) => {
    onChange(
      value.map((item) =>
        item.id === id
          ? {
              ...item,
              ...patch,
              value:
                patch.syntax && patch.syntax !== item.syntax
                  ? ""
                  : (patch.value ?? item.value),
            }
          : item,
      ),
    );
  };

  return (
    <div className="space-y-2">
      {value.length > 0 ? (
        value.map((item) => (
          <div
            key={item.id}
            className="grid gap-2 rounded-lg border border-border bg-background/60 p-2 sm:grid-cols-[8.5rem_1fr_auto]"
          >
            <Select
              value={item.syntax}
              onValueChange={(syntax) =>
                updateItem(item.id, { syntax: syntax as ArrayItemSyntax })
              }
              disabled={readOnly}
            >
              <SelectTrigger className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {getSyntaxOptions(field).map((syntax) => (
                  <SelectItem key={syntax} value={syntax}>
                    {arraySyntaxLabels[syntax]}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <ArrayItemInput
              item={item}
              field={field}
              plugins={plugins}
              onChange={(patch) => updateItem(item.id, patch)}
              readOnly={readOnly}
            />
            {!readOnly && (
              <Button
                type="button"
                variant="outline"
                size="icon"
                className="sm:self-start"
                onClick={() =>
                  onChange(value.filter((entry) => entry.id !== item.id))
                }
              >
                <Minus className="h-4 w-4" />
              </Button>
            )}
          </div>
        ))
      ) : (
        <div className="rounded-lg border border-dashed p-4 text-sm text-muted-foreground">
          暂无配置项，点击下方按钮新增。
        </div>
      )}

      {!readOnly && (
        <Button type="button" variant="outline" size="sm" onClick={addItem}>
          <Plus className="mr-1.5 h-4 w-4" />
          新增配置项
        </Button>
      )}
    </div>
  );
}

function ObjectFieldEditor({
  fields,
  plugins,
  value,
  onChange,
  defaultArrayObjectCollapsed,
  readOnly,
}: {
  fields: ConfigField[];
  plugins: PluginInstance[];
  value: Record<string, unknown>;
  onChange: (value: Record<string, unknown>) => void;
  defaultArrayObjectCollapsed: boolean;
  readOnly: boolean;
}) {
  return (
    <div className="space-y-4">
      {fields.map((field) => (
        <Field key={field.key}>
          <ConfigFieldLabel field={field} />
          <ConfigFieldControl
            field={field}
            plugins={plugins}
            value={value[field.key]}
            onChange={(nextFieldValue) =>
              onChange({ ...value, [field.key]: nextFieldValue })
            }
            defaultArrayObjectCollapsed={defaultArrayObjectCollapsed}
            readOnly={readOnly}
          />
        </Field>
      ))}
    </div>
  );
}

function RecordFieldEditor({
  field,
  value,
  onChange,
  readOnly,
}: {
  field: ConfigField;
  value: RecordItemValue[];
  onChange: (value: RecordItemValue[]) => void;
  readOnly: boolean;
}) {
  const addItem = () => {
    onChange([...value, { id: createArrayItemId(), key: "", value: "" }]);
  };

  const updateItem = (id: string, patch: Partial<RecordItemValue>) => {
    onChange(
      value.map((item) => (item.id === id ? { ...item, ...patch } : item)),
    );
  };

  return (
    <div className="space-y-2">
      {value.length > 0 ? (
        value.map((item) => (
          <div
            key={item.id}
            className="grid gap-2 rounded-lg border border-border bg-background/60 p-2 sm:grid-cols-[minmax(0,12rem)_1fr_auto]"
          >
            <Input
              value={item.key}
              onChange={(event) =>
                updateItem(item.id, { key: event.target.value })
              }
              placeholder={field.keyPlaceholder ?? "key"}
              className="font-mono text-sm"
              disabled={readOnly}
            />
            <Input
              value={item.value}
              onChange={(event) =>
                updateItem(item.id, { value: event.target.value })
              }
              placeholder={field.valuePlaceholder ?? "value"}
              className="font-mono text-sm"
              disabled={readOnly}
            />
            {!readOnly && (
              <Button
                type="button"
                variant="outline"
                size="icon"
                className="h-9 w-9"
                onClick={() =>
                  onChange(value.filter((entry) => entry.id !== item.id))
                }
              >
                <Minus className="h-4 w-4" />
              </Button>
            )}
          </div>
        ))
      ) : (
        <div className="rounded-lg border border-dashed p-4 text-sm text-muted-foreground">
          暂无配置项，点击下方按钮新增。
        </div>
      )}

      {!readOnly && (
        <Button type="button" variant="outline" size="sm" onClick={addItem}>
          <Plus className="mr-1.5 h-4 w-4" />
          新增配置项
        </Button>
      )}
    </div>
  );
}

function SchemaArrayFieldEditor({
  field,
  plugins,
  value,
  onChange,
  defaultArrayObjectCollapsed,
  readOnly,
}: {
  field: ConfigField;
  plugins: PluginInstance[];
  value: unknown[];
  onChange: (items: unknown[]) => void;
  defaultArrayObjectCollapsed: boolean;
  readOnly: boolean;
}) {
  const itemOptions = getArrayFieldItemOptions(field);
  const [selectedOptionKey, setSelectedOptionKey] = useState(
    getChildOptionKey(itemOptions[0]),
  );
  const [collapsedItems, setCollapsedItems] = useState<Record<string, boolean>>(
    {},
  );

  const addItem = () => {
    const selectedOption =
      itemOptions.find(
        (option) => getChildOptionKey(option) === selectedOptionKey,
      ) ?? itemOptions[0];

    if (!selectedOption) return;

    if (field.itemOptions) {
      onChange([
        ...value,
        {
          id: createArrayItemId(),
          optionKey: getChildOptionKey(selectedOption),
          value: createDefaultArrayItemValue(selectedOption),
        } satisfies SchemaArrayOptionValue,
      ]);
      return;
    }

    onChange([...value, createDefaultArrayItemValue(selectedOption)]);
  };

  const updateItem = (index: number, nextValue: unknown) => {
    onChange(
      value.map((entry, entryIndex) =>
        entryIndex === index ? nextValue : entry,
      ),
    );
  };

  const removeItem = (index: number) => {
    onChange(value.filter((_, entryIndex) => entryIndex !== index));
  };

  return (
    <div className="space-y-2">
      {value.length > 0 ? (
        value.map((entry, index) => {
          const entryKey = getArrayEntryKey(entry, index);
          const child = getArrayEntryChild(entry, field);
          const entryValue = getArrayEntryValue(entry, field);
          const canCollapse = child.type === "object";
          const isCollapsed =
            canCollapse &&
            (collapsedItems[entryKey] ?? defaultArrayObjectCollapsed);

          return (
            <div
              key={entryKey}
              className="rounded-lg border border-border bg-background/60 px-3 py-2"
            >
              <div
                className={`flex items-center justify-between gap-3 ${
                  isCollapsed ? "" : "mb-2"
                }`}
              >
                <div className="min-w-0 flex-1">
                  {canCollapse ? (
                    <button
                      type="button"
                      className="flex w-full min-w-0 items-center gap-2 text-left text-xs font-medium text-muted-foreground hover:text-foreground"
                      onClick={() =>
                        setCollapsedItems((current) => ({
                          ...current,
                          [entryKey]: !isCollapsed,
                        }))
                      }
                    >
                      <ChevronDown
                        className={`h-4 w-4 shrink-0 transition-transform ${
                          isCollapsed ? "-rotate-90" : ""
                        }`}
                      />
                      <span className="truncate">
                        {getArrayEntryLabel(entry, field, index)}
                      </span>
                      {isCollapsed && (
                        <span className="min-w-0 flex-1 truncate text-foreground">
                          {getObjectSummary(child, entryValue)}
                        </span>
                      )}
                    </button>
                  ) : (
                    <div className="text-xs font-medium text-muted-foreground">
                      {getArrayEntryLabel(entry, field, index)}
                    </div>
                  )}
                </div>
                {!readOnly && (
                  <Button
                    type="button"
                    variant="outline"
                    size="icon"
                    className="h-8 w-8 shrink-0"
                    onClick={() => removeItem(index)}
                  >
                    <Minus className="h-4 w-4" />
                  </Button>
                )}
              </div>
              {!isCollapsed && (
                <SchemaArrayItemControl
                  item={child}
                  plugins={plugins}
                  value={entryValue}
                  placeholder={field.placeholder}
                  onChange={(nextValue) =>
                    updateItem(
                      index,
                      setArrayEntryValue(entry, field, nextValue),
                    )
                  }
                  defaultArrayObjectCollapsed={defaultArrayObjectCollapsed}
                  readOnly={readOnly}
                />
              )}
            </div>
          );
        })
      ) : (
        <div className="rounded-lg border border-dashed p-4 text-sm text-muted-foreground">
          暂无配置项，点击下方按钮新增。
        </div>
      )}

      {!readOnly && (
        <div className="flex flex-wrap items-center gap-2">
          {field.itemOptions && itemOptions.length > 1 && (
            <Select
              value={selectedOptionKey}
              onValueChange={setSelectedOptionKey}
            >
              <SelectTrigger className="h-9 w-36">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {itemOptions.map((option) => (
                  <SelectItem
                    key={getChildOptionKey(option)}
                    value={getChildOptionKey(option)}
                  >
                    {getChildLabel(option)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          )}
          <Button type="button" variant="outline" size="sm" onClick={addItem}>
            <Plus className="mr-1.5 h-4 w-4" />
            新增配置项
          </Button>
        </div>
      )}
    </div>
  );
}

function SchemaArrayItemControl({
  item,
  plugins,
  value,
  placeholder,
  onChange,
  defaultArrayObjectCollapsed,
  readOnly,
}: {
  item: ConfigFieldChild;
  plugins: PluginInstance[];
  value: unknown;
  placeholder?: string;
  onChange: (value: unknown) => void;
  defaultArrayObjectCollapsed: boolean;
  readOnly: boolean;
}) {
  if (item.type === "object") {
    const objectValue =
      value && typeof value === "object" && !Array.isArray(value)
        ? (value as Record<string, unknown>)
        : {};

    return (
      <ObjectFieldEditor
        fields={item.fields}
        plugins={plugins}
        value={objectValue}
        onChange={onChange}
        defaultArrayObjectCollapsed={defaultArrayObjectCollapsed}
        readOnly={readOnly}
      />
    );
  }

  if (item.type === "array") {
    return (
      <SchemaArrayFieldEditor
        field={arrayItemToConfigField(item, placeholder)}
        plugins={plugins}
        value={Array.isArray(value) ? value : []}
        onChange={onChange}
        defaultArrayObjectCollapsed={defaultArrayObjectCollapsed}
        readOnly={readOnly}
      />
    );
  }

  return (
    <ConfigFieldControl
      field={arrayItemToConfigField(item, placeholder)}
      plugins={plugins}
      value={value}
      onChange={onChange}
      defaultArrayObjectCollapsed={defaultArrayObjectCollapsed}
      readOnly={readOnly}
    />
  );
}

function ArrayItemInput({
  item,
  field,
  plugins,
  onChange,
  readOnly,
}: {
  item: ArrayItemValue;
  field: ConfigField;
  plugins: PluginInstance[];
  onChange: (patch: Partial<ArrayItemValue>) => void;
  readOnly: boolean;
}) {
  if (item.syntax === "plugin") {
    const referenceTypes = item.referenceTypes ?? inferReferenceTypes(field);
    const canInvert = referenceTypes.includes("matcher");

    return (
      <div className="flex min-w-0 items-center gap-2">
        <PluginReferencePicker
          plugins={plugins}
          value={stripInvertPrefix(item.value)}
          referenceTypes={referenceTypes}
          referencePlugins={field.referencePlugins}
          disabled={readOnly}
          onChange={(nextValue) =>
            onChange({
              value: item.invert ? `!$${nextValue}` : `$${nextValue}`,
            })
          }
        />
        {canInvert && (
          <label className="flex shrink-0 items-center gap-2 text-xs text-muted-foreground">
            <Switch
              checked={!!item.invert}
              disabled={readOnly || !stripInvertPrefix(item.value)}
              onCheckedChange={(checked) =>
                onChange({
                  invert: checked,
                  value: checked
                    ? `!$${stripInvertPrefix(item.value)}`
                    : `$${stripInvertPrefix(item.value)}`,
                })
              }
            />
            取反
          </label>
        )}
      </div>
    );
  }

  return (
    <Input
      value={item.value}
      onChange={(event) => onChange({ value: event.target.value })}
      placeholder={field.placeholder?.split("\n")[0] ?? "value"}
      className="font-mono text-sm"
      disabled={readOnly}
    />
  );
}

interface PluginReferencePickerProps {
  plugins: PluginInstance[];
  value: string;
  referenceTypes?: PluginType[];
  referencePlugins?: string[];
  disabled?: boolean;
  onChange: (value: string) => void;
}

export function PluginReferencePicker({
  plugins,
  value,
  referenceTypes,
  referencePlugins,
  disabled = false,
  onChange,
}: PluginReferencePickerProps) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");
  const normalizedValue = stripReferencePrefix(value);
  const selectedPlugin = plugins.find((p) => p.name === normalizedValue);

  const filteredPlugins = plugins.filter((plugin) => {
    if (
      referenceTypes &&
      referenceTypes.length > 0 &&
      !referenceTypes.includes(plugin.type)
    )
      return false;
    if (
      referencePlugins &&
      referencePlugins.length > 0 &&
      !referencePlugins.includes(plugin.pluginKind)
    )
      return false;

    const definition = getPluginCatalogItem(plugin.pluginKind);
    const normalizedSearch = search.trim().toLowerCase();
    if (!normalizedSearch) return true;

    return [
      plugin.name,
      plugin.type,
      plugin.pluginKind,
      definition?.name,
      definition?.description,
    ]
      .filter(Boolean)
      .join(" ")
      .toLowerCase()
      .includes(normalizedSearch);
  });

  return (
    <Popover open={open && !disabled} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          type="button"
          variant="outline"
          className="min-w-0 flex-1 justify-between font-normal bg-background text-foreground"
          disabled={disabled}
        >
          {selectedPlugin ? (
            <PluginReferenceSummary
              plugin={selectedPlugin}
              singleLine
              inDropdown={false}
            />
          ) : (
            <span className="text-muted-foreground">选择插件引用</span>
          )}
        </Button>
      </PopoverTrigger>

      <PopoverContent
        align="start"
        side="bottom"
        className="w-[28rem] max-w-[calc(100vw-3rem)] p-2 z-[50]"
      >
        <div className="relative">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="搜索插件名称、类型或种类"
            className="pl-9"
          />
        </div>

        <div className="max-h-72 overflow-y-auto space-y-2 pt-1">
          {filteredPlugins.length > 0 ? (
            filteredPlugins.map((plugin) => (
              <button
                key={plugin.id}
                type="button"
                className="flex w-full flex-col gap-1 rounded-lg border border-border bg-background p-3 text-left transition-colors hover:bg-accent"
                onClick={() => {
                  onChange(plugin.name);
                  setOpen(false);
                  setSearch("");
                }}
              >
                <PluginReferenceSummary
                  plugin={plugin}
                  singleLine={false}
                  inDropdown
                />
              </button>
            ))
          ) : (
            <div className="rounded-lg border border-dashed p-4 text-center text-sm text-muted-foreground">
              没有匹配的插件
            </div>
          )}
        </div>
      </PopoverContent>
    </Popover>
  );
}

interface PluginReferenceSummaryProps {
  plugin: PluginInstance;
  singleLine?: boolean;
  inDropdown?: boolean; // 控制背景色
}

export function PluginReferenceSummary({
  plugin,
  singleLine = false,
  inDropdown = false,
}: PluginReferenceSummaryProps) {
  const definition = getPluginCatalogItem(plugin.pluginKind);
  const iconName = definition?.icon ?? "Database";

  // 单行小图标，下拉列表大图标
  const iconSizeClass = singleLine ? "h-4 w-4" : "h-10 w-10";

  // 图标背景和颜色保持一致
  const iconBgClass =
    inDropdown || singleLine
      ? "bg-primary/10 text-primary"
      : "bg-background text-foreground";

  if (singleLine) {
    // 触发按钮单行显示
    return (
      <span className="flex items-center gap-2 truncate min-w-0">
        <span
          className={`flex h-6 w-6 shrink-0 items-center justify-center rounded-md ${iconBgClass}`}
        >
          {renderPluginKindIcon(iconName, { className: iconSizeClass })}
        </span>
        <span className="flex-1 flex items-center gap-2 truncate">
          <span className="truncate font-mono text-sm">{plugin.name}</span>
          <span className="flex gap-1">
            <Badge variant="outline" className="text-[0.65rem]">
              {PLUGIN_TYPE_LABELS[plugin.type]}
            </Badge>
            {definition?.name && (
              <Badge variant="secondary" className="text-[0.65rem]">
                {definition.name}
              </Badge>
            )}
          </span>
        </span>
      </span>
    );
  }

  // 下拉列表多行卡片布局
  return (
    <div className="flex gap-3 p-2 rounded-lg border border-border bg-background hover:bg-accent">
      {/* 左侧大图标 */}
      <div
        className={`flex shrink-0 items-center justify-center rounded-md ${iconBgClass}`}
      >
        {renderPluginKindIcon(iconName, { className: iconSizeClass })}
      </div>

      {/* 右侧两行内容 */}
      <div className="flex-1 flex flex-col justify-center gap-1 min-w-0">
        {/* 第一行：名称 + Badge */}
        <div className="flex items-center gap-2 truncate">
          <span className="truncate font-mono text-sm">{plugin.name}</span>
          <span className="flex gap-1">
            <Badge variant="outline" className="text-[0.65rem]">
              {PLUGIN_TYPE_LABELS[plugin.type]}
            </Badge>
            {definition?.name && (
              <Badge variant="secondary" className="text-[0.65rem]">
                {definition.name}
              </Badge>
            )}
          </span>
        </div>

        {/* 第二行：描述 */}
        {definition?.description && (
          <span className="text-xs text-muted-foreground truncate">
            {definition.description}
          </span>
        )}
      </div>
    </div>
  );
}
function normalizeArrayValue(value: unknown): ArrayItemValue[] {
  if (!Array.isArray(value)) {
    if (typeof value === "string" && value.trim()) {
      return value
        .split("\n")
        .map((line) => line.trim())
        .filter(Boolean)
        .map(createArrayItemFromString);
    }
    return [];
  }

  return value.map((item) =>
    typeof item === "string"
      ? createArrayItemFromString(item)
      : (item as ArrayItemValue),
  );
}

function normalizeRecordValue(value: unknown): RecordItemValue[] {
  if (!value || typeof value !== "object" || Array.isArray(value)) return [];
  return Object.entries(value as Record<string, unknown>).map(
    ([key, entry]) => ({
      id: createArrayItemId(),
      key,
      value: typeof entry === "string" ? entry : String(entry ?? ""),
    }),
  );
}

function serializeRecordValue(value: RecordItemValue[]) {
  return value.reduce<Record<string, string>>((record, item) => {
    const key = item.key.trim();
    if (!key) return record;
    record[key] = item.value;
    return record;
  }, {});
}

function normalizeArrayFieldValue(
  value: unknown,
  field: ConfigField,
): unknown[] {
  if (field.itemOptions) {
    return normalizeOptionArrayValue(value, field.itemOptions);
  }

  if (field.item) {
    return normalizeSchemaArrayValue(value, field.item);
  }

  return normalizeArrayValue(value);
}

function serializeArrayFieldValue(value: unknown[], field: ConfigField) {
  if (field.itemOptions) {
    return value
      .map((entry) =>
        serializeOptionArrayEntry(entry as SchemaArrayOptionValue, field),
      )
      .filter((entry) => !isEmptyConfigValue(entry));
  }

  if (field.item) {
    return value
      .map((item) => serializeSchemaArrayItem(item, field.item!))
      .filter((item) => !isEmptyConfigValue(item));
  }

  return value
    .map((item) =>
      typeof item === "string"
        ? item
        : serializeArrayItem(item as ArrayItemValue),
    )
    .filter(Boolean);
}

function normalizeOptionArrayValue(
  value: unknown,
  itemOptions: ConfigFieldChild[],
): SchemaArrayOptionValue[] {
  const entries = normalizeArrayInputEntries(value);
  if (entries.length === 0) return [];

  return entries.map((entry) => {
    const option = inferArrayItemOption(entry, itemOptions);
    return {
      id: createArrayItemId(),
      optionKey: getChildOptionKey(option),
      value: normalizeSchemaValue(entry, option),
    };
  });
}

function normalizeSchemaArrayValue(
  value: unknown,
  item: ConfigFieldChild,
): unknown[] {
  return normalizeArrayInputEntries(value).map((entry) =>
    normalizeSchemaValue(entry, item),
  );
}

function normalizeArrayInputEntries(value: unknown): unknown[] {
  if (Array.isArray(value)) return value;
  if (typeof value === "string" && value.trim()) {
    return value
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean);
  }
  return [];
}

function normalizeSchemaValue(value: unknown, item: ConfigFieldChild): unknown {
  if (item.type === "object") {
    return value && typeof value === "object" && !Array.isArray(value)
      ? createPluginConfigFormValues(
          item.fields,
          value as Record<string, unknown>,
        )
      : createDefaultPluginConfigValues(item.fields);
  }

  if (item.type === "array") {
    const field = arrayItemToConfigField(item);
    return normalizeArrayFieldValue(value, field);
  }

  return value;
}

function serializeSchemaArrayItem(
  value: unknown,
  item: ConfigFieldChild,
): unknown {
  if (item.type === "object") {
    if (!value || typeof value !== "object" || Array.isArray(value)) return {};
    return serializePluginConfigValues(
      item.fields,
      value as Record<string, unknown>,
    );
  }

  if (item.type === "array") {
    return Array.isArray(value)
      ? serializeArrayFieldValue(value, arrayItemToConfigField(item))
      : [];
  }

  if (item.type === "reference") {
    const tag = stripReferencePrefix(value);
    if (!tag) return "";
    const inverted = typeof value === "string" && value.startsWith("!");
    return `${inverted ? "!" : ""}${item.referencePrefix ?? ""}${tag}`;
  }

  return value;
}

function serializeOptionArrayEntry(
  entry: SchemaArrayOptionValue,
  field: ConfigField,
) {
  const options = field.itemOptions ?? [];
  const option =
    options.find((item) => getChildOptionKey(item) === entry.optionKey) ??
    options[0];

  if (!option) return "";
  return serializeSchemaArrayItem(entry.value, option);
}

function createDefaultArrayItemValue(item: ConfigFieldChild): unknown {
  if (item.type === "object") {
    return createDefaultPluginConfigValues(item.fields);
  }

  if (item.type === "array") return [];
  if (item.default !== undefined) return item.default;
  if (item.type === "switch") return false;
  return "";
}

function arrayItemToConfigField(
  item: ConfigFieldChild,
  placeholder?: string,
): ConfigField {
  return {
    key: "value",
    ...item,
    label: item.label ?? "值",
    placeholder: item.placeholder ?? placeholder,
  };
}

function getArrayFieldItemOptions(field: ConfigField): ConfigFieldChild[] {
  if (field.itemOptions?.length) return field.itemOptions;
  if (field.item) return [field.item];
  return [
    {
      optionKey: "input",
      type: "text",
      label: "输入值",
      placeholder: field.placeholder?.split("\n")[0],
    },
  ];
}

function getArrayEntryChild(
  entry: unknown,
  field: ConfigField,
): ConfigFieldChild {
  const options = getArrayFieldItemOptions(field);
  if (!field.itemOptions) return options[0];

  const optionKey =
    entry && typeof entry === "object" && "optionKey" in entry
      ? String((entry as SchemaArrayOptionValue).optionKey)
      : "";
  return (
    options.find((option) => getChildOptionKey(option) === optionKey) ??
    options[0]
  );
}

function getArrayEntryValue(entry: unknown, field: ConfigField) {
  if (!field.itemOptions) return entry;
  return entry && typeof entry === "object" && "value" in entry
    ? (entry as SchemaArrayOptionValue).value
    : "";
}

function getArrayEntryKey(entry: unknown, index: number) {
  if (entry && typeof entry === "object" && "id" in entry) {
    return String((entry as { id: unknown }).id);
  }
  return `item_${index}`;
}

function setArrayEntryValue(
  entry: unknown,
  field: ConfigField,
  value: unknown,
): unknown {
  if (!field.itemOptions) return value;
  const current =
    entry && typeof entry === "object"
      ? (entry as SchemaArrayOptionValue)
      : ({
          id: createArrayItemId(),
          optionKey: getChildOptionKey(getArrayFieldItemOptions(field)[0]),
          value: "",
        } satisfies SchemaArrayOptionValue);
  return { ...current, value };
}

function getArrayEntryLabel(entry: unknown, field: ConfigField, index: number) {
  const child = getArrayEntryChild(entry, field);
  return child.label ?? `配置项 ${index + 1}`;
}

function getObjectSummary(item: ConfigFieldChild, value: unknown): string {
  if (item.type !== "object") return formatSummaryValue(value);
  return getObjectSummaryFromFields(item.fields, item.summaryFields, value);
}

function getObjectSummaryFromFields(
  fields: ConfigField[],
  summaryFields: string[] | undefined,
  value: unknown,
): string {
  const objectValue =
    value && typeof value === "object" && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : {};
  const selectedFields = getObjectSummaryFields(fields, summaryFields);
  const summary = selectedFields
    .map((field): string => {
      const fieldValue = objectValue[field.key];
      const formatted: string =
        field.type === "object"
          ? getObjectSummaryFromFields(
              field.fields ?? [],
              field.summaryFields,
              fieldValue,
            )
          : formatSummaryValue(fieldValue);
      return formatted ? `${field.label}: ${formatted}` : "";
    })
    .filter(Boolean)
    .join(" · ");

  return summary || "未配置";
}

function getObjectSummaryFields(
  fields: ConfigField[],
  summaryFields: string[] | undefined,
): ConfigField[] {
  const summaryKeys = summaryFields?.length
    ? summaryFields
    : [fields[0]?.key].filter(Boolean);
  return summaryKeys
    .map((key) => fields.find((field) => field.key === key))
    .filter((field): field is ConfigField => Boolean(field));
}

function formatSummaryValue(value: unknown): string {
  if (value === undefined || value === null || value === "") return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  if (Array.isArray(value)) {
    if (value.length === 0) return "";
    const primitiveValues = value.filter(
      (entry) =>
        typeof entry === "string" ||
        typeof entry === "number" ||
        typeof entry === "boolean",
    );
    if (primitiveValues.length === value.length) {
      return primitiveValues.map(String).join(", ");
    }
    return `${value.length} 项`;
  }
  if (typeof value === "object") {
    const values = Object.values(value).map(formatSummaryValue).filter(Boolean);
    return values.join(" · ");
  }
  return "";
}

function inferArrayItemOption(
  value: unknown,
  options: ConfigFieldChild[],
): ConfigFieldChild {
  const normalized = stringifyConfigValue(value).trim();

  if (value && typeof value === "object" && !Array.isArray(value)) {
    const objectOption = options.find((option) => option.type === "object");
    if (objectOption) return objectOption;
  }

  if (
    (normalized.startsWith("$") || normalized.startsWith("!$")) &&
    options.some((option) => option.type === "reference")
  ) {
    return options.find((option) => option.type === "reference")!;
  }

  return options.find((option) => option.type !== "reference") ?? options[0];
}

function getChildOptionKey(item: ConfigFieldChild) {
  return item.optionKey ?? item.type;
}

function getChildLabel(item: ConfigFieldChild) {
  if (item.label) return item.label;
  if (item.type === "reference") return "引用";
  if (item.type === "object") return "对象";
  return "输入值";
}

function isEmptyConfigValue(value: unknown): boolean {
  if (value === undefined || value === null || value === "") return true;
  if (Array.isArray(value)) return value.length === 0;
  if (typeof value === "object") {
    const values = Object.values(value);
    return values.length === 0 || values.every(isEmptyConfigValue);
  }
  return false;
}

function createArrayItemFromString(value: string): ArrayItemValue {
  const normalized = value.trim();
  const withoutInvert = stripInvertPrefix(normalized);

  if (withoutInvert.startsWith("$")) {
    return {
      id: createArrayItemId(),
      syntax: "plugin",
      value: normalized,
      invert: normalized.startsWith("!"),
    };
  }

  return {
    id: createArrayItemId(),
    syntax: inferSyntaxFromValue(normalized),
    value: normalized,
  };
}

function serializeArrayItem(item: ArrayItemValue) {
  const trimmed = item.value.trim();
  if (!trimmed) return "";

  if (item.syntax === "plugin") {
    const tag = stripReferencePrefix(stripInvertPrefix(trimmed));
    if (!tag) return "";
    return `${item.invert ? "!" : ""}$${tag}`;
  }

  return trimmed;
}

function getSyntaxOptions(field: ConfigField): ArrayItemSyntax[] {
  const text =
    `${field.key} ${field.label} ${field.description ?? ""} ${field.placeholder ?? ""}`.toLowerCase();

  if (text.includes("provider 引用") || text.includes("只接受 $tag")) {
    return ["plugin"];
  }

  if (
    text.includes("matcher") ||
    text.includes("$tag") ||
    text.includes("quick setup")
  ) {
    return ["plugin", "quick", "value"];
  }

  if (
    text.includes("域名") ||
    text.includes("domain") ||
    text.includes("qname") ||
    text.includes("cname")
  ) {
    return ["domain", "plugin", "value"];
  }

  if (text.includes("ip") || text.includes("cidr")) {
    return ["value", "plugin"];
  }

  if (text.includes("文件") || text.includes("file")) {
    return ["value"];
  }

  return ["value"];
}

function inferDefaultSyntax(field: ConfigField): ArrayItemSyntax {
  return getSyntaxOptions(field)[0] ?? "value";
}

function inferSyntaxFromValue(value: string): ArrayItemSyntax {
  if (value.includes(":") && /^(full|domain|keyword|regexp):/.test(value)) {
    return "domain";
  }
  if (value.includes(" ")) return "quick";
  return "value";
}

function inferReferenceTypes(field: ConfigField): PluginType[] {
  const text =
    `${field.key} ${field.label} ${field.description ?? ""} ${field.placeholder ?? ""}`.toLowerCase();

  if (text.includes("executor")) return ["executor"];
  if (text.includes("matcher")) return ["matcher"];
  if (text.includes("provider")) return ["provider"];
  if (field.key === "sets" || field.key === "args")
    return ["provider", "matcher"];
  return ["provider", "matcher", "executor"];
}

function stringifyConfigValue(value: unknown) {
  return typeof value === "string" ? value : "";
}

function stripInvertPrefix(value: unknown) {
  const stringValue = stringifyConfigValue(value);
  return stringValue.startsWith("!") ? stringValue.slice(1) : stringValue;
}

function stripReferencePrefix(value: unknown) {
  const stringValue = stripInvertPrefix(value);
  return stringValue.startsWith("$") ? stringValue.slice(1) : stringValue;
}

function createArrayItemId() {
  return `item_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
}
