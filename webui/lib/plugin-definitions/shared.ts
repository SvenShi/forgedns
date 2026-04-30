import type { PluginType } from "../types";
// Add new plugin kinds here first. The web UI catalog, create dialog, cards, and
// detail drawer all resolve their display metadata from these definitions.
export interface PluginKindDefinition {
  kind: string;
  type: PluginType;
  name: string;
  description: string;
  icon: string;
  configSchema: ConfigField[];
}
export type ConfigFieldType =
  | "text"
  | "number"
  | "select"
  | "textarea"
  | "switch"
  | "array"
  | "object"
  | "duration"
  | "json"
  | "record"
  | "reference";
export interface ConfigField {
  key: string;
  label: string;
  type: ConfigFieldType;
  placeholder?: string;
  description?: string;
  docs?: string;
  required?: boolean;
  default?: unknown;
  options?: {
    label: string;
    value: string;
  }[];
  referenceTypes?: PluginType[];
  referencePlugins?: string[];
  referencePrefix?: "$" | "";
  allowInvert?: boolean;
  asArray?: boolean;
  keyPlaceholder?: string;
  valuePlaceholder?: string;
  item?: ConfigFieldChild;
  itemOptions?: ConfigFieldChild[];
  fields?: ConfigField[];
  summaryFields?: string[];
}
export type ConfigFieldChild =
  | ({
      type: Exclude<ConfigFieldType, "array" | "object">;
    } & Omit<
      ConfigField,
      | "key"
      | "type"
      | "item"
      | "itemOptions"
      | "fields"
      | "label"
      | "required"
      | "summaryFields"
    > & {
        optionKey?: string;
        label?: string;
      })
  | {
      type: "array";
      optionKey?: string;
      label?: string;
      placeholder?: string;
      description?: string;
      item?: ConfigFieldChild;
      itemOptions?: ConfigFieldChild[];
    }
  | {
      type: "object";
      optionKey?: string;
      label?: string;
      placeholder?: string;
      description?: string;
      fields: ConfigField[];
      summaryFields?: string[];
    };
export type ConfigArrayItem = ConfigFieldChild;
export const executorRef = (
  key: string,
  label: string,
  required = true,
  referencePlugins?: string[],
  description?: string,
): ConfigField => ({
  key,
  label,
  type: "reference",
  required,
  referenceTypes: ["executor"],
  referencePlugins,
  description,
});
export const matcherListField = (
  description = "每行一个 matcher 表达式，支持 $tag、quick setup 和 ! 取反",
): ConfigField => ({
  key: "args",
  label: "匹配表达式",
  type: "array",
  required: true,
  placeholder: "$match_tag\nqname domain:example.com\n!$blocked",
  description,
  itemOptions: [
    {
      optionKey: "matcher_ref",
      type: "reference",
      label: "引用 matcher",
      referenceTypes: ["matcher"],
      referencePrefix: "$",
      allowInvert: true,
      placeholder: "match_tag",
    },
    {
      optionKey: "input",
      type: "text",
      label: "输入值",
      placeholder: "qname domain:example.com",
    },
  ],
});
export const stringArrayField = (
  key: string,
  label: string,
  placeholder: string,
  required = false,
  description = "每行一项",
  item?: ConfigFieldChild,
  itemOptions?: ConfigFieldChild[],
): ConfigField => ({
  key,
  label,
  type: "array",
  required,
  placeholder,
  description,
  item: itemOptions
    ? item
    : (item ?? inputArrayItem(placeholder.split("\n")[0])),
  itemOptions,
});
export const inputArrayItem = (placeholder: string): ConfigFieldChild => ({
  optionKey: "input",
  type: "text",
  label: "输入值",
  placeholder,
});
export const providerReferenceArrayItem = (
  placeholder: string,
): ConfigFieldChild => ({
  optionKey: "provider_ref",
  type: "reference",
  label: "引用 provider",
  referenceTypes: ["provider"],
  referencePrefix: "$",
  placeholder,
});
export const executorReferenceArrayItem = (
  placeholder: string,
): ConfigFieldChild => ({
  optionKey: "executor_ref",
  type: "reference",
  label: "引用 executor",
  referenceTypes: ["executor"],
  referencePrefix: "$",
  placeholder,
});
export const nftSetTargetFields: ConfigField[] = [
  {
    key: "table_family",
    label: "表 Family",
    type: "text",
    placeholder: "ip",
    required: true,
  },
  {
    key: "table_name",
    label: "表名",
    type: "text",
    placeholder: "mangle",
    required: true,
  },
  {
    key: "set_name",
    label: "Set 名称",
    type: "text",
    placeholder: "dns_v4",
    required: true,
  },
  { key: "mask", label: "前缀长度", type: "number", placeholder: "24" },
];
