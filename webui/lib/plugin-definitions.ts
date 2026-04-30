export type {
  ConfigArrayItem,
  ConfigField,
  ConfigFieldChild,
  ConfigFieldType,
  PluginKindDefinition,
} from "./plugin-definitions/shared";
import type { PluginType } from "./types";
import type {
  ConfigField,
  PluginKindDefinition,
} from "./plugin-definitions/shared";
import { executorPluginDefinitions } from "./plugin-definitions/executor";
import { matcherPluginDefinitions } from "./plugin-definitions/matcher";
import { providerPluginDefinitions } from "./plugin-definitions/provider";
import { serverPluginDefinitions } from "./plugin-definitions/server";
import { pluginFieldDocs } from "./plugin-definitions/docs";

function withFieldDocs(definition: PluginKindDefinition): PluginKindDefinition {
  const docs = (pluginFieldDocs as Record<string, Record<string, string>>)[
    definition.kind
  ];
  if (!docs) return definition;

  return {
    ...definition,
    configSchema: applyDocsToFields(definition.configSchema, docs),
  };
}

function applyDocsToFields(
  fields: ConfigField[],
  docs: Record<string, string>,
  parentPath?: string,
): ConfigField[] {
  return fields.map((field) => {
    const path = parentPath ? `${parentPath}.${field.key}` : field.key;
    const arrayPath = parentPath ? `${parentPath}[].${field.key}` : field.key;
    const fieldDocs = docs[path] ?? docs[arrayPath] ?? docs[field.key];

    return {
      ...field,
      docs: fieldDocs ?? field.docs,
      fields: field.fields
        ? applyDocsToFields(field.fields, docs, path)
        : field.fields,
      item:
        field.item && field.item.type === "object"
          ? {
              ...field.item,
              fields: applyDocsToFields(field.item.fields, docs, path),
            }
          : field.item,
      itemOptions: field.itemOptions?.map((item) =>
        item.type === "object"
          ? {
              ...item,
              fields: applyDocsToFields(item.fields, docs, path),
            }
          : item,
      ),
    };
  });
}

export const pluginKindDefinitions: PluginKindDefinition[] = [
  ...serverPluginDefinitions,
  ...executorPluginDefinitions,
  ...matcherPluginDefinitions,
  ...providerPluginDefinitions,
].map(withFieldDocs);

export function getPluginKindsByType(type: PluginType): PluginKindDefinition[] {
  return pluginKindDefinitions.filter((p) => p.type === type);
}

export function getPluginKindDefinition(
  kind: string,
): PluginKindDefinition | undefined {
  return pluginKindDefinitions.find((p) => p.kind === kind);
}
