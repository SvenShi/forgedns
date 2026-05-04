/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

export interface YamlParseResult {
  value: unknown;
  error?: string;
}

interface YamlLine {
  indent: number;
  text: string;
  lineNumber: number;
}

export function stringifyPluginConfigYaml(value: unknown): string {
  if (value === undefined || value === null) return "{}";
  return stringifyYamlValue(value, 0).join("\n");
}

export function parsePluginConfigYaml(input: string): YamlParseResult {
  try {
    const lines = input
      .split("\n")
      .map((raw, index): YamlLine | null => {
        const withoutRightSpace = raw.replace(/\s+$/, "");
        if (!withoutRightSpace.trim() || withoutRightSpace.trimStart().startsWith("#")) {
          return null;
        }
        return {
          indent: withoutRightSpace.length - withoutRightSpace.trimStart().length,
          text: withoutRightSpace.trimStart(),
          lineNumber: index + 1,
        };
      })
      .filter((line): line is YamlLine => Boolean(line));

    if (lines.length === 0) return { value: {} };

    const parsed = parseBlock(lines, 0, lines[0].indent);
    if (parsed.nextIndex < lines.length) {
      return {
        value: undefined,
        error: `第 ${lines[parsed.nextIndex].lineNumber} 行缩进不属于当前配置块`,
      };
    }

    return { value: parsed.value };
  } catch (error) {
    return {
      value: undefined,
      error: error instanceof Error ? error.message : "YAML 解析失败",
    };
  }
}

function stringifyYamlValue(value: unknown, indent: number): string[] {
  if (Array.isArray(value)) {
    if (value.length === 0) return [`${spaces(indent)}[]`];
    return value.flatMap((entry) => stringifyArrayEntry(entry, indent));
  }

  if (isPlainRecord(value)) {
    const entries = Object.entries(value);
    if (entries.length === 0) return [`${spaces(indent)}{}`];
    return entries.flatMap(([key, entry]) => stringifyObjectEntry(key, entry, indent));
  }

  return [`${spaces(indent)}${formatScalar(value)}`];
}

function stringifyObjectEntry(key: string, value: unknown, indent: number): string[] {
  if (Array.isArray(value)) {
    if (value.length === 0) return [`${spaces(indent)}${key}: []`];
    return [
      `${spaces(indent)}${key}:`,
      ...value.flatMap((entry) => stringifyArrayEntry(entry, indent + 2)),
    ];
  }

  if (isPlainRecord(value)) {
    const entries = Object.entries(value);
    if (entries.length === 0) return [`${spaces(indent)}${key}: {}`];
    return [
      `${spaces(indent)}${key}:`,
      ...entries.flatMap(([childKey, entry]) =>
        stringifyObjectEntry(childKey, entry, indent + 2),
      ),
    ];
  }

  return [`${spaces(indent)}${key}: ${formatScalar(value)}`];
}

function stringifyArrayEntry(value: unknown, indent: number): string[] {
  if (Array.isArray(value)) {
    if (value.length === 0) return [`${spaces(indent)}- []`];
    return [
      `${spaces(indent)}-`,
      ...value.flatMap((entry) => stringifyArrayEntry(entry, indent + 2)),
    ];
  }

  if (isPlainRecord(value)) {
    const entries = Object.entries(value);
    if (entries.length === 0) return [`${spaces(indent)}- {}`];
    const [firstEntry, ...restEntries] = entries;
    const [firstKey, firstValue] = firstEntry;

    if (!Array.isArray(firstValue) && !isPlainRecord(firstValue)) {
      return [
        `${spaces(indent)}- ${firstKey}: ${formatScalar(firstValue)}`,
        ...restEntries.flatMap(([key, entry]) =>
          stringifyObjectEntry(key, entry, indent + 2),
        ),
      ];
    }

    return [
      `${spaces(indent)}- ${firstKey}:`,
      ...stringifyYamlValue(firstValue, indent + 4),
      ...restEntries.flatMap(([key, entry]) =>
        stringifyObjectEntry(key, entry, indent + 2),
      ),
    ];
  }

  return [`${spaces(indent)}- ${formatScalar(value)}`];
}

function parseBlock(
  lines: YamlLine[],
  startIndex: number,
  indent: number,
): { value: unknown; nextIndex: number } {
  const first = lines[startIndex];
  if (!first) return { value: {}, nextIndex: startIndex };
  if (first.indent < indent) return { value: {}, nextIndex: startIndex };
  if (first.indent !== indent) {
    throw new Error(`第 ${first.lineNumber} 行缩进应为 ${indent} 个空格`);
  }

  if (first.text.startsWith("-")) {
    return parseArray(lines, startIndex, indent);
  }

  return parseObject(lines, startIndex, indent);
}

function parseArray(
  lines: YamlLine[],
  startIndex: number,
  indent: number,
): { value: unknown[]; nextIndex: number } {
  const value: unknown[] = [];
  let index = startIndex;

  while (index < lines.length) {
    const line = lines[index];
    if (line.indent < indent) break;
    if (line.indent !== indent || !line.text.startsWith("-")) break;

    const rest = line.text.slice(1).trimStart();
    if (!rest) {
      const child = parseChildOrEmpty(lines, index + 1, indent + 2);
      value.push(child.value);
      index = child.nextIndex;
      continue;
    }

    const pair = splitYamlPair(rest);
    if (!pair) {
      value.push(parseScalar(rest, line.lineNumber));
      index += 1;
      continue;
    }

    const item: Record<string, unknown> = {};
    item[pair.key] = pair.value
      ? parseScalar(pair.value, line.lineNumber)
      : parseChildOrEmpty(lines, index + 1, indent + 4).value;

    const afterFirst =
      pair.value || !hasChildBlock(lines, index + 1, indent + 4)
        ? index + 1
        : parseChildOrEmpty(lines, index + 1, indent + 4).nextIndex;

    const restObject = parseObjectContinuation(lines, afterFirst, indent + 2);
    Object.assign(item, restObject.value);
    value.push(item);
    index = restObject.nextIndex;
  }

  return { value, nextIndex: index };
}

function parseObject(
  lines: YamlLine[],
  startIndex: number,
  indent: number,
): { value: Record<string, unknown>; nextIndex: number } {
  return parseObjectContinuation(lines, startIndex, indent);
}

function parseObjectContinuation(
  lines: YamlLine[],
  startIndex: number,
  indent: number,
): { value: Record<string, unknown>; nextIndex: number } {
  const value: Record<string, unknown> = {};
  let index = startIndex;

  while (index < lines.length) {
    const line = lines[index];
    if (line.indent < indent) break;
    if (line.indent !== indent || line.text.startsWith("-")) break;

    const pair = splitYamlPair(line.text);
    if (!pair) {
      throw new Error(`第 ${line.lineNumber} 行缺少 key: value 结构`);
    }

    if (pair.value) {
      value[pair.key] = parseScalar(pair.value, line.lineNumber);
      index += 1;
      continue;
    }

    const child = parseChildOrEmpty(lines, index + 1, indent + 2);
    value[pair.key] = child.value;
    index = child.nextIndex;
  }

  return { value, nextIndex: index };
}

function parseChildOrEmpty(
  lines: YamlLine[],
  startIndex: number,
  indent: number,
): { value: unknown; nextIndex: number } {
  const next = lines[startIndex];
  if (!next || next.indent < indent) return { value: {}, nextIndex: startIndex };
  return parseBlock(lines, startIndex, indent);
}

function hasChildBlock(lines: YamlLine[], startIndex: number, indent: number) {
  const next = lines[startIndex];
  return Boolean(next && next.indent >= indent);
}

function splitYamlPair(text: string): { key: string; value: string } | null {
  const index = text.indexOf(":");
  if (index <= 0) return null;
  return {
    key: text.slice(0, index).trim(),
    value: text.slice(index + 1).trim(),
  };
}

function parseScalar(value: string, lineNumber: number): unknown {
  if (value === "{}") return {};
  if (value === "[]") return [];
  if (value === "null" || value === "~") return null;
  if (value === "true") return true;
  if (value === "false") return false;
  if (/^-?\d+(\.\d+)?$/.test(value)) return Number(value);

  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    try {
      return value.startsWith('"')
        ? JSON.parse(value)
        : value.slice(1, -1).replace(/''/g, "'");
    } catch {
      throw new Error(`第 ${lineNumber} 行字符串引号不完整`);
    }
  }

  return value;
}

function formatScalar(value: unknown) {
  if (value === null || value === undefined) return "null";
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  const text = String(value);
  if (!text) return '""';
  if (/^[A-Za-z0-9_./@:+-]+$/.test(text) && !isAmbiguousScalar(text)) {
    return text;
  }
  return JSON.stringify(text);
}

function isAmbiguousScalar(value: string) {
  return (
    value === "true" ||
    value === "false" ||
    value === "null" ||
    value === "~" ||
    /^-?\d+(\.\d+)?$/.test(value)
  );
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function spaces(count: number) {
  return " ".repeat(count);
}
