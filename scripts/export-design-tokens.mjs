#!/usr/bin/env node

import { randomUUID } from "node:crypto";
import {
  chmod,
  mkdir,
  open,
  rename,
  unlink,
} from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { TextDecoder } from "node:util";

const LIMITS = Object.freeze({
  inputBytes: 1024 * 1024,
  outputBytes: 4 * 1024 * 1024,
  jsonDepth: 48,
  jsonValues: 20_000,
  stringCodeUnits: 16_384,
  groupDepth: 24,
  nodes: 4_096,
  tokens: 2_048,
  pathCodeUnits: 512,
  segmentCodeUnits: 64,
  descriptionCodeUnits: 2_048,
  fontFamilies: 32,
  fontFamilyCodeUnits: 128,
});

const SUPPORTED_TYPES = new Set([
  "color",
  "fontFamily",
  "dimension",
  "duration",
  "cubicBezier",
]);
const TOKEN_METADATA = new Set([
  "$value",
  "$type",
  "$description",
  "$deprecated",
]);
const GROUP_METADATA = new Set(["$type", "$description"]);
const TOKEN_SEGMENT = /^(?:[A-Za-z][A-Za-z0-9_-]*|[0-9][0-9_-]*)$/;
const ALIAS = /^\{([^{}]+)\}$/;
const NUMBER = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/y;

class TokenError extends Error {
  constructor(message) {
    super(message);
    this.name = "TokenError";
  }
}

class StrictJsonParser {
  constructor(text) {
    this.text = text;
    this.index = 0;
    this.values = 0;
  }

  parse() {
    this.skipWhitespace();
    const value = this.parseValue(0);
    this.skipWhitespace();
    if (this.index !== this.text.length) {
      this.fail("JSON 末尾存在多余内容");
    }
    return value;
  }

  parseValue(depth) {
    if (depth > LIMITS.jsonDepth) {
      this.fail(`JSON 嵌套超过 ${LIMITS.jsonDepth} 层`);
    }
    this.values += 1;
    if (this.values > LIMITS.jsonValues) {
      this.fail(`JSON 值数量超过 ${LIMITS.jsonValues}`);
    }

    const char = this.text[this.index];
    if (char === "{") return this.parseObject(depth);
    if (char === "[") return this.parseArray(depth);
    if (char === '"') return this.parseString();
    if (char === "t") return this.parseLiteral("true", true);
    if (char === "f") return this.parseLiteral("false", false);
    if (char === "n") return this.parseLiteral("null", null);
    if (char === "-" || (char >= "0" && char <= "9")) {
      return this.parseNumber();
    }
    this.fail("不是有效的 JSON 值");
  }

  parseObject(depth) {
    const result = Object.create(null);
    const keys = new Set();
    this.index += 1;
    this.skipWhitespace();
    if (this.consume("}")) return result;

    while (true) {
      if (this.text[this.index] !== '"') {
        this.fail("对象键必须是 JSON 字符串");
      }
      const key = this.parseString();
      if (keys.has(key)) {
        this.fail(`对象包含重复键 ${JSON.stringify(key)}`);
      }
      keys.add(key);
      this.skipWhitespace();
      this.expect(":");
      this.skipWhitespace();
      result[key] = this.parseValue(depth + 1);
      this.skipWhitespace();
      if (this.consume("}")) return result;
      this.expect(",");
      this.skipWhitespace();
    }
  }

  parseArray(depth) {
    const result = [];
    this.index += 1;
    this.skipWhitespace();
    if (this.consume("]")) return result;

    while (true) {
      result.push(this.parseValue(depth + 1));
      this.skipWhitespace();
      if (this.consume("]")) return result;
      this.expect(",");
      this.skipWhitespace();
    }
  }

  parseString() {
    const start = this.index;
    this.index += 1;

    while (this.index < this.text.length) {
      const code = this.text.charCodeAt(this.index);
      const char = this.text[this.index];
      if (code < 0x20) this.fail("字符串包含未转义的控制字符");
      if (char === '"') {
        this.index += 1;
        let decoded;
        try {
          decoded = JSON.parse(this.text.slice(start, this.index));
        } catch {
          this.fail("字符串转义无效");
        }
        if (hasUnpairedSurrogate(decoded)) {
          this.fail("字符串包含未配对的 UTF-16 代理项");
        }
        if (decoded.length > LIMITS.stringCodeUnits) {
          this.fail(`字符串长度超过 ${LIMITS.stringCodeUnits}`);
        }
        return decoded;
      }
      if (char === "\\") {
        this.index += 1;
        const escape = this.text[this.index];
        if (escape === "u") {
          const digits = this.text.slice(this.index + 1, this.index + 5);
          if (!/^[0-9A-Fa-f]{4}$/.test(digits)) {
            this.fail("Unicode 转义无效");
          }
          this.index += 5;
          continue;
        }
        if (!['"', "\\", "/", "b", "f", "n", "r", "t"].includes(escape)) {
          this.fail("字符串转义无效");
        }
        this.index += 1;
        continue;
      }
      this.index += 1;
    }
    this.fail("字符串没有结束引号");
  }

  parseNumber() {
    NUMBER.lastIndex = this.index;
    const match = NUMBER.exec(this.text);
    if (!match) this.fail("数字格式无效");
    if (match[0].length > 128) this.fail("数字字面量过长");
    this.index = NUMBER.lastIndex;
    const value = Number(match[0]);
    if (!Number.isFinite(value)) this.fail("数字超出有限范围");
    return value;
  }

  parseLiteral(literal, value) {
    if (!this.text.startsWith(literal, this.index)) {
      this.fail(`无效字面量，应为 ${literal}`);
    }
    this.index += literal.length;
    return value;
  }

  skipWhitespace() {
    while (
      this.text[this.index] === " " ||
      this.text[this.index] === "\t" ||
      this.text[this.index] === "\n" ||
      this.text[this.index] === "\r"
    ) {
      this.index += 1;
    }
  }

  consume(expected) {
    if (this.text[this.index] !== expected) return false;
    this.index += 1;
    return true;
  }

  expect(expected) {
    if (!this.consume(expected)) this.fail(`应为 ${JSON.stringify(expected)}`);
  }

  fail(message) {
    throw new TokenError(`${message}（字符位置 ${this.index}）`);
  }
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasUnpairedSurrogate(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return true;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function hasOwn(value, key) {
  return Object.prototype.hasOwnProperty.call(value, key);
}

function tokenLabel(pathSegments) {
  return pathSegments.length === 0 ? "<root>" : pathSegments.join(".");
}

function validateDescription(value, label) {
  if (typeof value !== "string" || value.length > LIMITS.descriptionCodeUnits) {
    throw new TokenError(
      `${label} 的 $description 必须是至多 ${LIMITS.descriptionCodeUnits} 字符的字符串`,
    );
  }
}

function validateType(value, label) {
  if (typeof value !== "string" || !SUPPORTED_TYPES.has(value)) {
    throw new TokenError(`${label} 使用了不支持的 $type ${JSON.stringify(value)}`);
  }
  return value;
}

function validateSegment(segment, parentLabel) {
  if (
    segment.length > LIMITS.segmentCodeUnits ||
    !TOKEN_SEGMENT.test(segment)
  ) {
    throw new TokenError(
      `${parentLabel} 下的名称 ${JSON.stringify(segment)} 不符合安全名称规则`,
    );
  }
}

function cssSegment(segment) {
  return segment
    .replace(/([a-z0-9])([A-Z])/g, "$1-$2")
    .replaceAll("_", "-")
    .toLowerCase();
}

function cssVariable(pathSegments) {
  return `--${pathSegments.map(cssSegment).join("-")}`;
}

function flattenTokens(root) {
  if (!isRecord(root)) throw new TokenError("令牌源根节点必须是 JSON 对象");

  const tokens = [];
  const cssNames = new Map();
  const caseFoldedPaths = new Map();
  const stack = [
    { node: root, pathSegments: [], inheritedType: undefined, depth: 0 },
  ];
  let nodes = 0;

  while (stack.length > 0) {
    const current = stack.pop();
    const { node, pathSegments, inheritedType, depth } = current;
    const label = tokenLabel(pathSegments);
    if (!isRecord(node)) throw new TokenError(`${label} 必须是对象`);

    nodes += 1;
    if (nodes > LIMITS.nodes) {
      throw new TokenError(`令牌树节点数量超过 ${LIMITS.nodes}`);
    }
    if (hasOwn(node, "$description")) {
      validateDescription(node.$description, label);
    }

    const declaredType = hasOwn(node, "$type")
      ? validateType(node.$type, label)
      : undefined;
    const effectiveType = declaredType ?? inheritedType;
    const isToken = hasOwn(node, "$value");
    const entries = Object.entries(node);

    if (isToken) {
      if (pathSegments.length === 0) {
        throw new TokenError("根节点不能直接作为令牌");
      }
      for (const [key] of entries) {
        if (key.startsWith("$") && !TOKEN_METADATA.has(key)) {
          throw new TokenError(`${label} 包含不支持的令牌字段 ${key}`);
        }
        if (!key.startsWith("$")) {
          throw new TokenError(`${label} 同时包含 $value 和子节点 ${key}`);
        }
      }
      if (hasOwn(node, "$deprecated")) {
        const deprecated = node.$deprecated;
        if (
          typeof deprecated !== "boolean" &&
          !(
            typeof deprecated === "string" &&
            deprecated.length > 0 &&
            deprecated.length <= LIMITS.descriptionCodeUnits
          )
        ) {
          throw new TokenError(`${label} 的 $deprecated 必须是布尔值或有界说明`);
        }
      }
      if (!effectiveType) throw new TokenError(`${label} 缺少 $type 或继承类型`);

      const pathKey = pathSegments.join(".");
      const folded = pathKey.toLowerCase();
      if (caseFoldedPaths.has(folded)) {
        throw new TokenError(
          `${pathKey} 与 ${caseFoldedPaths.get(folded)} 仅大小写不同`,
        );
      }
      caseFoldedPaths.set(folded, pathKey);

      const variable = cssVariable(pathSegments);
      if (cssNames.has(variable)) {
        throw new TokenError(
          `${pathKey} 与 ${cssNames.get(variable)} 会生成相同 CSS 变量 ${variable}`,
        );
      }
      cssNames.set(variable, pathKey);
      tokens.push({
        path: pathKey,
        pathSegments,
        type: effectiveType,
        value: node.$value,
        variable,
        reference: undefined,
      });
      if (tokens.length > LIMITS.tokens) {
        throw new TokenError(`令牌数量超过 ${LIMITS.tokens}`);
      }
      continue;
    }

    for (const [key] of entries) {
      if (key.startsWith("$") && !GROUP_METADATA.has(key)) {
        throw new TokenError(`${label} 包含不支持的分组字段 ${key}`);
      }
    }
    const children = entries.filter(([key]) => !key.startsWith("$"));
    if (children.length === 0) throw new TokenError(`${label} 是空分组`);
    if (depth >= LIMITS.groupDepth) {
      throw new TokenError(`令牌分组深度超过 ${LIMITS.groupDepth}`);
    }

    children.sort(([left], [right]) => compareText(left, right));
    for (let index = children.length - 1; index >= 0; index -= 1) {
      const [segment, child] = children[index];
      validateSegment(segment, label);
      const childPath = [...pathSegments, segment];
      if (childPath.join(".").length > LIMITS.pathCodeUnits) {
        throw new TokenError(`${tokenLabel(childPath)} 的路径过长`);
      }
      stack.push({
        node: child,
        pathSegments: childPath,
        inheritedType: effectiveType,
        depth: depth + 1,
      });
    }
  }

  if (tokens.length === 0) throw new TokenError("令牌源中没有令牌");
  return tokens;
}

function compareText(left, right) {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

function validateExactKeys(value, required, optional, label) {
  if (!isRecord(value)) throw new TokenError(`${label} 必须是对象`);
  const allowed = new Set([...required, ...optional]);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) throw new TokenError(`${label} 包含未知字段 ${key}`);
  }
  for (const key of required) {
    if (!hasOwn(value, key)) throw new TokenError(`${label} 缺少字段 ${key}`);
  }
}

function finiteNumber(value, label, minimum, maximum) {
  if (
    typeof value !== "number" ||
    !Number.isFinite(value) ||
    value < minimum ||
    value > maximum
  ) {
    throw new TokenError(`${label} 必须是 ${minimum} 到 ${maximum} 之间的有限数字`);
  }
  return value;
}

function formatNumber(value) {
  return Object.is(value, -0) ? "0" : String(value);
}

function validateColor(value, label) {
  validateExactKeys(value, ["colorSpace", "components"], ["alpha", "hex"], label);
  if (value.colorSpace !== "srgb") {
    throw new TokenError(`${label} 目前只支持可直接导出 CSS 的 srgb 色彩空间`);
  }
  if (!Array.isArray(value.components) || value.components.length !== 3) {
    throw new TokenError(`${label}.components 必须恰好包含 3 个分量`);
  }
  const components = value.components.map((component, index) =>
    finiteNumber(component, `${label}.components[${index}]`, 0, 1),
  );
  const alpha = hasOwn(value, "alpha")
    ? finiteNumber(value.alpha, `${label}.alpha`, 0, 1)
    : 1;
  if (hasOwn(value, "hex")) {
    if (typeof value.hex !== "string" || !/^#[0-9A-Fa-f]{6}$/.test(value.hex)) {
      throw new TokenError(`${label}.hex 必须是 #RRGGBB`);
    }
    const expected = `#${components
      .map((component) => Math.round(component * 255).toString(16).padStart(2, "0"))
      .join("")}`;
    if (value.hex.toLowerCase() !== expected) {
      throw new TokenError(`${label}.hex 与 srgb 分量不一致（应为 ${expected}）`);
    }
  }
  return `color(srgb ${components.map(formatNumber).join(" ")} / ${formatNumber(alpha)})`;
}

function validateFontFamily(value, label) {
  const families = typeof value === "string" ? [value] : value;
  if (
    !Array.isArray(families) ||
    families.length === 0 ||
    families.length > LIMITS.fontFamilies
  ) {
    throw new TokenError(`${label} 必须包含 1 到 ${LIMITS.fontFamilies} 个字体族`);
  }
  const seen = new Set();
  return families
    .map((family, index) => {
      if (
        typeof family !== "string" ||
        family.length === 0 ||
        family !== family.trim() ||
        family.length > LIMITS.fontFamilyCodeUnits ||
        hasForbiddenFontFamilyCharacter(family)
      ) {
        throw new TokenError(`${label}[${index}] 不是安全的有界字体族名称`);
      }
      const folded = family.toLowerCase();
      if (seen.has(folded)) throw new TokenError(`${label} 包含重复字体族 ${family}`);
      seen.add(folded);
      return cssFontFamily(family);
    })
    .join(", ");
}

function hasForbiddenFontFamilyCharacter(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (
      code <= 0x1f ||
      code === 0x7f ||
      value[index] === "{" ||
      value[index] === "}"
    ) {
      return true;
    }
  }
  return false;
}

function cssFontFamily(family) {
  const cssWideKeywords = new Set([
    "inherit",
    "initial",
    "revert",
    "revert-layer",
    "unset",
  ]);
  const identifier = /^(?:[A-Za-z_][A-Za-z0-9_-]*|-[A-Za-z_][A-Za-z0-9_-]*)$/;
  if (identifier.test(family) && !cssWideKeywords.has(family.toLowerCase())) {
    return family;
  }
  return `"${family.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
}

function validateDimension(value, label) {
  validateExactKeys(value, ["value", "unit"], [], label);
  const amount = finiteNumber(value.value, `${label}.value`, -1_000_000, 1_000_000);
  if (value.unit !== "px" && value.unit !== "rem") {
    throw new TokenError(`${label}.unit 必须是 px 或 rem`);
  }
  return `${formatNumber(amount)}${value.unit}`;
}

function validateDuration(value, label) {
  validateExactKeys(value, ["value", "unit"], [], label);
  const amount = finiteNumber(value.value, `${label}.value`, 0, 86_400_000);
  if (value.unit !== "ms" && value.unit !== "s") {
    throw new TokenError(`${label}.unit 必须是 ms 或 s`);
  }
  const milliseconds = value.unit === "s" ? amount * 1_000 : amount;
  if (milliseconds > 86_400_000) throw new TokenError(`${label} 不能超过 24 小时`);
  return `${formatNumber(amount)}${value.unit}`;
}

function validateCubicBezier(value, label) {
  if (!Array.isArray(value) || value.length !== 4) {
    throw new TokenError(`${label} 必须恰好包含 4 个数字`);
  }
  const points = value.map((point, index) =>
    finiteNumber(
      point,
      `${label}[${index}]`,
      index === 0 || index === 2 ? 0 : -100,
      index === 0 || index === 2 ? 1 : 100,
    ),
  );
  return `cubic-bezier(${points.map(formatNumber).join(", ")})`;
}

function parseReference(value, label) {
  if (typeof value !== "string") return undefined;
  const match = ALIAS.exec(value);
  if (!match) return undefined;
  if (value.length > LIMITS.pathCodeUnits + 2) {
    throw new TokenError(`${label} 的引用路径过长`);
  }
  const pathSegments = match[1].split(".");
  if (pathSegments.some((segment) => segment.length === 0)) {
    throw new TokenError(`${label} 的引用包含空路径段`);
  }
  for (const segment of pathSegments) validateSegment(segment, `${label} 的引用`);
  return pathSegments.join(".");
}

function validateTokenValues(tokens) {
  const byPath = new Map(tokens.map((token) => [token.path, token]));
  for (const token of tokens) {
    const label = `${token.path} ($value)`;
    token.reference = parseReference(token.value, label);
    if (token.reference !== undefined) {
      const target = byPath.get(token.reference);
      if (!target) throw new TokenError(`${token.path} 引用了不存在的 ${token.reference}`);
      if (target.type !== token.type) {
        throw new TokenError(
          `${token.path} 的 ${token.type} 引用不能指向 ${target.type} 令牌 ${target.path}`,
        );
      }
      token.cssValue = `var(${target.variable})`;
      continue;
    }

    switch (token.type) {
      case "color":
        token.cssValue = validateColor(token.value, label);
        break;
      case "fontFamily":
        token.cssValue = validateFontFamily(token.value, label);
        break;
      case "dimension":
        token.cssValue = validateDimension(token.value, label);
        break;
      case "duration":
        token.cssValue = validateDuration(token.value, label);
        break;
      case "cubicBezier":
        token.cssValue = validateCubicBezier(token.value, label);
        break;
      default:
        throw new TokenError(`${token.path} 使用了无法导出的类型 ${token.type}`);
    }
  }

  validateReferenceCycles(tokens, byPath);
}

function validateReferenceCycles(tokens, byPath) {
  const complete = new Set();
  for (const start of tokens) {
    if (complete.has(start.path)) continue;
    const trail = [];
    const positions = new Map();
    let current = start;
    while (current && !complete.has(current.path)) {
      if (positions.has(current.path)) {
        const cycle = trail.slice(positions.get(current.path)).concat(current.path);
        throw new TokenError(`令牌引用形成循环：${cycle.join(" -> ")}`);
      }
      positions.set(current.path, trail.length);
      trail.push(current.path);
      current = current.reference ? byPath.get(current.reference) : undefined;
    }
    for (const pathKey of trail) complete.add(pathKey);
  }
}

function renderCss(tokens) {
  const sorted = [...tokens].sort((left, right) => compareText(left.path, right.path));
  const lines = [
    "/* Generated from tokens.tokens.json; edit the token source, not this file. */",
    ":root {",
  ];
  for (const token of sorted) lines.push(`  ${token.variable}: ${token.cssValue};`);
  lines.push("}", "");
  const result = lines.join("\n");
  if (Buffer.byteLength(result, "utf8") > LIMITS.outputBytes) {
    throw new TokenError(`生成的 CSS 超过 ${LIMITS.outputBytes} 字节`);
  }
  return result;
}

async function loadTokenSource(sourcePath) {
  const bytes = await readBoundedRegularFile(
    sourcePath,
    LIMITS.inputBytes,
    "令牌源",
  );
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new TokenError("令牌源不是有效 UTF-8");
  }
  const root = new StrictJsonParser(text).parse();
  const tokens = flattenTokens(root);
  validateTokenValues(tokens);
  return renderCss(tokens);
}

async function readBoundedRegularFile(filePath, maximumBytes, label) {
  const handle = await open(filePath, "r");
  try {
    const metadata = await handle.stat();
    if (!metadata.isFile()) throw new TokenError(`${label}必须是普通文件`);
    if (metadata.size > maximumBytes) {
      throw new TokenError(`${label}超过 ${maximumBytes} 字节`);
    }

    const chunks = [];
    let total = 0;
    while (true) {
      const remaining = maximumBytes + 1 - total;
      if (remaining <= 0) throw new TokenError(`${label}超过 ${maximumBytes} 字节`);
      const chunk = Buffer.allocUnsafe(Math.min(64 * 1024, remaining));
      const { bytesRead } = await handle.read(chunk, 0, chunk.length, null);
      if (bytesRead === 0) break;
      chunks.push(chunk.subarray(0, bytesRead));
      total += bytesRead;
    }
    return Buffer.concat(chunks, total);
  } finally {
    await handle.close();
  }
}

async function writeAtomically(destination, content) {
  const directory = path.dirname(destination);
  await mkdir(directory, { recursive: true });
  const temporary = path.join(
    directory,
    `.${path.basename(destination)}.${process.pid}.${randomUUID()}.tmp`,
  );
  let handle;
  try {
    handle = await open(temporary, "wx", 0o600);
    await handle.writeFile(content, "utf8");
    await handle.sync();
    await handle.close();
    handle = undefined;
    await chmod(temporary, 0o644);
    await rename(temporary, destination);
  } finally {
    if (handle) await handle.close().catch(() => {});
    await unlink(temporary).catch(() => {});
  }
}

function usage() {
  return [
    "用法：",
    "  node scripts/export-design-tokens.mjs <source.json> <output.css>",
    "  node scripts/export-design-tokens.mjs --check <source.json> <output.css>",
  ].join("\n");
}

async function main() {
  const args = process.argv.slice(2);
  const check = args[0] === "--check";
  if (check) args.shift();
  if (args.length !== 2 || args.includes("--check") || args.includes("--help")) {
    throw new TokenError(usage());
  }

  const sourcePath = path.resolve(args[0]);
  const outputPath = path.resolve(args[1]);
  if (sourcePath === outputPath) {
    throw new TokenError("令牌源与 CSS 输出不能是同一个文件");
  }
  const generated = await loadTokenSource(sourcePath);

  if (check) {
    let existing;
    try {
      existing = await readBoundedRegularFile(
        outputPath,
        LIMITS.outputBytes,
        "生成的 CSS",
      );
    } catch (error) {
      if (error?.code === "ENOENT") {
        throw new TokenError(`缺少生成文件 ${args[1]}，请先运行 pnpm tokens:build`);
      }
      throw error;
    }
    const expected = Buffer.from(generated, "utf8");
    if (!existing.equals(expected)) {
      throw new TokenError(
        `${args[1]} 与令牌源的确定性输出不一致，请运行 pnpm tokens:build`,
      );
    }
    process.stdout.write(`令牌检查通过：${args[1]}\n`);
    return;
  }

  await writeAtomically(outputPath, generated);
  process.stdout.write(`已生成 ${args[1]}\n`);
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`design tokens: ${message}\n`);
  process.exitCode = 1;
});
