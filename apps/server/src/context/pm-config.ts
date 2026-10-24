// #17 Package-manager and toolchain configuration outside the project:
// ~/.npmrc, ~/.yarnrc(.yml), pip.conf / pip.ini, uv.toml,
// ~/.cargo/config.toml, ~/.gradle/gradle.properties, ~/.m2/settings.xml,
// .condarc and `go env`. Only keys and non-secret values are kept: every
// key naming a credential (auth, token, password, _auth, credential, …) is
// dropped entirely, URLs lose their userinfo and secret query values, and
// the secret scrub runs on top of what is left.

import { readFile, stat } from "node:fs/promises";
import { join } from "node:path";

import { quietEnv, runTool, type Runner } from "./exec.js";
import { cleanText, cleanUrl, isSecretKey, tildePath, type PrivacyContext, type Scrubber } from "./privacy.js";
import { redactionRaw } from "./redact-policy.js";

const MAX_CONFIG_FILE_BYTES = 256 * 1024;
const MAX_ENTRIES_PER_FILE = 200;
const MAX_VALUE_CHARS = 1_000;

export type PmTool = "npm" | "yarn" | "pip" | "uv" | "cargo" | "gradle" | "maven" | "conda";
export type PmConfigFile = { tool: PmTool; path: string; entries: Record<string, string>; dropped_keys: number };
export type PmConfig = { files: PmConfigFile[]; go_env?: Record<string, string> };

export const GO_ENV_KEYS = ["GOPROXY", "GOPRIVATE", "GONOPROXY", "GONOSUMDB", "GONOSUMCHECK", "GOSUMDB", "GOINSECURE", "GOFLAGS", "GO111MODULE", "GOTOOLCHAIN"];

/** `key=value` lines (npmrc, gradle.properties); `#` and `;` comments; [sections] prefix their keys. */
export function parseIni(text: string, separators = /[=:]/): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  let section = "";
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) continue;
    const header = /^\[([^\]]+)\]$/.exec(line);
    if (header) {
      section = header[1]!.trim();
      continue;
    }
    const match = separators.exec(line);
    if (!match || match.index === 0) continue;
    const key = line.slice(0, match.index).trim();
    let value = line.slice(match.index + 1).trim();
    value = value.replace(/^"(.*)"$/, "$1").replace(/^'(.*)'$/, "$1");
    out.push([section ? `${section}.${key}` : key, value]);
  }
  return out;
}

/** npmrc keys may hold `=` in a scoped registry (`//host/:_authToken=x`): the first `=` separates. */
export function parseNpmrc(text: string): Array<[string, string]> {
  return parseIni(text, /=/);
}

/** Yarn 1 `.yarnrc`: `key "value"` or `key value`. */
export function parseYarnrc(text: string): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const match = /^("?)([^"\s]+)\1\s+(.+)$/.exec(line);
    if (match) out.push([match[2]!, match[3]!.trim().replace(/^"(.*)"$/, "$1")]);
  }
  return out;
}

/**
 * A light YAML reader for the flat configs (.yarnrc.yml, .condarc): nested
 * mappings become dotted keys, `- item` lists become `key[0]`, values are
 * taken as written (quotes dropped). Anchors, flow maps and multi-line
 * scalars are kept as raw text.
 */
export function parseSimpleYaml(text: string): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  const stack: Array<{ indent: number; key: string; index: number }> = [];
  for (const raw of text.split(/\r?\n/)) {
    if (!raw.trim() || raw.trim().startsWith("#")) continue;
    const indent = raw.length - raw.trimStart().length;
    const line = raw.trim();
    while (stack.length > 0 && stack[stack.length - 1]!.indent >= indent && !(line.startsWith("- ") && stack[stack.length - 1]!.indent === indent)) stack.pop();
    const prefix = stack.map((entry) => entry.key).join(".");
    if (line.startsWith("- ")) {
      const parent = stack[stack.length - 1];
      const index = parent ? parent.index++ : 0;
      const value = line.slice(2).trim().replace(/^["'](.*)["']$/, "$1");
      out.push([`${prefix}[${index}]`, value]);
      continue;
    }
    const match = /^("?)([^":]+)\1\s*:(?:\s+(.*))?$/.exec(line);
    if (!match) continue;
    const key = match[2]!.trim();
    const value = (match[3] ?? "").trim().replace(/\s+#.*$/, "");
    if (value === "" || value === "|" || value === ">") {
      stack.push({ indent, key, index: 0 });
      continue;
    }
    out.push([prefix ? `${prefix}.${key}` : key, value.replace(/^["'](.*)["']$/, "$1")]);
  }
  return out;
}

/** A light TOML reader (uv.toml, cargo config): `[table]`, `[[array]]` and `key = value`. */
export function parseSimpleToml(text: string): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  let table = "";
  const arrays = new Map<string, number>();
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const arrayHeader = /^\[\[([^\]]+)\]\]$/.exec(line);
    if (arrayHeader) {
      const name = arrayHeader[1]!.trim();
      const index = arrays.get(name) ?? 0;
      arrays.set(name, index + 1);
      table = `${name}[${index}]`;
      continue;
    }
    const header = /^\[([^\]]+)\]$/.exec(line);
    if (header) {
      table = header[1]!.trim().replace(/"/g, "");
      continue;
    }
    const match = /^([^=]+?)\s*=\s*(.*)$/.exec(line);
    if (!match) continue;
    const key = match[1]!.trim().replace(/"/g, "");
    const value = match[2]!.trim().replace(/\s+#[^"']*$/, "").replace(/^"(.*)"$/, "$1").replace(/^'(.*)'$/, "$1");
    out.push([table ? `${table}.${key}` : key, value]);
  }
  return out;
}

/**
 * Maven settings.xml: mirrors (id, url, mirrorOf), proxies (protocol, host,
 * port, nonProxyHosts), repository URLs, server ids and the offline/local
 * repository flags. Usernames, passwords, private keys and passphrases are
 * never read.
 */
export function parseMavenSettings(text: string): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  const noComments = text.replace(/<!--[\s\S]*?-->/g, "");
  const tag = (block: string, name: string) => new RegExp(`<${name}>\\s*([^<]*?)\\s*</${name}>`).exec(block)?.[1] ?? null;
  const blocks = (name: string) => [...noComments.matchAll(new RegExp(`<${name}>([\\s\\S]*?)</${name}>`, "g"))].map((m) => m[1]!);
  for (const flag of ["localRepository", "offline", "interactiveMode"]) {
    const value = tag(noComments, flag);
    if (value !== null) out.push([flag, value]);
  }
  blocks("mirror").forEach((block, index) => {
    for (const name of ["id", "url", "mirrorOf"]) {
      const value = tag(block, name);
      if (value !== null) out.push([`mirrors[${index}].${name}`, value]);
    }
  });
  blocks("proxy").forEach((block, index) => {
    for (const name of ["id", "active", "protocol", "host", "port", "nonProxyHosts"]) {
      const value = tag(block, name);
      if (value !== null) out.push([`proxies[${index}].${name}`, value]);
    }
  });
  blocks("repository").concat(blocks("pluginRepository")).forEach((block, index) => {
    for (const name of ["id", "url"]) {
      const value = tag(block, name);
      if (value !== null) out.push([`repositories[${index}].${name}`, value]);
    }
  });
  blocks("server").forEach((block, index) => {
    const id = tag(block, "id");
    if (id !== null) out.push([`servers[${index}].id`, id]);
  });
  return out;
}

/** Whether a config entry must be dropped whole: its key names a credential. */
export function isDroppedKey(key: string): boolean {
  // `//registry.npmjs.org/:_authToken`, `npmScopes.acme.npmAuthToken`, `registries.x.token`, `pip.index-url` stays.
  const parts = key.split(/[.:/[\]]+/).filter(Boolean);
  return parts.some((part) => isSecretKey(part)) || isSecretKey(key.split(/[:/]/).at(-1) ?? key);
}

/** A kept value: URLs cleaned, the home as `~`, secrets scrubbed, at most 1000 chars. */
function cleanValue(value: string, privacy: PrivacyContext, scrub: Scrubber): string {
  const urls = value.replace(/[a-z][a-z0-9+.-]*:\/\/[^\s,;"']+/gi, (url) => cleanUrl(url));
  const cleaned = cleanText(urls, privacy, scrub);
  return cleaned.length > MAX_VALUE_CHARS ? `${cleaned.slice(0, MAX_VALUE_CHARS)}…` : cleaned;
}

export function filterEntries(pairs: Array<[string, string]>, privacy: PrivacyContext, scrub: Scrubber): { entries: Record<string, string>; dropped: number } {
  const entries: Record<string, string> = {};
  let dropped = 0;
  for (const [key, value] of pairs) {
    if (!redactionRaw() && isDroppedKey(key)) {
      dropped += 1;
      continue;
    }
    if (Object.keys(entries).length >= MAX_ENTRIES_PER_FILE) break;
    const cleanKey = cleanText(key, privacy, scrub);
    entries[cleanKey] = cleanValue(value, privacy, scrub);
  }
  return { entries, dropped };
}

type Source = { tool: PmTool; path: string; parse: (text: string) => Array<[string, string]> };

/** The user/global config files each tool reads, for this platform. */
export function configSources(home: string, platform: NodeJS.Platform, env: NodeJS.ProcessEnv = process.env): Source[] {
  const appData = env.APPDATA ?? join(home, "AppData", "Roaming");
  const xdg = env.XDG_CONFIG_HOME ?? join(home, ".config");
  const sources: Source[] = [
    { tool: "npm", path: env.NPM_CONFIG_USERCONFIG ?? env.npm_config_userconfig ?? join(home, ".npmrc"), parse: parseNpmrc },
    { tool: "yarn", path: join(home, ".yarnrc"), parse: parseYarnrc },
    { tool: "yarn", path: join(home, ".yarnrc.yml"), parse: parseSimpleYaml },
    { tool: "uv", path: join(platform === "win32" ? appData : xdg, "uv", "uv.toml"), parse: parseSimpleToml },
    { tool: "cargo", path: join(env.CARGO_HOME ?? join(home, ".cargo"), "config.toml"), parse: parseSimpleToml },
    { tool: "cargo", path: join(env.CARGO_HOME ?? join(home, ".cargo"), "config"), parse: parseSimpleToml },
    { tool: "gradle", path: join(env.GRADLE_USER_HOME ?? join(home, ".gradle"), "gradle.properties"), parse: (text) => parseIni(text) },
    { tool: "maven", path: join(home, ".m2", "settings.xml"), parse: parseMavenSettings },
    { tool: "conda", path: join(home, ".condarc"), parse: parseSimpleYaml },
    { tool: "conda", path: join(home, ".conda", ".condarc"), parse: parseSimpleYaml },
    { tool: "conda", path: join(xdg, "conda", ".condarc"), parse: parseSimpleYaml },
  ];
  if (platform === "win32") {
    sources.push({ tool: "pip", path: join(appData, "pip", "pip.ini"), parse: (text) => parseIni(text) });
    sources.push({ tool: "pip", path: join(home, "pip", "pip.ini"), parse: (text) => parseIni(text) });
  } else {
    sources.push({ tool: "pip", path: join(xdg, "pip", "pip.conf"), parse: (text) => parseIni(text) });
    sources.push({ tool: "pip", path: join(home, ".pip", "pip.conf"), parse: (text) => parseIni(text) });
    sources.push({ tool: "pip", path: "/etc/pip.conf", parse: (text) => parseIni(text) });
    if (platform === "darwin") sources.push({ tool: "pip", path: join(home, "Library", "Application Support", "pip", "pip.conf"), parse: (text) => parseIni(text) });
  }
  if (env.PIP_CONFIG_FILE) sources.push({ tool: "pip", path: env.PIP_CONFIG_FILE, parse: (text) => parseIni(text) });
  if (env.UV_CONFIG_FILE) sources.push({ tool: "uv", path: env.UV_CONFIG_FILE, parse: parseSimpleToml });
  if (env.CONDARC) sources.push({ tool: "conda", path: env.CONDARC, parse: parseSimpleYaml });
  return sources;
}

export type PmConfigOptions = {
  privacy: PrivacyContext;
  scrub: Scrubber;
  platform?: NodeJS.Platform;
  env?: NodeJS.ProcessEnv;
  run?: Runner;
  resolve?: (command: string) => string | null;
};

export async function collectPmConfig(options: PmConfigOptions): Promise<PmConfig> {
  const home = options.privacy.home;
  const platform = options.platform ?? process.platform;
  const files: PmConfigFile[] = [];
  if (home) {
    const seen = new Set<string>();
    for (const source of configSources(home, platform, options.env)) {
      if (seen.has(source.path)) continue;
      seen.add(source.path);
      try {
        const info = await stat(source.path);
        if (!info.isFile() || info.size > MAX_CONFIG_FILE_BYTES) continue;
        const text = await readFile(source.path, "utf8");
        const { entries, dropped } = filterEntries(source.parse(text), options.privacy, options.scrub);
        if (Object.keys(entries).length === 0 && dropped === 0) continue;
        files.push({ tool: source.tool, path: tildePath(source.path, options.privacy), entries, dropped_keys: dropped });
      } catch {
        // Not there.
      }
    }
  }
  const result: PmConfig = { files };
  // GOTOOLCHAIN=local: `go env` never downloads the toolchain a go.mod or GOTOOLCHAIN asks for.
  const go = await runTool("go", ["env", "-json", ...GO_ENV_KEYS], {
    env: quietEnv({ GOTOOLCHAIN: "local" }),
    timeoutMs: 5_000,
    maxBytes: 64 * 1024,
    ...(options.run ? { run: options.run } : {}),
    ...(options.resolve ? { resolve: options.resolve } : {}),
  });
  if (go && go.code === 0) {
    try {
      const parsed = JSON.parse(go.stdout) as Record<string, unknown>;
      const pairs = Object.entries(parsed).filter(([, value]) => typeof value === "string" && value !== "") as Array<[string, string]>;
      const { entries } = filterEntries(pairs, options.privacy, options.scrub);
      if (Object.keys(entries).length > 0) result.go_env = entries;
    } catch {
      // Not JSON (a very old go).
    }
  }
  return result;
}
