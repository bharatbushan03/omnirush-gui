// #16 The agent's own setup: client and engine version, the bundled skills
// (name, version, hash), the skills and plugins installed for the user or
// the project (with their text files, capped), the configured MCP servers
// (name, command, arguments with secrets scrubbed, the package version when
// it can be resolved; environment and header NAMES only, never their
// values), and the model and non-secret settings (effort, variant).

import { createHash } from "node:crypto";
import { readdir, readFile, stat } from "node:fs/promises";
import { basename, join, relative, sep } from "node:path";

import { cleanText, cleanUrl, isTextBuffer, tildePath, tildeText, type PrivacyContext, type Scrubber } from "./privacy.js";
import { redactionRaw } from "./redact-policy.js";

export const MAX_SETUP_FILE_BYTES = 256 * 1024;
export const MAX_SETUP_TOTAL_BYTES = 2 * 1024 * 1024;
const MAX_FILES_PER_ITEM = 200;
const MAX_ITEMS = 200;
const MAX_CONFIG_BYTES = 1024 * 1024;
const SKIP_DIRS = new Set(["node_modules", ".git", "__pycache__", ".venv", "venv", "dist", "build", ".cache"]);

export type SetupModel = { provider_id: string | null; model_id: string | null; variant: string | null; agent: string | null };
export type SetupItem = { name: string; scope: "user" | "project" | "bundled"; root: string | null; version: string | null; files: number; bytes: number; sha256: string | null; source?: "file" | "npm" };
export type McpServer = {
  name: string;
  scope: string;
  type: "local" | "remote";
  command: string | null;
  args: string[];
  url: string | null;
  env_names: string[];
  header_names: string[];
  /** client-raw: the server's environment and header values as configured. */
  env?: Record<string, string>;
  headers?: Record<string, string>;
  package: string | null;
  version: string | null;
  version_source: "spec" | "installed" | null;
  enabled: boolean;
};
export type SetupFile = { kind: "skill" | "plugin"; owner: string; scope: string; rel: string; sha256: string; bytes: number; content: string | null; binary?: true; truncated?: true };
export type Setup = {
  client: string;
  app_version: string | null;
  engine_version: string | null;
  model: SetupModel | null;
  settings: Record<string, unknown>;
  bundled_skills: Array<{ name: string; version: string | null; sha256: string }>;
  skills: SetupItem[];
  plugins: SetupItem[];
  mcp_servers: McpServer[];
};

/** JSON with comments and trailing commas (opencode.jsonc). */
export function parseJsonc(text: string): unknown {
  let out = "";
  let inString = false;
  for (let i = 0; i < text.length; i += 1) {
    const char = text[i]!;
    if (inString) {
      out += char;
      if (char === "\\") out += text[++i] ?? "";
      else if (char === '"') inString = false;
      continue;
    }
    if (char === '"') {
      inString = true;
      out += char;
    } else if (char === "/" && text[i + 1] === "/") {
      while (i < text.length && text[i] !== "\n") i += 1;
      out += "\n";
    } else if (char === "/" && text[i + 1] === "*") {
      i += 2;
      while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) i += 1;
      i += 1;
    } else {
      out += char;
    }
  }
  return JSON.parse(out.replace(/,(\s*[}\]])/g, "$1"));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

async function readJsonFile(path: string): Promise<unknown> {
  try {
    const info = await stat(path);
    if (!info.isFile() || info.size > MAX_CONFIG_BYTES) return null;
    return parseJsonc(await readFile(path, "utf8"));
  } catch {
    return null;
  }
}

// --- packages of on-the-fly MCP commands -------------------------------------------

const RUNNERS: Record<string, "npm" | "pypi"> = { npx: "npm", bunx: "npm", pnpx: "npm", uvx: "pypi", pipx: "pypi" };

/** `npx -y @scope/pkg@1.2.3 --flag` → { package, version }; `uvx pkg==1.0` likewise. */
export function packageOfCommand(argv: string[]): { package: string; version: string | null; ecosystem: "npm" | "pypi" } | null {
  if (argv.length === 0) return null;
  let index = 0;
  let runner = basename(argv[0]!).replace(/\.(?:cmd|exe)$/i, "");
  if ((runner === "pnpm" || runner === "yarn") && argv[1] === "dlx") {
    runner = "npx";
    index = 1;
  } else if (runner === "npm" && argv[1] === "exec") {
    runner = "npx";
    index = 1;
  } else if (runner === "bun" && argv[1] === "x") {
    runner = "bunx";
    index = 1;
  } else if (runner === "pipx" && argv[1] === "run") {
    index = 1;
  } else if (runner === "uv" && argv[1] === "tool" && argv[2] === "run") {
    runner = "uvx";
    index = 2;
  }
  const ecosystem = RUNNERS[runner];
  if (!ecosystem) return null;
  for (let i = index + 1; i < argv.length; i += 1) {
    const word = argv[i]!;
    if (word === "--") continue;
    if (word.startsWith("-")) {
      if (/^--(?:package|from|with)$/.test(word) || word === "-p") {
        const value = argv[i + 1];
        if (value) return { ...splitSpec(value, ecosystem), ecosystem };
      }
      const eq = /^--(?:package|from)=(.+)$/.exec(word);
      if (eq) return { ...splitSpec(eq[1]!, ecosystem), ecosystem };
      continue;
    }
    return { ...splitSpec(word, ecosystem), ecosystem };
  }
  return null;
}

/** `@scope/pkg@1.2.3` → (@scope/pkg, 1.2.3); `pkg==1.0` / `pkg@1.0` (PyPI). */
export function splitSpec(spec: string, ecosystem: "npm" | "pypi"): { package: string; version: string | null } {
  if (ecosystem === "pypi") {
    const match = /^([A-Za-z0-9._\-[\],]+?)(?:==|@)([^\s]+)$/.exec(spec);
    return match ? { package: match[1]!, version: match[2]! } : { package: spec, version: null };
  }
  const at = spec.lastIndexOf("@");
  if (at > 0) return { package: spec.slice(0, at), version: spec.slice(at + 1) || null };
  return { package: spec, version: null };
}

/** The version of a package installed under a `node_modules` the command path points into. */
async function installedVersionOf(command: string, args: string[]): Promise<{ package: string; version: string } | null> {
  for (const word of [command, ...args]) {
    const match = /^(.*[\\/]node_modules[\\/])((?:@[^\\/]+[\\/])?[^\\/]+)/.exec(word);
    if (!match) continue;
    const manifest = await readJsonFile(join(match[1]!, match[2]!, "package.json"));
    if (isRecord(manifest) && typeof manifest.name === "string" && typeof manifest.version === "string") return { package: manifest.name, version: manifest.version };
  }
  return null;
}

/** An MCP argument for the record: secret-named flags' values dropped, URLs cleaned, home as `~`, scrubbed. */
export function cleanArgs(args: string[], privacy: PrivacyContext, scrub: Scrubber): string[] {
  const out: string[] = [];
  const secretFlag = /^--?[\w-]*(?:token|password|passwd|secret|api[-_]?key|apikey|auth|credential|bearer|private[-_]?key)[\w-]*$/i;
  for (let i = 0; i < args.length && i < 100; i += 1) {
    const arg = String(args[i]);
    const eq = /^(--?[\w-]+)=(.*)$/.exec(arg);
    // client-raw: every argument as configured (URLs and the home as `~` below).
    if (redactionRaw()) {
      out.push(cleanText(arg, privacy, scrub).slice(0, 1000));
      continue;
    }
    if (eq && secretFlag.test(eq[1]!)) {
      out.push(`${eq[1]}=[REDACTED]`);
      continue;
    }
    if (secretFlag.test(arg) && i + 1 < args.length) {
      out.push(arg, "[REDACTED]");
      i += 1;
      continue;
    }
    const urls = arg.replace(/[a-z][a-z0-9+.-]*:\/\/[^\s"']+/gi, (url) => cleanUrl(url));
    out.push(cleanText(urls, privacy, scrub).slice(0, 1000));
  }
  return out;
}

type RawServer = { name: string; scope: string; command: string | null; args: string[]; url: string | null; env: string[]; headers: string[]; enabled: boolean; type?: string; envValues?: Record<string, string>; headerValues?: Record<string, string> };

/** A config map's string values (numbers and booleans as text); other values are left out. */
function stringValues(map: unknown): Record<string, string> {
  if (!isRecord(map)) return {};
  return Object.fromEntries(Object.entries(map).flatMap(([key, value]) => (["string", "number", "boolean"].includes(typeof value) ? [[key, String(value)]] : [])));
}

/** opencode `mcp` entries: `{type: "local", command: [..], environment}` / `{type: "remote", url, headers}`. */
export function serversOfOpencodeConfig(config: unknown, scope: string): RawServer[] {
  if (!isRecord(config) || !isRecord(config.mcp)) return [];
  const out: RawServer[] = [];
  for (const [name, raw] of Object.entries(config.mcp)) {
    if (!isRecord(raw)) continue;
    const argv = Array.isArray(raw.command) ? raw.command.map(String) : typeof raw.command === "string" ? [raw.command, ...(Array.isArray(raw.args) ? raw.args.map(String) : [])] : [];
    out.push({
      name,
      scope,
      type: typeof raw.type === "string" ? raw.type : argv.length > 0 ? "local" : "remote",
      command: argv[0] ?? null,
      args: argv.slice(1),
      url: typeof raw.url === "string" ? raw.url : null,
      env: isRecord(raw.environment) ? Object.keys(raw.environment) : isRecord(raw.env) ? Object.keys(raw.env) : [],
      headers: isRecord(raw.headers) ? Object.keys(raw.headers) : [],
      envValues: stringValues(isRecord(raw.environment) ? raw.environment : raw.env),
      headerValues: stringValues(raw.headers),
      enabled: raw.enabled !== false,
    });
  }
  return out;
}

/** Claude-style `{mcpServers: {name: {command, args, env} | {url, headers}}}` (also a bare map). */
export function serversOfClaudeConfig(config: unknown, scope: string): RawServer[] {
  if (!isRecord(config)) return [];
  const map = isRecord(config.mcpServers) ? config.mcpServers : isRecord(config.servers) ? config.servers : null;
  if (!map) return [];
  const out: RawServer[] = [];
  for (const [name, raw] of Object.entries(map)) {
    if (!isRecord(raw)) continue;
    out.push({
      name,
      scope,
      command: typeof raw.command === "string" ? raw.command : null,
      args: Array.isArray(raw.args) ? raw.args.map(String) : [],
      url: typeof raw.url === "string" ? raw.url : null,
      env: isRecord(raw.env) ? Object.keys(raw.env) : [],
      headers: isRecord(raw.headers) ? Object.keys(raw.headers) : [],
      envValues: stringValues(raw.env),
      headerValues: stringValues(raw.headers),
      enabled: raw.disabled !== true && raw.enabled !== false,
    });
  }
  return out;
}

/** At most 100 values of 1000 characters each, the home as `~`. */
function rawValues(values: Record<string, string> | undefined, privacy: PrivacyContext, scrub: Scrubber): Record<string, string> {
  return Object.fromEntries(Object.entries(values ?? {}).slice(0, 100).map(([key, value]) => [cleanText(key, privacy, scrub).slice(0, 200), cleanText(value, privacy, scrub).slice(0, 1000)]));
}

async function describeServer(raw: RawServer, privacy: PrivacyContext, scrub: Scrubber): Promise<McpServer> {
  let pkg: string | null = null;
  let version: string | null = null;
  let versionSource: McpServer["version_source"] = null;
  if (raw.command) {
    const spec = packageOfCommand([raw.command, ...raw.args]);
    if (spec) {
      pkg = spec.package;
      if (spec.version && spec.version !== "latest") {
        version = spec.version;
        versionSource = "spec";
      }
    }
    if (!version) {
      const installed = await installedVersionOf(raw.command, raw.args);
      if (installed) {
        pkg = pkg ?? installed.package;
        version = installed.version;
        versionSource = "installed";
      }
    }
  }
  const nameOnly = (name: string) => cleanText(name, privacy, scrub).slice(0, 200);
  return {
    name: nameOnly(raw.name),
    scope: raw.scope,
    type: raw.url && !raw.command ? "remote" : "local",
    command: raw.command ? cleanText(raw.command, privacy, scrub).slice(0, 1000) : null,
    args: cleanArgs(raw.args, privacy, scrub),
    url: raw.url ? cleanText(cleanUrl(raw.url), privacy, scrub) : null,
    env_names: raw.env.slice(0, 100).map(nameOnly),
    header_names: raw.headers.slice(0, 100).map(nameOnly),
    // client-raw: the values too (the old rules keep names only).
    ...(redactionRaw() ? { env: rawValues(raw.envValues, privacy, scrub), headers: rawValues(raw.headerValues, privacy, scrub) } : {}),
    package: pkg ? nameOnly(pkg) : null,
    version: version ? nameOnly(version) : null,
    version_source: versionSource,
    enabled: raw.enabled,
  };
}

// --- skills and plugins --------------------------------------------------------------

type Budget = { bytes: number };

async function walkFiles(root: string, limit = MAX_FILES_PER_ITEM): Promise<string[]> {
  const out: string[] = [];
  const walk = async (dir: string, depth: number) => {
    if (out.length >= limit || depth > 6) return;
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (out.length >= limit) return;
      const path = join(dir, entry.name);
      if (entry.isDirectory() && !SKIP_DIRS.has(entry.name)) await walk(path, depth + 1);
      else if (entry.isFile()) out.push(path);
    }
  };
  await walk(root, 0);
  return out;
}

/** Reads an item's files: hashes all, keeps the text of each (scrubbed) while the session budget lasts. */
async function readItem(
  kind: SetupFile["kind"],
  owner: string,
  scope: string,
  root: string,
  paths: string[],
  options: { privacy: PrivacyContext; scrub: Scrubber; denied?: (path: string) => boolean },
  budget: Budget,
  files: SetupFile[],
): Promise<{ files: number; bytes: number; sha256: string }> {
  const itemHash = createHash("sha256");
  let bytes = 0;
  let count = 0;
  for (const path of paths) {
    const rel = relative(root, path).split(sep).join("/") || basename(path);
    if (options.denied?.(rel)) continue;
    let buffer: Buffer;
    try {
      const info = await stat(path);
      if (info.size > 16 * MAX_SETUP_FILE_BYTES) continue;
      buffer = await readFile(path);
    } catch {
      continue;
    }
    const sha256 = createHash("sha256").update(buffer).digest("hex");
    itemHash.update(`${rel}\0${sha256}\n`);
    bytes += buffer.length;
    count += 1;
    const text = isTextBuffer(buffer);
    let content: string | null = null;
    let truncated = false;
    if (text && budget.bytes > 0) {
      let raw = buffer.toString("utf8");
      if (Buffer.byteLength(raw) > MAX_SETUP_FILE_BYTES) {
        raw = buffer.subarray(0, MAX_SETUP_FILE_BYTES).toString("utf8").replace(/�$/, "");
        truncated = true;
      }
      if (Buffer.byteLength(raw) <= budget.bytes) {
        content = tildeText(options.scrub.content(rel, raw), options.privacy);
        budget.bytes -= Buffer.byteLength(raw);
      } else {
        truncated = true;
      }
    }
    files.push({
      kind,
      owner,
      scope,
      rel,
      sha256,
      bytes: buffer.length,
      content,
      ...(text ? {} : { binary: true as const }),
      ...(truncated ? { truncated: true as const } : {}),
    });
  }
  return { files: count, bytes, sha256: itemHash.digest("hex") };
}

/** Front-matter `version:` of a SKILL.md, else null. */
export function skillVersion(text: string): string | null {
  const front = /^---\r?\n([\s\S]*?)\r?\n---/.exec(text);
  const version = front ? /^\s*version:\s*["']?([^"'\n]+)["']?\s*$/m.exec(front[1]!) : null;
  return version ? version[1]!.trim() : null;
}

export type SetupOptions = {
  root: string;
  client: "cli" | "gui";
  appVersion?: string | null;
  engineVersion?: string | null;
  model?: SetupModel | null;
  settings?: Record<string, unknown>;
  /** Directories of the skills the app ships (each subfolder with a SKILL.md is one). */
  bundledSkillDirs?: string[];
  /** Skills the app ships inside its own bundle (name, version, hash), beside bundledSkillDirs. */
  bundledSkills?: Array<{ name: string; version: string | null; sha256: string }>;
  /** Extra opencode config files (the engine config the app writes: OPENCODE_CONFIG). */
  configFiles?: string[];
  /** Extra Claude-style MCP config files (the CLI's ~/.omnirush/mcp.json). */
  mcpFiles?: string[];
  privacy: PrivacyContext;
  scrub: Scrubber;
  /** The upload denylist (credential files): such a file is neither read nor hashed. */
  denied?: (relPath: string) => boolean;
  env?: NodeJS.ProcessEnv;
};

/** Non-secret engine settings: model, agents' model/variant/effort, and a few behaviour flags. */
export function settingsOfConfig(config: unknown): Record<string, unknown> {
  if (!isRecord(config)) return {};
  const out: Record<string, unknown> = {};
  for (const key of ["model", "small_model", "default_agent", "share", "autoupdate", "snapshot", "theme", "username"]) {
    if (key === "username" && !redactionRaw()) continue;
    if (typeof config[key] === "string" || typeof config[key] === "boolean") out[key] = config[key];
  }
  if (isRecord(config.agent)) {
    const agents: Record<string, unknown> = {};
    for (const [name, agent] of Object.entries(config.agent)) {
      if (!isRecord(agent)) continue;
      const picked: Record<string, unknown> = {};
      for (const key of ["model", "variant", "reasoningEffort", "temperature", "top_p", "mode", "disable"]) if (agent[key] !== undefined && typeof agent[key] !== "object") picked[key] = agent[key];
      if (isRecord(agent.options)) for (const key of ["reasoningEffort", "textVerbosity", "thinking"]) if (agent.options[key] !== undefined && typeof agent.options[key] !== "object") picked[key] = agent.options[key];
      if (Object.keys(picked).length > 0) agents[name] = picked;
    }
    if (Object.keys(agents).length > 0) out.agent = agents;
  }
  if (isRecord(config.permission)) out.permission = JSON.parse(JSON.stringify(config.permission));
  return out;
}

export async function collectSetup(options: SetupOptions): Promise<{ setup: Setup; files: SetupFile[] }> {
  const { privacy, scrub } = options;
  const env = options.env ?? process.env;
  const home = privacy.home;
  const xdg = env.XDG_CONFIG_HOME ?? (home ? join(home, ".config") : null);
  const files: SetupFile[] = [];
  const budget: Budget = { bytes: MAX_SETUP_TOTAL_BYTES };
  const where = (path: string) => (path.startsWith(options.root) ? `$PROJECT/${relative(options.root, path).split(sep).join("/")}` : tildePath(path, privacy));

  // Bundled skills: name, version and hash only (their text is the app's own).
  const bundled: Setup["bundled_skills"] = [...(options.bundledSkills ?? [])];
  for (const dir of options.bundledSkillDirs ?? []) {
    let names: string[] = [];
    try {
      names = (await readdir(dir, { withFileTypes: true })).filter((e) => e.isDirectory()).map((e) => e.name).sort();
    } catch {
      continue;
    }
    for (const name of names) {
      try {
        const text = await readFile(join(dir, name, "SKILL.md"));
        bundled.push({ name, version: skillVersion(text.toString("utf8")), sha256: createHash("sha256").update(text).digest("hex") });
      } catch {
        // No SKILL.md.
      }
    }
  }

  // Installed skills: every folder with a SKILL.md under the skill roots opencode (and Claude-style tools) read.
  const skillRoots: Array<{ dir: string; scope: "user" | "project" }> = [];
  for (const name of ["skill", "skills"]) {
    if (xdg) skillRoots.push({ dir: join(xdg, "opencode", name), scope: "user" });
    if (env.OPENCODE_CONFIG_DIR) skillRoots.push({ dir: join(env.OPENCODE_CONFIG_DIR, name), scope: "user" });
    skillRoots.push({ dir: join(options.root, ".opencode", name), scope: "project" });
  }
  if (home) {
    skillRoots.push({ dir: join(home, ".claude", "skills"), scope: "user" });
    skillRoots.push({ dir: join(home, ".agents", "skills"), scope: "user" });
  }
  skillRoots.push({ dir: join(options.root, ".claude", "skills"), scope: "project" });
  skillRoots.push({ dir: join(options.root, ".agents", "skills"), scope: "project" });
  const skills: SetupItem[] = [];
  const seenSkillDirs = new Set<string>();
  for (const { dir, scope } of skillRoots) {
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
      if (!entry.isDirectory() || skills.length >= MAX_ITEMS) continue;
      const skillDir = join(dir, entry.name);
      if (seenSkillDirs.has(skillDir)) continue;
      seenSkillDirs.add(skillDir);
      let version: string | null = null;
      try {
        version = skillVersion(await readFile(join(skillDir, "SKILL.md"), "utf8"));
      } catch {
        continue;
      }
      const summary = await readItem("skill", entry.name, scope, skillDir, await walkFiles(skillDir), options, budget, files);
      skills.push({ name: entry.name, scope, root: where(skillDir), version, ...summary });
    }
  }

  // Config files: opencode (global, project, the app's engine config) and Claude-style MCP files.
  const opencodeConfigs: Array<{ path: string; scope: string }> = [];
  for (const name of ["opencode.json", "opencode.jsonc", "config.json"]) {
    if (xdg) opencodeConfigs.push({ path: join(xdg, "opencode", name), scope: "user" });
  }
  for (const name of ["opencode.json", "opencode.jsonc", ".opencode/opencode.json", ".opencode/opencode.jsonc"]) opencodeConfigs.push({ path: join(options.root, name), scope: "project" });
  if (env.OPENCODE_CONFIG) opencodeConfigs.push({ path: env.OPENCODE_CONFIG, scope: "app" });
  for (const path of options.configFiles ?? []) opencodeConfigs.push({ path, scope: "app" });
  const claudeConfigs: Array<{ path: string; scope: string }> = [{ path: join(options.root, ".mcp.json"), scope: "project" }];
  for (const path of options.mcpFiles ?? []) claudeConfigs.push({ path, scope: "app" });

  const rawServers: RawServer[] = [];
  const pluginSpecs: Array<{ spec: string; scope: string }> = [];
  let settings: Record<string, unknown> = { ...(options.settings ?? {}) };
  const seenConfigs = new Set<string>();
  for (const { path, scope } of opencodeConfigs) {
    if (seenConfigs.has(path)) continue;
    seenConfigs.add(path);
    const config = await readJsonFile(path);
    if (!config) continue;
    rawServers.push(...serversOfOpencodeConfig(config, scope));
    if (isRecord(config) && Array.isArray(config.plugin)) for (const spec of config.plugin) if (typeof spec === "string") pluginSpecs.push({ spec, scope });
    const picked = settingsOfConfig(config);
    if (Object.keys(picked).length > 0) settings = { ...picked, ...settings, ...(scope === "app" ? {} : { [`${scope}_config`]: picked }) };
  }
  for (const { path, scope } of claudeConfigs) {
    if (seenConfigs.has(path)) continue;
    seenConfigs.add(path);
    rawServers.push(...serversOfClaudeConfig(await readJsonFile(path), scope));
  }
  const mcpServers: McpServer[] = [];
  for (const raw of rawServers.slice(0, MAX_ITEMS)) mcpServers.push(await describeServer(raw, privacy, scrub));

  // Plugins: npm plugins named in the config (version from the spec or the engine's install cache), and plugin files.
  const plugins: SetupItem[] = [];
  const cacheDirs = [env.XDG_CACHE_HOME ? join(env.XDG_CACHE_HOME, "opencode") : null, home ? join(home, ".cache", "opencode") : null].filter(Boolean) as string[];
  for (const { spec, scope } of pluginSpecs.slice(0, MAX_ITEMS)) {
    if (spec.startsWith("file:") || spec.startsWith("/") || spec.startsWith(".")) continue;
    const { package: name, version: wanted } = splitSpec(spec, "npm");
    let version = wanted && wanted !== "latest" ? wanted : null;
    if (!version) {
      for (const dir of cacheDirs) {
        const manifest = await readJsonFile(join(dir, "node_modules", name, "package.json"));
        if (isRecord(manifest) && typeof manifest.version === "string") {
          version = manifest.version;
          break;
        }
      }
    }
    plugins.push({ name: cleanText(name, privacy, scrub), scope: scope === "app" ? "user" : (scope as "user" | "project"), root: null, version, files: 0, bytes: 0, sha256: null, source: "npm" });
  }
  const pluginRoots: Array<{ dir: string; scope: "user" | "project" }> = [];
  for (const name of ["plugin", "plugins"]) {
    if (xdg) pluginRoots.push({ dir: join(xdg, "opencode", name), scope: "user" });
    pluginRoots.push({ dir: join(options.root, ".opencode", name), scope: "project" });
  }
  for (const { dir, scope } of pluginRoots) {
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
      if (plugins.length >= MAX_ITEMS) break;
      const path = join(dir, entry.name);
      const paths = entry.isDirectory() ? await walkFiles(path) : entry.isFile() ? [path] : [];
      if (paths.length === 0) continue;
      const owner = entry.name.replace(/\.(?:[cm]?[jt]s)$/, "");
      const summary = await readItem("plugin", owner, scope, entry.isDirectory() ? path : dir, paths, options, budget, files);
      plugins.push({ name: owner, scope, root: where(path), version: null, ...summary, source: "file" });
    }
  }

  return {
    setup: {
      client: options.client,
      app_version: options.appVersion ?? null,
      engine_version: options.engineVersion ?? null,
      model: options.model ?? null,
      settings: scrub.json(JSON.parse(JSON.stringify(settings))) as Record<string, unknown>,
      bundled_skills: bundled,
      skills,
      plugins,
      mcp_servers: mcpServers,
    },
    files,
  };
}
