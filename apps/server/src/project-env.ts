// What a session's project expects from its environment, for
// `environment.toolchain` (see toolchain.ts): the names in its .env files
// (values only when clearly not secret), the environment variable names its
// code reads, the host (OS release, WSL, CPU) and the shell (name, version,
// version managers, PATH with the home directory and user name removed).
//
// Nothing here spawns a version-manager shim. Every value that could hold a
// secret is left out; when in doubt, the value is omitted and only the name
// is kept.

import { gitChildEnv } from "./git-env.js";
import { execFile } from "node:child_process";
import { readFile, readdir, lstat } from "node:fs/promises";
import { cpus, homedir, release as osRelease, userInfo } from "node:os";
import nodePath from "node:path";

import { gitSkipReason } from "./command-guard.js";
import { redactionRaw } from "./context/redact-policy.js";

export const MAX_ENV_FILES = 50;
export const MAX_ENV_KEYS_PER_FILE = 500;
export const MAX_ENV_FILE_BYTES = 256 * 1024;
export const MAX_ENV_NAMES_READ = 500;
export const MAX_PATH_ENTRIES = 64;
const MAX_ENV_VALUE_CHARS = 100;
const MAX_WALK_DEPTH = 6;
const MAX_WALK_DIRECTORIES = 5_000;
const MAX_SCANNED_FILES = 20_000;
const MAX_SCANNED_FILE_BYTES = 512 * 1024;
const MAX_SCANNED_TOTAL_BYTES = 32 * 1024 * 1024;

/** Folders never searched for .env files or source: dependencies, environments, build output. */
const SKIPPED_DIRS = new Set([
  "node_modules", ".git", ".hg", ".svn", ".venv", "venv", "env", ".tox", ".nox", "__pycache__", ".mypy_cache",
  ".pytest_cache", ".ruff_cache", "dist", "build", "out", "target", "vendor", ".next", ".nuxt", ".cache", ".turbo",
  "coverage", ".gradle", ".idea", ".terraform", "bower_components", "Pods", ".dart_tool", ".pnpm-store", ".yarn",
]);

export type EnvKey = { name: string; value?: string };
export type EnvFile = { path: string; keys: EnvKey[]; keys_truncated?: boolean };

export type SecretChecks = {
  /** The capture's secret-name rule (workspace-sync isSecretAssignmentKey). */
  isSecretName?: (name: string) => boolean;
  /** The capture's text scrub; a value it would change is never kept. */
  scrubText?: (value: string) => string;
  /** The capture's path denylist; a denied file's code is never scanned. */
  isDenied?: (path: string) => boolean;
};

// --- .env files ------------------------------------------------------------------

const ENV_FILE = /^\.env(?:\..+)?$/;
/** Documented placeholders, normal project files: not environment files. */
const ENV_TEMPLATE = /\.(?:example|sample|template)$/i;
// Names whose value is never kept, on top of the capture's own secret rule:
// anything that might be a credential, a personal detail or an identifier.
const SECRETISH_NAME = /KEY|SECRET|TOKEN|PASS|PWD|AUTH|CRED|PRIVATE|CERT|SALT|SESSION|COOKIE|SIGN|DSN|HASH|SEED|OTP|PIN|CODE|ACCOUNT|USER|LOGIN|EMAIL|MAIL|PHONE|TENANT|WEBHOOK|ENCRYPT|BEARER|JWT|API/i;
const BOOLEAN = /^(?:true|false|yes|no|on|off)$/i;
const NUMBER = /^-?\d{1,6}(?:\.\d{1,4})?$/;
const LOCAL_URL = /^(?:https?|wss?|postgres(?:ql)?|mysql|mariadb|redis|rediss|mongodb|amqp|nats|grpc):\/\/(?:localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0|host\.docker\.internal)(?::\d{1,5})?(?:\/[A-Za-z0-9._~\/-]*)?$/i;
const SAFE_WORDS = new Set([
  "development", "dev", "production", "prod", "staging", "stage", "test", "testing", "local", "preview", "qa", "ci",
  "sandbox", "release", "debug", "info", "warn", "warning", "error", "trace", "fatal", "silent", "verbose", "none",
  "utc", "json", "text", "pretty", "auto", "always", "never", "enabled", "disabled", "localhost", "0.0.0.0",
  "127.0.0.1", "memory", "disk", "sqlite", "postgres", "postgresql", "mysql", "redis", "docker", "node", "python",
  "http", "https", "light", "dark", "default", "strict", "lax", "inline", "headless",
]);

/**
 * The value of `name=raw` when it is clearly not a secret: a boolean, a short
 * number (a port), a well-known enum word (`NODE_ENV=development`) or a
 * localhost URL without credentials. Undefined otherwise, and always for a
 * secret-looking name or a value the scrub would touch.
 */
export function safeEnvValue(name: string, raw: string, checks: SecretChecks = {}): string | undefined {
  // client-raw: every plain value as written (the size cap stays).
  if (redactionRaw()) return rawEnvValue(raw);
  if (checks.isSecretName?.(name) || SECRETISH_NAME.test(name)) return undefined;
  const value = unquoteEnvValue(raw);
  if (value === undefined || value.length > MAX_ENV_VALUE_CHARS) return undefined;
  const safe = value === ""
    || BOOLEAN.test(value)
    || NUMBER.test(value)
    || SAFE_WORDS.has(value.toLowerCase())
    || (LOCAL_URL.test(value) && !value.includes("@"));
  if (!safe) return undefined;
  if (checks.scrubText && checks.scrubText(value) !== value) return undefined;
  return value;
}

/** client-raw: a dotenv right-hand side as written: a quoted value's text (`$`, `\\` and all), else the text before an inline comment. */
function rawEnvValue(raw: string): string | undefined {
  const text = raw.trim();
  const quote = text[0];
  if (quote === '"' || quote === "'" || quote === "`") {
    const end = text.indexOf(quote, 1);
    return end < 0 ? undefined : text.slice(1, end);
  }
  return text.replace(/\s+#.*$/, "").trim();
}

/** The literal value of a dotenv right-hand side, or undefined when it is not one plain value. */
function unquoteEnvValue(raw: string): string | undefined {
  const text = raw.trim();
  const quote = text[0];
  if (quote === '"' || quote === "'" || quote === "`") {
    const end = text.indexOf(quote, 1);
    if (end < 0) return undefined;
    const rest = text.slice(end + 1).trim();
    if (rest && !rest.startsWith("#")) return undefined;
    const inner = text.slice(1, end);
    return /\$\{?|\\/.test(inner) ? undefined : inner;
  }
  // An inline comment starts at a `#` after whitespace.
  const value = text.replace(/\s+#.*$/, "").trim();
  return /[$\\\s"'`]/.test(value) ? undefined : value;
}

/** The keys of one dotenv text, in order, each with its value only when safeEnvValue keeps it. */
export function parseEnvFile(text: string, checks: SecretChecks = {}): { keys: EnvKey[]; truncated: boolean } {
  const keys: EnvKey[] = [];
  const seen = new Set<string>();
  let openQuote: string | null = null;
  let truncated = false;
  // client-raw: a multi-line quoted value (a PEM key) is kept whole.
  const raw = redactionRaw();
  let multiline: { key: EnvKey; lines: string[] } | null = null;
  for (const line of text.split(/\r?\n/)) {
    if (openQuote) {
      // Inside a multi-line quoted value (a PEM key): its lines are never keys.
      const end = line.indexOf(openQuote);
      if (multiline) {
        multiline.lines.push(end < 0 ? line : line.slice(0, end));
        if (end >= 0) multiline.key.value = multiline.lines.join("\n");
      }
      if (end >= 0) {
        openQuote = null;
        multiline = null;
      }
      continue;
    }
    const match = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=(.*)$/.exec(line);
    if (!match) continue;
    const name = match[1]!;
    const rhs = match[2]!.trim();
    const quote = rhs[0];
    if ((quote === '"' || quote === "'" || quote === "`") && rhs.indexOf(quote, 1) < 0) openQuote = quote;
    if (seen.has(name)) continue;
    if (keys.length >= MAX_ENV_KEYS_PER_FILE) {
      truncated = true;
      continue;
    }
    seen.add(name);
    if (raw && openQuote) {
      const key: EnvKey = { name };
      multiline = { key, lines: [rhs.slice(1)] };
      keys.push(key);
      continue;
    }
    const value = openQuote ? undefined : safeEnvValue(name, rhs, checks);
    keys.push(value === undefined ? { name } : { name, value });
  }
  return { keys, truncated };
}

/** Every .env file under `root` (template files excluded), as project-relative paths. */
export async function findEnvFiles(root: string): Promise<string[]> {
  const found: string[] = [];
  let directories = 0;
  const walk = async (dir: string, depth: number): Promise<void> => {
    if (found.length >= MAX_ENV_FILES || directories >= MAX_WALK_DIRECTORIES) return;
    directories += 1;
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (found.length >= MAX_ENV_FILES) return;
      if (entry.isFile() && ENV_FILE.test(entry.name) && !ENV_TEMPLATE.test(entry.name)) {
        found.push(nodePath.relative(root, nodePath.join(dir, entry.name)).split(nodePath.sep).join("/"));
      }
    }
    if (depth >= MAX_WALK_DEPTH) return;
    for (const entry of entries) {
      if (entry.isDirectory() && !SKIPPED_DIRS.has(entry.name) && !entry.name.startsWith(".")) await walk(nodePath.join(dir, entry.name), depth + 1);
    }
  };
  await walk(root, 0);
  return found;
}

export async function collectEnvFiles(root: string, checks: SecretChecks = {}): Promise<EnvFile[]> {
  const files: EnvFile[] = [];
  for (const path of await findEnvFiles(root)) {
    const full = nodePath.join(root, path);
    try {
      const info = await lstat(full);
      if (!info.isFile() || info.size > MAX_ENV_FILE_BYTES) {
        files.push({ path, keys: [], keys_truncated: info.isFile() });
        continue;
      }
      const { keys, truncated } = parseEnvFile(await readFile(full, "utf8"), checks);
      files.push(truncated ? { path, keys, keys_truncated: true } : { path, keys });
    } catch {
      // Unreadable: left out.
    }
  }
  return files;
}

// --- environment variable names the code reads -----------------------------------

const NAME = "([A-Za-z_][A-Za-z0-9_]{0,127})";
const Q = "[\"'`]";
const ENV_READS = new RegExp([
  `process\\.env\\.${NAME}`,
  `process\\.env\\[\\s*${Q}${NAME}${Q}\\s*\\]`,
  `import\\.meta\\.env\\.${NAME}`,
  `Bun\\.env\\.${NAME}`,
  `Deno\\.env\\.get\\(\\s*${Q}${NAME}${Q}`,
  `os\\.environ\\[\\s*${Q}${NAME}${Q}\\s*\\]`,
  `os\\.environ\\.get\\(\\s*${Q}${NAME}${Q}`,
  `getenv\\(\\s*${Q}${NAME}${Q}`,
  `env::var(?:_os)?\\(\\s*"${NAME}"`,
  `env!\\(\\s*"${NAME}"`,
  `os\\.(?:Getenv|LookupEnv)\\(\\s*"${NAME}"`,
  `System\\.getenv\\(\\s*"${NAME}"`,
  `\\bENV(?:\\.fetch\\(\\s*|\\[\\s*)${Q}${NAME}${Q}`,
  `\\$_ENV\\[\\s*${Q}${NAME}${Q}`,
  `Environment\\.GetEnvironmentVariable\\(\\s*"${NAME}"`,
].join("|"), "g");
const CODE_EXTENSIONS = new Set([
  ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".vue", ".svelte", ".astro", ".py", ".pyi", ".rs",
  ".go", ".java", ".kt", ".kts", ".scala", ".groovy", ".rb", ".php", ".cs", ".fs", ".c", ".cc", ".cpp", ".cxx",
  ".h", ".hpp", ".swift", ".ex", ".exs", ".dart", ".lua", ".jl", ".r",
]);

/** The environment variable names in `text` read through a known accessor. */
export function envNamesIn(text: string, into: Set<string> = new Set()): Set<string> {
  ENV_READS.lastIndex = 0;
  for (const match of text.matchAll(ENV_READS)) {
    const name = match.slice(1).find((group) => group !== undefined);
    if (name) into.add(name);
  }
  return into;
}

async function projectSourceFiles(root: string, checks: SecretChecks): Promise<string[]> {
  const keep = (path: string) => CODE_EXTENSIONS.has(nodePath.extname(path).toLowerCase()) && !checks.isDenied?.(path)
    && !path.split("/").some((part) => SKIPPED_DIRS.has(part));
  if (!(await gitSkipReason())) {
    const listed = await new Promise<string[] | null>((resolvePromise) => {
      execFile("git", ["-C", root, "ls-files", "-co", "--exclude-standard", "-z"], {
        encoding: "buffer", maxBuffer: 16 * 1024 * 1024, timeout: 10_000, windowsHide: true,
        env: gitChildEnv({ GIT_OPTIONAL_LOCKS: "0" }),
      }, (error, stdout) => resolvePromise(error ? null : Buffer.from(stdout).toString("utf8").split("\0").filter(Boolean)));
    });
    if (listed) return listed.filter(keep).slice(0, MAX_SCANNED_FILES);
  }
  const files: string[] = [];
  let directories = 0;
  const walk = async (dir: string, depth: number): Promise<void> => {
    if (files.length >= MAX_SCANNED_FILES || directories >= MAX_WALK_DIRECTORIES || depth > MAX_WALK_DEPTH * 2) return;
    directories += 1;
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = nodePath.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!SKIPPED_DIRS.has(entry.name) && !entry.name.startsWith(".")) await walk(full, depth + 1);
      } else if (entry.isFile()) {
        const path = nodePath.relative(root, full).split(nodePath.sep).join("/");
        if (keep(path)) files.push(path);
      }
    }
  };
  await walk(root, 0);
  return files.slice(0, MAX_SCANNED_FILES);
}

/** The environment variable names the project's code reads, sorted, capped at MAX_ENV_NAMES_READ. */
export async function collectEnvNamesRead(root: string, checks: SecretChecks = {}): Promise<{ names: string[]; truncated: boolean }> {
  const names = new Set<string>();
  let total = 0;
  for (const path of await projectSourceFiles(root, checks)) {
    if (total >= MAX_SCANNED_TOTAL_BYTES) break;
    try {
      const full = nodePath.join(root, path);
      const info = await lstat(full);
      if (!info.isFile() || info.size > MAX_SCANNED_FILE_BYTES) continue;
      total += info.size;
      envNamesIn(await readFile(full, "utf8"), names);
    } catch {
      // Gone or unreadable.
    }
  }
  const sorted = [...names].sort();
  return { names: sorted.slice(0, MAX_ENV_NAMES_READ), truncated: sorted.length > MAX_ENV_NAMES_READ };
}

// --- host ------------------------------------------------------------------------

export type SystemInfo = {
  distro_id?: string;
  distro_version?: string;
  distro_name?: string;
  macos_version?: string;
  macos_build?: string;
  windows_build?: string;
  wsl: boolean;
  cpu_model?: string;
  cpu_logical_cores?: number;
};

/** Fields of an os-release file. */
export function parseOsRelease(text: string): Record<string, string> {
  const fields: Record<string, string> = {};
  for (const line of text.split(/\r?\n/)) {
    const match = /^([A-Z_]+)=(.*)$/.exec(line.trim());
    if (match) fields[match[1]!] = match[2]!.replace(/^(["'])(.*)\1$/, "$2");
  }
  return fields;
}

/** `sw_vers` output: ProductVersion and BuildVersion. */
export function parseSwVers(text: string): { version?: string; build?: string } {
  const field = (key: string) => new RegExp(`^${key}:\\s*(\\S+)`, "m").exec(text)?.[1];
  return { version: field("ProductVersion"), build: field("BuildVersion") };
}

export function isWsl(procVersion: string | null, env: NodeJS.ProcessEnv = process.env): boolean {
  return Boolean(env.WSL_DISTRO_NAME || env.WSL_INTEROP) || /microsoft|wsl/i.test(procVersion ?? "");
}

export type RunText = (file: string, args: string[]) => Promise<string | null>;

export async function systemInfo(run: RunText, platform: NodeJS.Platform = process.platform): Promise<SystemInfo> {
  const info: SystemInfo = { wsl: false };
  const clip = (value: string | undefined, limit = 128) => (value ? value.trim().slice(0, limit) || undefined : undefined);
  if (platform === "linux") {
    const osRelease = await readFile("/etc/os-release", "utf8").catch(() => readFile("/usr/lib/os-release", "utf8").catch(() => ""));
    const fields = parseOsRelease(osRelease);
    info.distro_id = clip(fields.ID, 64);
    info.distro_version = clip(fields.VERSION_ID, 64);
    info.distro_name = clip(fields.PRETTY_NAME);
    info.wsl = isWsl(await readFile("/proc/version", "utf8").catch(() => null));
  } else if (platform === "darwin") {
    // /usr/bin/sw_vers is part of the OS, not a Command Line Tools shim.
    const output = await run("/usr/bin/sw_vers", []);
    const { version, build } = parseSwVers(output ?? "");
    info.macos_version = clip(version, 32);
    info.macos_build = clip(build, 32);
  } else if (platform === "win32") {
    info.windows_build = clip(osRelease().split(".")[2], 16);
  }
  try {
    const list = cpus();
    info.cpu_model = clip(list[0]?.model?.replace(/\s+/g, " "));
    info.cpu_logical_cores = list.length || undefined;
  } catch {
    // No CPU information in this runtime.
  }
  for (const key of Object.keys(info) as (keyof SystemInfo)[]) if (info[key] === undefined) delete info[key];
  return info;
}

// --- shell -------------------------------------------------------------------------

export type ShellInfo = {
  name?: string;
  version?: string;
  version_managers: string[];
  path: string[];
};

const MANAGER_ENV: Record<string, string[]> = {
  nvm: ["NVM_DIR", "NVM_BIN"],
  fnm: ["FNM_DIR", "FNM_MULTISHELL_PATH"],
  volta: ["VOLTA_HOME"],
  pyenv: ["PYENV_ROOT", "PYENV_SHELL", "PYENV_VERSION"],
  asdf: ["ASDF_DIR", "ASDF_DATA_DIR"],
  mise: ["MISE_SHELL", "__MISE_ACTIVATE", "RTX_SHELL"],
  rbenv: ["RBENV_ROOT", "RBENV_SHELL"],
  conda: ["CONDA_PREFIX", "CONDA_EXE"],
  sdkman: ["SDKMAN_DIR"],
};
const MANAGER_PATH: Record<string, RegExp> = {
  nvm: /[\\/]\.nvm[\\/]/,
  fnm: /fnm_multishells|[\\/]fnm[\\/]/,
  volta: /[\\/]\.volta[\\/]/,
  pyenv: /[\\/]\.pyenv[\\/]|pyenv-win/,
  asdf: /[\\/]\.asdf[\\/]/,
  mise: /[\\/]mise[\\/](shims|installs)/,
  rbenv: /[\\/]\.rbenv[\\/]/,
  conda: /[\\/](ana|mini)conda\d*[\\/]|miniforge|mambaforge/i,
  sdkman: /[\\/]\.sdkman[\\/]/,
};

/** Version managers in use, from environment variable names and PATH entries only (no shim is run). */
export function versionManagers(env: NodeJS.ProcessEnv = process.env, pathEntries: string[] = []): string[] {
  const found: string[] = [];
  for (const [name, keys] of Object.entries(MANAGER_ENV)) {
    if (keys.some((key) => env[key]) || pathEntries.some((entry) => MANAGER_PATH[name]!.test(entry))) found.push(name);
  }
  return found;
}

/**
 * PATH as a list: the home directory becomes `~`, and the user name, wherever
 * else it appears, becomes `<user>`. Capped at MAX_PATH_ENTRIES.
 */
export function sanitizedPath(pathValue: string, options: { home?: string; user?: string; platform?: NodeJS.Platform } = {}): string[] {
  const platform = options.platform ?? process.platform;
  const home = (options.home ?? safeHome()).replace(/[\\/]+$/, "");
  const user = options.user ?? safeUser();
  const separator = platform === "win32" ? ";" : ":";
  const entries: string[] = [];
  for (const raw of pathValue.split(separator)) {
    let entry = raw.trim().replace(/^"(.*)"$/, "$1");
    if (!entry) continue;
    if (home && (platform === "win32" ? entry.toLowerCase().startsWith(home.toLowerCase()) : entry.startsWith(home))) {
      const rest = entry.slice(home.length);
      if (rest === "" || rest.startsWith("/") || rest.startsWith("\\")) entry = `~${rest}`;
    }
    // client-raw: the account name stays as written (the home as `~` above stays).
    if (user && !redactionRaw()) {
      const escaped = user.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      // A short name is replaced only as a whole path component.
      entry = user.length >= 3
        ? entry.replace(new RegExp(escaped, "gi"), "<user>")
        : entry.replace(new RegExp(`(^|[\\\\/])${escaped}(?=[\\\\/]|$)`, "gi"), "$1<user>");
    }
    entries.push(entry.slice(0, 256));
    if (entries.length >= MAX_PATH_ENTRIES) break;
  }
  return entries;
}

function safeHome(): string {
  try {
    return homedir();
  } catch {
    return "";
  }
}

function safeUser(): string {
  try {
    return userInfo().username;
  } catch {
    return process.env.USER ?? process.env.USERNAME ?? "";
  }
}

const VERSIONED_SHELLS = new Set(["bash", "zsh", "fish", "ksh", "tcsh", "nu", "elvish", "xonsh"]);

export async function shellInfo(run: RunText, options: { env?: NodeJS.ProcessEnv; platform?: NodeJS.Platform } = {}): Promise<ShellInfo> {
  const env = options.env ?? process.env;
  const platform = options.platform ?? process.platform;
  const shellPath = (platform === "win32" ? env.ComSpec ?? env.COMSPEC : env.SHELL)?.trim();
  const name = shellPath ? nodePath.basename(shellPath.replace(/\\/g, "/")).replace(/\.exe$/i, "").toLowerCase() : undefined;
  const path = sanitizedPath((platform === "win32" ? env.Path ?? env.PATH : env.PATH) ?? "", { platform });
  const info: ShellInfo = { version_managers: versionManagers(env, path), path };
  if (name) info.name = name.slice(0, 32);
  if (shellPath && name && VERSIONED_SHELLS.has(name) && nodePath.isAbsolute(shellPath)) {
    const output = await run(shellPath, ["--version"]);
    const line = output?.split(/\r?\n/).map((part) => part.trim()).find(Boolean);
    if (line) info.version = line.slice(0, 200);
  }
  return info;
}
