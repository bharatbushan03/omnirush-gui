// Exact toolchain versions for the upload envelope's `environment.toolchain`,
// so a session can be reproduced with the same interpreters, compilers and
// packages it ran against.
//
// Every probe runs in the session's project root (so pyenv, nvm, asdf, volta
// and .tool-versions shims answer for the version the project actually uses),
// only for a command that resolves on PATH, with a short timeout, all in
// parallel. A probe that fails, times out or prints nothing is left out.
// Projects nested in the root (a monorepo's apps/web, a backend/python with
// its own venv) are found by a bounded manifest search and get their own
// pip freeze and npm ls, run in their folder.
// Nothing recorded names an absolute path, a user name, an environment value
// or a credential: version lines go through `stripPaths`, pip freeze entries
// through `sanitizeFreezeLines`, and the caller runs the CONFIG scrub over the
// whole block before it leaves the machine.

import { spawn } from "node:child_process";
import { readdirSync, statSync, type Dirent } from "node:fs";
import { readdir, stat } from "node:fs/promises";
import { constants as osConstants, setPriority } from "node:os";
import nodePath from "node:path";

import { cltSkipReason, resolveCommand } from "./command-guard.js";
import { redactionPolicy, redactionRaw } from "./context/redact-policy.js";
import {
  collectEnvFiles,
  collectEnvNamesRead,
  shellInfo,
  systemInfo,
  type EnvFile,
  type SecretChecks,
  type ShellInfo,
  type SystemInfo,
} from "./project-env.js";

export const TOOLCHAIN_SCHEMA_VERSION = 1;
/** Per version probe. */
export const PROBE_TIMEOUT_MS = 2_000;
/** The package snapshot (pip freeze) gets a little longer: pip imports a lot. */
export const FREEZE_TIMEOUT_MS = 4_000;
export const MAX_VERSION_CHARS = 200;
export const MAX_FREEZE_BYTES = 64 * 1024;
export const MAX_FREEZE_LINES = 2_000;
const MAX_PROBE_OUTPUT_BYTES = 256 * 1024;

export type PythonExecutableKind = "venv" | "conda" | "pyenv" | "asdf" | "mise" | "uv" | "system";

export type UploadToolchain = {
  schema: number;
  collected_at: string;
  duration_ms: number;
  /** Tool name to its version line, e.g. `"node": "v22.19.0"`. */
  versions: Record<string, string>;
  /** Tools on PATH that were deliberately not run, and why (`xcode_clt_missing`). */
  skipped?: Record<string, string>;
  /** Of the interpreter the top-level pip_freeze came from. */
  python_executable_kind?: PythonExecutableKind;
  /**
   * Manifest and version-pin files, as paths relative to the project root,
   * nested projects included (`package.json`, `backend/python/requirements.txt`).
   */
  manifests: string[];
  /** Lockfiles, as paths relative to the project root. */
  lockfiles: string[];
  /** The manifest search stopped at its folder or time cap. */
  manifests_truncated?: boolean;
  /**
   * `pip freeze` of the project's interpreter, sanitised; only with a Python
   * project. The root's, or the first nested project's when the root is not
   * one (`pip_freeze_dir` then names it).
   */
  pip_freeze?: string[];
  pip_freeze_tool?: "pip" | "uv";
  pip_freeze_truncated?: boolean;
  /** With nested Python projects: the folder (`.` for the root) the top-level pip_freeze describes. */
  pip_freeze_dir?: string;
  /** With nested Python projects: pip freeze per project folder, the size caps shared between them. */
  pip_freeze_by_dir?: Record<string, string[]>;
  /** Folders whose pip_freeze_by_dir entry was cut to its share of the caps. */
  pip_freeze_truncated_dirs?: string[];
  /** With nested Python projects: the interpreter kind per project folder. */
  python_executable_kind_by_dir?: Record<string, PythonExecutableKind>;
  /** With nested Python projects: the virtual environment's `python --version` per project folder that has one. */
  venv_python_by_dir?: Record<string, string>;
  /**
   * `npm ls --json --depth=0`, reduced to direct dependency versions; only with
   * package.json and node_modules. The root's, or the first nested folder's.
   */
  npm_ls?: NpmLs;
  /** With nested Node projects: the folder the top-level npm_ls describes. */
  npm_ls_dir?: string;
  /** With nested Node projects: npm ls per folder with package.json and node_modules, the size cap shared between them. */
  npm_ls_by_dir?: Record<string, NpmLs>;
  /** More than MAX_PROJECT_DIRS Python or Node projects: the rest were not probed. */
  projects_truncated?: boolean;
  /** OS release, WSL, CPU. */
  system?: SystemInfo;
  /** Shell name and version, version managers in use, PATH (home as `~`, never the user name). */
  shell?: ShellInfo;
  /** .env files (templates excluded): key names, values only when clearly not secret. */
  env_files?: EnvFile[];
  /** Environment variable names the project's code reads. */
  env_names_read?: string[];
  env_names_read_truncated?: boolean;
};

export type NpmLs = { name?: string; version?: string; dependencies: Record<string, string>; truncated?: boolean };
export const MAX_NPM_LS_BYTES = 64 * 1024;

type Probe = {
  /** Key in `versions`. */
  key: string;
  command: string;
  args: string[];
  /** Read the version from stderr (java prints `-version` there). */
  stderr?: boolean;
  /** The line holding the version, when it is not the first (gradle). */
  pick?: RegExp;
};

export const TOOLCHAIN_PROBES: readonly Probe[] = [
  { key: "python3", command: "python3", args: ["--version"] },
  { key: "python", command: "python", args: ["--version"] },
  { key: "node", command: "node", args: ["-v"] },
  { key: "npm", command: "npm", args: ["-v"] },
  { key: "pnpm", command: "pnpm", args: ["-v"] },
  { key: "yarn", command: "yarn", args: ["-v"] },
  { key: "bun", command: "bun", args: ["-v"] },
  { key: "deno", command: "deno", args: ["--version"] },
  { key: "rustc", command: "rustc", args: ["-V"] },
  { key: "cargo", command: "cargo", args: ["-V"] },
  { key: "go", command: "go", args: ["version"] },
  { key: "java", command: "java", args: ["-version"], stderr: true },
  { key: "ruby", command: "ruby", args: ["-v"] },
  { key: "php", command: "php", args: ["-v"] },
  { key: "dotnet", command: "dotnet", args: ["--version"] },
  { key: "gcc", command: "gcc", args: ["--version"] },
  { key: "clang", command: "clang", args: ["--version"] },
  { key: "uv", command: "uv", args: ["--version"] },
  { key: "mvn", command: "mvn", args: ["-v"] },
  { key: "gradle", command: "gradle", args: ["-v"], pick: /^Gradle\s+\S+/ },
  { key: "cmake", command: "cmake", args: ["--version"] },
  { key: "poetry", command: "poetry", args: ["--version"] },
];

const LOCKFILES = new Set([
  "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb", "deno.lock",
  "Cargo.lock", "go.sum", "poetry.lock", "uv.lock", "Pipfile.lock", "pdm.lock", "conda-lock.yml",
  "Gemfile.lock", "composer.lock", "packages.lock.json", "gradle.lockfile", "mix.lock", "pubspec.lock",
  "Package.resolved", "flake.lock",
]);
const MANIFESTS = new Set([
  "package.json", "pyproject.toml", "setup.py", "setup.cfg", "Pipfile", "environment.yml", "environment.yaml",
  "Cargo.toml", "go.mod", "Gemfile", "composer.json", "pom.xml", "build.gradle", "build.gradle.kts",
  "deno.json", "deno.jsonc", "global.json", ".tool-versions", ".python-version", ".nvmrc", ".node-version",
  ".ruby-version", ".java-version", "mise.toml", ".mise.toml", "rust-toolchain", "rust-toolchain.toml",
  ".go-version", "volta.json",
]);
const PYTHON_MANIFESTS = new Set(["pyproject.toml", "setup.py", "setup.cfg", "Pipfile", "Pipfile.lock", "poetry.lock", "uv.lock", "pdm.lock", ".python-version"]);
const REQUIREMENTS = /^requirements[\w.-]*\.(txt|in)$/i;
/** Preferred virtual environment names, in order; any folder holding pyvenv.cfg is one too. */
const VENV_DIRS = [".venv", "venv", "env"];

/** How far below the project root manifests are searched (the root is level 0). */
export const MANIFEST_SCAN_DEPTH = 3;
/** Folders read per search, the root included. */
export const MANIFEST_SCAN_MAX_DIRS = 200;
/** Wall time for one search. */
export const MANIFEST_SCAN_BUDGET_MS = 2_000;
/** Python environments, and Node folders, probed per project (each). */
export const MAX_PROJECT_DIRS = 8;
/**
 * Never searched: installed dependencies, build output, caches. Dotted folders
 * (.git, .cache, .venv, .tox …) and virtual or conda environments are skipped too.
 */
const SKIP_DIRS = new Set([
  "node_modules", "bower_components", "jspm_packages", "vendor", "build", "dist", "target", "out", "coverage",
  "__pycache__", "site-packages", "Pods", "DerivedData",
]);

export type ProjectFiles = {
  /** Manifest and version-pin files, as paths relative to the root (`backend/python/requirements.txt`). */
  manifests: string[];
  /** Lockfiles, as paths relative to the root. */
  lockfiles: string[];
  /** Changes when a manifest, lockfile, virtual environment, node_modules or root .env file appears, goes, or is rewritten. */
  signature: string;
  /** A Python project at the root: a Python manifest or lockfile, a virtual environment, or a .py file. */
  python: boolean;
  /** package.json at the root. */
  node: boolean;
  /** node_modules/ at the root (installed dependencies, for npm ls). */
  nodeModules: boolean;
  /** Folders holding a Python project (`.` for the root), shallowest first. */
  pythonDirs: string[];
  /** Folders holding a package.json, shallowest first. */
  nodeDirs: string[];
  /** Folders holding a package.json and node_modules/, shallowest first. */
  nodeModulesDirs: string[];
  /** Virtual environments (folders with pyvenv.cfg), relative to the root. */
  venvs: string[];
  /** The search stopped at its folder or time cap. */
  truncated: boolean;
};

export type ScanOptions = { maxDepth?: number; maxDirs?: number; budgetMs?: number; now?: () => number };

/** `a/b` → `a`, `a` → `.`. */
function parentDir(rel: string): string {
  const cut = rel.lastIndexOf("/");
  return cut < 0 ? "." : rel.slice(0, cut);
}

function dirDepth(rel: string): number {
  return rel === "." ? 0 : rel.split("/").length;
}

/** Shallowest first, then by name: the root, then `api`, then `apps/web`. */
function byDepth(a: string, b: string): number {
  return dirDepth(a) - dirDepth(b) || (a < b ? -1 : a > b ? 1 : 0);
}

function isVenvListing(name: string, names: Set<string>): boolean {
  if (names.has("pyvenv.cfg")) return true;
  // virtualenv < 20 wrote no pyvenv.cfg.
  return VENV_DIRS.includes(name) && (names.has("bin") || names.has("Scripts")) && (names.has("lib") || names.has("Lib"));
}

/**
 * The manifests and lockfiles of the project at `root` and of the projects
 * nested in it (a monorepo's `apps/web`, a `backend/python`), searched
 * breadth first down to MANIFEST_SCAN_DEPTH levels, at most
 * MANIFEST_SCAN_MAX_DIRS folders and MANIFEST_SCAN_BUDGET_MS; symlinks are
 * never followed. Paths are relative to the root, with `/`.
 */
export async function projectFiles(root: string, scan: ScanOptions = {}): Promise<ProjectFiles> {
  const maxDepth = scan.maxDepth ?? MANIFEST_SCAN_DEPTH;
  const maxDirs = scan.maxDirs ?? MANIFEST_SCAN_MAX_DIRS;
  const now = scan.now ?? Date.now;
  const deadline = now() + (scan.budgetMs ?? MANIFEST_SCAN_BUDGET_MS);
  const manifests: string[] = [];
  const lockfiles: string[] = [];
  const venvs: string[] = [];
  const pythonDirs = new Set<string>();
  const nodeDirs: string[] = [];
  const nodeModulesDirs: string[] = [];
  let rootNames: string[] = [];
  let visited = 0;
  let truncated = false;
  const queue: Array<{ rel: string; depth: number }> = [{ rel: "", depth: 0 }];
  for (let next = queue.shift(); next; next = queue.shift()) {
    if (visited >= maxDirs || now() > deadline) {
      truncated = true;
      break;
    }
    const { rel, depth } = next;
    const abs = rel ? nodePath.join(root, ...rel.split("/")) : root;
    let entries: Dirent[];
    try {
      entries = await readdir(abs, { withFileTypes: true });
    } catch {
      continue;
    }
    visited += 1;
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    const names = new Set(entries.map((entry) => entry.name));
    const key = rel || ".";
    if (rel) {
      const base = rel.slice(rel.lastIndexOf("/") + 1);
      if (isVenvListing(base, names)) {
        venvs.push(rel);
        pythonDirs.add(parentDir(rel));
        continue;
      }
      if (base.startsWith(".") || names.has("conda-meta")) continue;
    } else {
      rootNames = [...names];
    }
    const at = (name: string) => (rel ? `${rel}/${name}` : name);
    const children: string[] = [];
    for (const entry of entries) {
      const name = entry.name;
      if (entry.isDirectory()) {
        if (!name.startsWith(".") && !SKIP_DIRS.has(name)) children.push(name);
        else if (VENV_DIRS.includes(name)) children.push(name); // .venv: read only to confirm it is one
        continue;
      }
      if (LOCKFILES.has(name)) lockfiles.push(at(name));
      else if (MANIFESTS.has(name) || REQUIREMENTS.test(name)) manifests.push(at(name));
      else continue;
      if (PYTHON_MANIFESTS.has(name) || REQUIREMENTS.test(name)) pythonDirs.add(key);
    }
    if (names.has("package.json")) {
      nodeDirs.push(key);
      if (names.has("node_modules")) nodeModulesDirs.push(key);
    }
    if (depth < maxDepth) {
      for (const name of children) queue.push({ rel: at(name), depth: depth + 1 });
    } else {
      // A manifest at the last level still finds the environment next to it.
      const found = await Promise.all(children.slice(0, 32).map(async (name) => {
        try {
          return (await stat(nodePath.join(abs, name, "pyvenv.cfg"))).isFile() ? name : null;
        } catch {
          return null;
        }
      }));
      for (const name of found) {
        if (!name) continue;
        venvs.push(at(name));
        pythonDirs.add(key);
      }
    }
  }
  manifests.sort();
  lockfiles.sort();
  venvs.sort();
  const envFiles = rootNames.filter((name) => /^\.env(?:\..+)?$/.test(name)).sort();
  const stamps = await Promise.all([...manifests, ...lockfiles, ...envFiles].map(async (rel) => {
    try {
      const info = await stat(nodePath.join(root, ...rel.split("/")));
      return `${rel}:${info.size}:${Math.trunc(info.mtimeMs)}`;
    } catch {
      return `${rel}:-`;
    }
  }));
  // A script-only Python project (`main.py`, no manifest) still runs on the interpreter's installed packages.
  const pyScripts = rootNames.some((name) => /\.py$/i.test(name));
  if (pyScripts) pythonDirs.add(".");
  const node = nodeDirs.includes(".");
  const nodeModules = nodeModulesDirs.includes(".");
  return {
    manifests,
    lockfiles,
    signature: [
      ...stamps,
      ...venvs.map((dir) => `venv:${dir}`),
      ...nodeModulesDirs.map((dir) => `node_modules:${dir}`),
      pyScripts ? "py" : "",
    ].join("|"),
    python: pythonDirs.has("."),
    node,
    nodeModules,
    pythonDirs: [...pythonDirs].sort(byDepth),
    nodeDirs: nodeDirs.sort(byDepth),
    nodeModulesDirs: nodeModulesDirs.sort(byDepth),
    venvs,
    truncated,
  };
}

/** The virtual environment a Python project in `dir` runs on: one next to it, else the nearest one above it, up to the root. */
export function venvFor(dir: string, venvs: readonly string[]): string | null {
  const rank = (rel: string) => {
    const index = VENV_DIRS.indexOf(rel.slice(rel.lastIndexOf("/") + 1));
    return index < 0 ? VENV_DIRS.length : index;
  };
  for (let at = dir; ; at = parentDir(at)) {
    const here = venvs.filter((venv) => parentDir(venv) === at).sort((a, b) => rank(a) - rank(b) || (a < b ? -1 : 1));
    if (here.length > 0) return here[0]!;
    if (at === ".") return null;
  }
}

// --- command resolution ------------------------------------------------------

export { resolveCommand, type ResolveOptions } from "./command-guard.js";

function defaultIsFile(path: string): boolean {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

// --- running a probe ---------------------------------------------------------

export type RunResult = { code: number | null; stdout: string; stderr: string } | null;
export type RunCommand = (file: string, args: string[], options: { cwd: string; timeoutMs: number; maxBytes: number }) => Promise<RunResult>;

export const PROBE_ENV_OVERRIDES: Record<string, string> = {
  NO_COLOR: "1",
  TERM: "dumb",
  PIP_DISABLE_PIP_VERSION_CHECK: "1",
  PIP_NO_INPUT: "1",
  PYTHONWARNINGS: "ignore",
  // corepack's pnpm/yarn shims would otherwise offer to download a release.
  COREPACK_ENABLE_DOWNLOAD_PROMPT: "0",
  COREPACK_ENABLE_NETWORK: "0",
  DOTNET_NOLOGO: "1",
  DOTNET_CLI_TELEMETRY_OPTOUT: "1",
  DOTNET_SKIP_FIRST_TIME_EXPERIENCE: "1",
  POETRY_NO_INTERACTION: "1",
  UV_NO_PROGRESS: "1",
  UV_OFFLINE: "1",
};

/**
 * Runs `file` with no shell, stdin closed, no window, and settles by
 * `timeoutMs` whatever the child does: on the deadline it is killed and the
 * result is null (a grandchild holding the pipes open cannot stall it).
 */
export const runCommand: RunCommand = (file, args, { cwd, timeoutMs, maxBytes }) => new Promise((resolvePromise) => {
  let argv0 = file;
  let argv = args;
  if (process.platform === "win32" && /\.(cmd|bat)$/i.test(file)) {
    // A batch file cannot be spawned without cmd.exe; the arguments are fixed
    // probe flags, never user input.
    argv0 = process.env.ComSpec || "cmd.exe";
    argv = ["/d", "/s", "/c", `"${[file, ...args].map((part) => `"${part}"`).join(" ")}"`];
  }
  let settled = false;
  let child: ReturnType<typeof spawn>;
  try {
    child = spawn(argv0, argv, {
      cwd,
      env: { ...process.env, ...PROBE_ENV_OVERRIDES },
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
      windowsVerbatimArguments: argv0 !== file,
    });
  } catch {
    resolvePromise(null);
    return;
  }
  // Probes run in the background: never at the expense of the agent's own work.
  if (child.pid) {
    try {
      setPriority(child.pid, osConstants.priority.PRIORITY_BELOW_NORMAL);
    } catch {
      // Not permitted here; it runs at normal priority.
    }
  }
  const out: Buffer[] = [];
  const err: Buffer[] = [];
  let outBytes = 0;
  let errBytes = 0;
  const finish = (result: RunResult) => {
    if (settled) return;
    settled = true;
    clearTimeout(timer);
    resolvePromise(result);
  };
  const timer = setTimeout(() => {
    try {
      child.kill("SIGKILL");
    } catch {
      // already gone
    }
    child.stdout?.destroy();
    child.stderr?.destroy();
    finish(null);
  }, timeoutMs);
  timer.unref?.();
  child.stdout?.on("data", (chunk: Buffer) => {
    if (outBytes < maxBytes) out.push(chunk);
    outBytes += chunk.length;
  });
  child.stderr?.on("data", (chunk: Buffer) => {
    if (errBytes < 64 * 1024) err.push(chunk);
    errBytes += chunk.length;
  });
  child.on("error", () => finish(null));
  child.on("close", (code) => finish({
    code,
    stdout: Buffer.concat(out).toString("utf8").slice(0, maxBytes),
    stderr: Buffer.concat(err).toString("utf8"),
  }));
});

// --- parsing -------------------------------------------------------------------

// eslint-disable-next-line no-control-regex
const ANSI = /\u001b\[[0-9;?]*[A-Za-z]|\u001b\][^\u0007]*\u0007/g;
// Absolute paths: POSIX (two or more components) and Windows drive or UNC.
const POSIX_PATH = /(^|[\s("'=:])\/(?:[^\s/"'()]+\/)+[^\s"'()]*/g;
const WINDOWS_PATH = /(^|[\s("'=])(?:[A-Za-z]:|\\\\[^\\\s]+)\\[^\s"'()]*/g;

/** Replaces every absolute path in `text` with `<path>`. */
export function stripPaths(text: string): string {
  return text.replace(POSIX_PATH, "$1<path>").replace(WINDOWS_PATH, "$1<path>");
}

/** The version line a probe printed: its first non-empty line, paths stripped, capped. */
export function parseProbeOutput(stdout: string, stderr: string, preferStderr = false, line?: RegExp): string | null {
  const pick = (text: string) => text.replace(ANSI, "").split(/\r?\n/).map((part) => part.trim()).find((part) => (line ? line.test(part) : part.length > 0)) ?? "";
  const first = preferStderr ? (pick(stderr) || pick(stdout)) : (pick(stdout) || pick(stderr));
  if (!first) return null;
  const clean = (redactionRaw() ? first : stripPaths(first)).replace(/[\u0000-\u001f\u007f]/g, " ").trim();
  if (!clean) return null;
  return clean.length > MAX_VERSION_CHARS ? clean.slice(0, MAX_VERSION_CHARS) : clean;
}

const PEP503 = /^[A-Za-z0-9][A-Za-z0-9._-]*/;

function packageNameFrom(text: string): string | null {
  const egg = /[#&]egg=([A-Za-z0-9][A-Za-z0-9._-]*)/.exec(text);
  if (egg) return egg[1]!;
  return null;
}

/**
 * pip freeze output reduced to entries that name no path, host or
 * credential: `name==1.2` stays; a direct reference (`name @ file:///…`,
 * `name @ git+https://user:pass@…`, `-e …`) becomes `name @ local`,
 * `name @ vcs` or `name @ url`; comments and index options are dropped.
 * Capped at MAX_FREEZE_LINES entries and MAX_FREEZE_BYTES.
 */
export function sanitizeFreezeLines(
  text: string,
  caps: { maxLines?: number; maxBytes?: number } = {},
): { lines: string[]; truncated: boolean } {
  const maxLines = caps.maxLines ?? MAX_FREEZE_LINES;
  const maxBytes = caps.maxBytes ?? MAX_FREEZE_BYTES;
  const lines: string[] = [];
  let bytes = 0;
  let truncated = false;
  let pendingEditableName: string | null = null;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    if (line.startsWith("#")) {
      // pip: "# Editable install with no version control (name==0.1)"
      const named = /\(([A-Za-z0-9][A-Za-z0-9._-]*)==[^)]*\)\s*$/.exec(line);
      pendingEditableName = named ? named[1]! : pendingEditableName;
      continue;
    }
    let entry: string | null = null;
    // client-raw: every requirement line as pip printed it.
    if (redactionRaw()) {
      entry = line;
    } else if (/^(-e|--editable)\s+/.test(line)) {
      const target = line.replace(/^(-e|--editable)\s+/, "");
      const vcs = /^(git|hg|svn|bzr)\+/i.test(target);
      const name = packageNameFrom(target) ?? pendingEditableName ?? (vcs ? null : localName(target));
      entry = name ? `${name} @ ${vcs ? "vcs" : "local"}` : null;
    } else if (line.startsWith("-")) {
      // --index-url, --extra-index-url, -f, -i …: never recorded.
      entry = null;
    } else if (line.includes(" @ ")) {
      const [namePart, target = ""] = line.split(" @ ", 2) as [string, string?];
      const name = PEP503.exec(namePart.trim())?.[0];
      const kind = /^(git|hg|svn|bzr)\+/i.test(target.trim()) ? "vcs" : /^file:/i.test(target.trim()) ? "local" : "url";
      entry = name ? `${name} @ ${kind}` : null;
    } else if (/^[A-Za-z0-9][A-Za-z0-9._\-[\],]*\s*(===?|~=|>=|<=|!=|<|>)\s*[^\s;@]+/.test(line) && !/[\\/]/.test(line) && !/:\/\//.test(line)) {
      entry = line.split(";")[0]!.trim();
    } else if (PEP503.test(line) && /^[A-Za-z0-9._-]+$/.test(line)) {
      entry = line;
    }
    pendingEditableName = null;
    if (!entry) continue;
    const size = Buffer.byteLength(entry, "utf8") + 1;
    if (lines.length >= maxLines || bytes + size > maxBytes) {
      truncated = true;
      break;
    }
    lines.push(entry);
    bytes += size;
  }
  return { lines, truncated };
}

function localName(target: string): string | null {
  const base = target.replace(/[\\/]+$/, "").split(/[\\/]/).pop() ?? "";
  const name = PEP503.exec(base)?.[0];
  return name && name !== "." && name !== ".." ? name : null;
}

// --- python ------------------------------------------------------------------

/** The interpreter inside the virtual environment at `venv`, or null. */
export function venvInterpreter(venv: string, platform: NodeJS.Platform = process.platform, isFile: (path: string) => boolean = defaultIsFile): string | null {
  const path = platform === "win32" ? nodePath.win32 : nodePath.posix;
  const candidates = platform === "win32"
    ? [path.join(venv, "Scripts", "python.exe")]
    : [path.join(venv, "bin", "python"), path.join(venv, "bin", "python3")];
  return candidates.find((candidate) => isFile(candidate)) ?? null;
}

/** The interpreter of the project's own virtual environment (.venv, venv, env), or null. */
export function projectVenvPython(root: string, platform: NodeJS.Platform = process.platform, isFile: (path: string) => boolean = defaultIsFile): string | null {
  const path = platform === "win32" ? nodePath.win32 : nodePath.posix;
  for (const dir of VENV_DIRS) {
    const python = venvInterpreter(path.join(root, dir), platform, isFile);
    if (python) return python;
  }
  return null;
}

/** What kind of interpreter `python` is, judged from its path (the path itself is never recorded). */
export function pythonExecutableKind(python: string, options: { venv?: boolean; isFile?: (path: string) => boolean } = {}): PythonExecutableKind {
  if (options.venv) return "venv";
  const normalized = python.replace(/\\/g, "/");
  const lower = normalized.toLowerCase();
  if (/\/(\.?pyenv|pyenv-win)\//.test(lower)) return "pyenv";
  if (/\/(ana|mini)conda\d*\/|\/miniforge\d*\/|\/mambaforge\/|\/conda\/|\/\.conda\//.test(lower)) return "conda";
  if (lower.includes("/.asdf/")) return "asdf";
  if (lower.includes("/mise/") || lower.includes("/.local/share/rtx/")) return "mise";
  if (lower.includes("/uv/python/")) return "uv";
  const isFile = options.isFile ?? defaultIsFile;
  const binDir = nodePath.dirname(normalized);
  const prefix = nodePath.dirname(binDir);
  if (isFile(nodePath.join(prefix, "pyvenv.cfg"))) return "venv";
  if (isFile(nodePath.join(prefix, "conda-meta", "history"))) return "conda";
  return "system";
}

// --- collection --------------------------------------------------------------

export type CollectOptions = {
  run?: RunCommand;
  resolve?: (command: string) => string | null;
  probes?: readonly Probe[];
  probeTimeoutMs?: number;
  freezeTimeoutMs?: number;
  platform?: NodeJS.Platform;
  now?: () => number;
  files?: ProjectFiles;
  /** The capture's secret rules, for .env values and the source scan. */
  checks?: SecretChecks;
  /** Environment for the shell and version-manager detection (process.env). */
  env?: NodeJS.ProcessEnv;
};

/**
 * Probes the toolchain for the project at `root`. Never throws; a probe
 * that cannot answer is simply missing from the result.
 */
export async function collectToolchain(root: string, options: CollectOptions = {}): Promise<UploadToolchain> {
  const now = options.now ?? Date.now;
  const started = now();
  const run = options.run ?? runCommand;
  const platform = options.platform ?? process.platform;
  const resolve = options.resolve ?? ((command: string) => resolveCommand(command, { platform }));
  const probeTimeoutMs = options.probeTimeoutMs ?? PROBE_TIMEOUT_MS;
  const files = options.files ?? (await projectFiles(root));
  const skipped: Record<string, string> = {};

  const resolved = new Map<string, string | null>();
  const where = (command: string) => {
    if (!resolved.has(command)) resolved.set(command, resolve(command));
    return resolved.get(command) ?? null;
  };

  const versionOf = async (probe: Probe): Promise<[string, string] | null> => {
    const file = where(probe.command);
    if (!file) return null;
    const reason = await cltSkipReason(probe.command, file);
    if (reason) {
      skipped[probe.key] = reason;
      return null;
    }
    if (platform === "darwin" && javaWouldPrompt(probe.command, file)) return null;
    const result = await run(file, probe.args, { cwd: root, timeoutMs: probeTimeoutMs, maxBytes: 16 * 1024 }).catch(() => null);
    if (!result || result.code !== 0) return null;
    const version = parseProbeOutput(result.stdout, result.stderr, probe.stderr, probe.pick);
    return version ? [probe.key, version] : null;
  };

  const freezeTimeoutMs = options.freezeTimeoutMs ?? FREEZE_TIMEOUT_MS;
  const abs = (dir: string) => (dir === "." ? root : nodePath.join(root, ...dir.split("/")));
  let projectsTruncated = false;

  // Python: every project folder runs on the environment next to it (or the
  // nearest one above it), else on the interpreter PATH finds.
  if (files.pythonDirs.length > MAX_PROJECT_DIRS) projectsTruncated = true;
  const pyProjects = files.pythonDirs.slice(0, MAX_PROJECT_DIRS).map((dir) => {
    const venv = venvFor(dir, files.venvs);
    return { dir, venvPython: venv ? venvInterpreter(abs(venv), platform) : null };
  });
  const systemPython = where("python3") ?? where("python");
  // `uv pip freeze --python /usr/bin/python3` would run the shim too.
  const systemSkip = systemPython && pyProjects.some((project) => !project.venvPython)
    ? cltSkipReason(where("python3") === systemPython ? "python3" : "python", systemPython)
    : Promise.resolve(null);
  const interpreters = new Map<string, { cwd: string; venv: boolean }>();
  for (const project of pyProjects) {
    const python = project.venvPython ?? systemPython;
    if (python && !interpreters.has(python)) interpreters.set(python, { cwd: abs(project.dir), venv: Boolean(project.venvPython) });
  }
  const freezes = Promise.all([...interpreters].map(async ([python, { cwd, venv }]) => {
    const reason = venv ? null : await systemSkip;
    if (reason) {
      skipped.pip_freeze = reason;
      return [python, null] as const;
    }
    return [python, await freezeRaw(python, cwd, where, run, freezeTimeoutMs)] as const;
  })).then((entries) => new Map(entries));
  // The project's own interpreter, which PATH does not reach unless the venv is active.
  const venvVersions = Promise.all([...interpreters].filter(([, info]) => info.venv).map(async ([python, { cwd }]) => {
    const result = await run(python, ["--version"], { cwd, timeoutMs: probeTimeoutMs, maxBytes: 16 * 1024 }).catch(() => null);
    return [python, result && result.code === 0 ? parseProbeOutput(result.stdout, result.stderr) : null] as const;
  })).then((entries) => new Map(entries));

  // Node: npm ls in every folder with package.json and node_modules.
  if (files.nodeModulesDirs.length > MAX_PROJECT_DIRS) projectsTruncated = true;
  const npmDirs = files.nodeModulesDirs.slice(0, MAX_PROJECT_DIRS);
  const checks = options.checks ?? {};
  // One-shot text runs (sw_vers, the shell's --version), under the same guard.
  const runText = async (file: string, args: string[]): Promise<string | null> => {
    if (await cltSkipReason(nodePath.basename(file), file)) return null;
    const result = await run(file, args, { cwd: root, timeoutMs: probeTimeoutMs, maxBytes: 16 * 1024 }).catch(() => null);
    return result && result.code === 0 ? result.stdout || result.stderr : null;
  };
  const extras = Promise.all([
    npmDirs.length > 0 ? npmLsRaw(npmDirs.map(abs), where, run, freezeTimeoutMs, skipped) : Promise.resolve([]),
    systemInfo(runText, platform).catch(() => null),
    shellInfo(runText, { env: options.env, platform }).catch(() => null),
    collectEnvFiles(root, checks).catch(() => []),
    collectEnvNamesRead(root, checks).catch(() => ({ names: [], truncated: false })),
  ]);
  const pairs = await Promise.all((options.probes ?? TOOLCHAIN_PROBES).map(versionOf));
  const versions: Record<string, string> = {};
  for (const pair of pairs) {
    if (pair) versions[pair[0]] = pair[1];
  }
  if (versions.python && versions.python === versions.python3) delete versions.python;
  const [frozen, venvVersion] = await Promise.all([freezes, venvVersions]);
  const primary = pyProjects[0];
  const primaryVenv = primary?.venvPython ?? null;
  if (primaryVenv && venvVersion.get(primaryVenv)) versions.venv_python = venvVersion.get(primaryVenv)!;

  const toolchain: UploadToolchain = {
    schema: TOOLCHAIN_SCHEMA_VERSION,
    collected_at: new Date(started).toISOString(),
    duration_ms: 0,
    versions,
    manifests: files.manifests,
    lockfiles: files.lockfiles,
  };
  if (files.truncated) toolchain.manifests_truncated = true;
  const systemRuns = Boolean(versions.python3 || versions.python);
  const kindOf = (venvPython: string | null): PythonExecutableKind | null => {
    const python = venvPython ?? systemPython;
    if (!python || !(venvPython || systemRuns)) return null;
    return pythonExecutableKind(python, { venv: Boolean(venvPython) });
  };
  const primaryKind = kindOf(primaryVenv);
  if (primaryKind) toolchain.python_executable_kind = primaryKind;
  const primarySnapshot = primary ? frozen.get(primaryVenv ?? systemPython ?? "") : null;
  if (primarySnapshot) {
    const { lines, truncated } = sanitizeFreezeLines(primarySnapshot.stdout);
    toolchain.pip_freeze = lines;
    toolchain.pip_freeze_tool = primarySnapshot.tool;
    if (truncated) toolchain.pip_freeze_truncated = true;
  }
  if (pyProjects.some((project) => project.dir !== ".")) {
    toolchain.pip_freeze_dir = primary!.dir;
    // One share of the caps per interpreter; a project sharing one with an earlier folder repeats its list.
    const full = new Map([...frozen].flatMap(([python, snapshot]) => (snapshot ? [[python, sanitizeFreezeLines(snapshot.stdout, { maxLines: Infinity, maxBytes: Infinity }).lines] as const] : [])));
    const keys = [...full.keys()];
    const lineShares = splitBudget(keys.map((key) => full.get(key)!.length), MAX_FREEZE_LINES);
    const byteShares = splitBudget(keys.map((key) => full.get(key)!.reduce((sum, line) => sum + Buffer.byteLength(line, "utf8") + 1, 0)), MAX_FREEZE_BYTES);
    const capped = new Map(keys.map((key, index) => [key, capLines(full.get(key)!, lineShares[index]!, byteShares[index]!)] as const));
    const byDir: Record<string, string[]> = {};
    const kinds: Record<string, PythonExecutableKind> = {};
    const venvByDir: Record<string, string> = {};
    const truncatedDirs: string[] = [];
    for (const project of pyProjects) {
      const kind = kindOf(project.venvPython);
      if (kind) kinds[project.dir] = kind;
      const version = project.venvPython ? venvVersion.get(project.venvPython) : null;
      if (version) venvByDir[project.dir] = version;
      const lines = capped.get(project.venvPython ?? systemPython ?? "");
      if (!lines) continue;
      byDir[project.dir] = lines.lines;
      if (lines.truncated) truncatedDirs.push(project.dir);
    }
    if (Object.keys(byDir).length > 0) toolchain.pip_freeze_by_dir = byDir;
    if (truncatedDirs.length > 0) toolchain.pip_freeze_truncated_dirs = truncatedDirs;
    if (Object.keys(kinds).length > 0) toolchain.python_executable_kind_by_dir = kinds;
    if (Object.keys(venvByDir).length > 0) toolchain.venv_python_by_dir = venvByDir;
  }
  // A package.json without node_modules: nothing is installed for npm ls to list; say so rather than leave it out silently.
  if (files.nodeDirs.length > 0 && npmDirs.length === 0 && !skipped.npm_ls) skipped.npm_ls = "not_installed";
  const [npmOutputs, system, shell, envFiles, namesRead] = await extras;
  const npm = npmOutputs[0] ? summarizeNpmLs(npmOutputs[0]) : null;
  if (npm) toolchain.npm_ls = npm;
  if (npmDirs.some((dir) => dir !== ".")) {
    toolchain.npm_ls_dir = npmDirs[0]!;
    const full = npmOutputs.map((stdout) => (stdout ? summarizeNpmLs(stdout, Infinity) : null));
    // As summarizeNpmLs counts: the JSON plus a separator per dependency.
    const shares = splitBudget(full.map((summary) => (summary ? JSON.stringify(summary).length + Object.keys(summary.dependencies).length : 0)), MAX_NPM_LS_BYTES);
    const byDir: Record<string, NpmLs> = {};
    npmDirs.forEach((dir, index) => {
      const stdout = npmOutputs[index];
      const summary = stdout ? summarizeNpmLs(stdout, shares[index]!) : null;
      if (summary) byDir[dir] = summary;
    });
    if (Object.keys(byDir).length > 0) toolchain.npm_ls_by_dir = byDir;
  }
  if (projectsTruncated) toolchain.projects_truncated = true;
  if (Object.keys(skipped).length > 0) toolchain.skipped = skipped;
  if (system) toolchain.system = system;
  if (shell) toolchain.shell = shell;
  if (envFiles.length > 0) toolchain.env_files = envFiles;
  if (namesRead.names.length > 0) toolchain.env_names_read = namesRead.names;
  if (namesRead.truncated) toolchain.env_names_read_truncated = true;
  toolchain.duration_ms = Math.max(0, Math.round(now() - started));
  return toolchain;
}

const NPM_NAME = /^(?:@[a-z0-9._~-]+\/)?[a-z0-9._~-]+$/i;
const NPM_VERSION = /^[0-9A-Za-z.+-]{1,64}$/;

/**
 * `npm ls --json --depth=0` reduced to `{name, version, dependencies: {dep:
 * version}}`: a dependency with no plain version (a link, a git or file
 * reference) is `local`, a missing one `missing`; nothing else (resolved
 * URLs, paths) is kept. Capped at MAX_NPM_LS_BYTES.
 */
export function summarizeNpmLs(stdout: string, maxBytes: number = MAX_NPM_LS_BYTES): NpmLs | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object") return null;
  const tree = parsed as { name?: unknown; version?: unknown; dependencies?: Record<string, { version?: unknown; missing?: unknown }> };
  const summary: NpmLs = { dependencies: {} };
  if (typeof tree.name === "string" && NPM_NAME.test(tree.name)) summary.name = tree.name;
  if (typeof tree.version === "string" && NPM_VERSION.test(tree.version)) summary.version = tree.version;
  let bytes = JSON.stringify(summary).length;
  for (const [name, dep] of Object.entries(tree.dependencies ?? {})) {
    if (!NPM_NAME.test(name)) continue;
    const version = typeof dep?.version === "string" && NPM_VERSION.test(dep.version) ? dep.version : dep?.missing ? "missing" : "local";
    const size = JSON.stringify(name).length + JSON.stringify(version).length + 2;
    if (bytes + size > maxBytes) {
      summary.truncated = true;
      break;
    }
    summary.dependencies[name] = version;
    bytes += size;
  }
  return summary;
}

/** `npm ls --json --depth=0` output in each of `dirs` (null where it failed), npm resolved and guarded once. */
async function npmLsRaw(
  dirs: string[],
  where: (command: string) => string | null,
  run: RunCommand,
  timeoutMs: number,
  skipped: Record<string, string>,
): Promise<Array<string | null>> {
  const npm = where("npm");
  if (!npm) return dirs.map(() => null);
  const reason = await cltSkipReason("npm", npm);
  if (reason) {
    skipped.npm_ls = reason;
    return dirs.map(() => null);
  }
  return Promise.all(dirs.map(async (cwd) => {
    const result = await run(npm, ["ls", "--json", "--depth=0"], { cwd, timeoutMs, maxBytes: MAX_PROBE_OUTPUT_BYTES * 4 }).catch(() => null);
    // npm ls exits 1 for missing or extraneous packages and still prints the tree.
    return result && (result.code === 0 || result.code === 1) ? result.stdout : null;
  }));
}

/** `pip freeze` output of `python`, run in `cwd`: through uv when it is on PATH, else `python -m pip`. */
async function freezeRaw(
  python: string,
  cwd: string,
  where: (command: string) => string | null,
  run: RunCommand,
  timeoutMs: number,
): Promise<{ stdout: string; tool: "pip" | "uv" } | null> {
  const options = { cwd, timeoutMs, maxBytes: MAX_PROBE_OUTPUT_BYTES };
  const uv = where("uv");
  // uv is much faster and also reads a uv-made venv, which has no pip.
  if (uv) {
    const result = await run(uv, ["pip", "freeze", "--python", python], options).catch(() => null);
    if (result && result.code === 0) return { stdout: result.stdout, tool: "uv" };
  }
  const result = await run(python, ["-m", "pip", "freeze", "--disable-pip-version-check"], options).catch(() => null);
  if (result && result.code === 0) return { stdout: result.stdout, tool: "pip" };
  return null;
}

/**
 * Splits `total` between items that want `wants[i]` each: the smaller wants
 * are met in full, the rest share what is left equally. Never more than
 * `total` in all.
 */
export function splitBudget(wants: readonly number[], total: number): number[] {
  const shares = wants.map(() => 0);
  const order = wants.map((_, index) => index).sort((a, b) => wants[a]! - wants[b]!);
  let left = total;
  let count = order.length;
  for (const index of order) {
    const share = Math.min(wants[index]!, Math.floor(left / count));
    shares[index] = share;
    left -= share;
    count -= 1;
  }
  return shares;
}

/** The leading `lines` that fit in `maxLines` entries and `maxBytes`. */
function capLines(lines: readonly string[], maxLines: number, maxBytes: number): { lines: string[]; truncated: boolean } {
  const kept: string[] = [];
  let bytes = 0;
  for (const line of lines) {
    const size = Buffer.byteLength(line, "utf8") + 1;
    if (kept.length >= maxLines || bytes + size > maxBytes) return { lines: kept, truncated: true };
    kept.push(line);
    bytes += size;
  }
  return { lines: kept, truncated: false };
}

// macOS: /usr/bin/java without a JDK opens a "no Java runtime" dialog (the
// Command Line Tools shims are handled by command-guard.ts).
function javaWouldPrompt(command: string, file: string): boolean {
  if (command !== "java" || file !== "/usr/bin/java") return false;
  try {
    return readdirSync("/Library/Java/JavaVirtualMachines").length === 0;
  } catch {
    return true;
  }
}

// --- cache -------------------------------------------------------------------

type CacheEntry = { signature: string; pending: Promise<UploadToolchain | null>; value: UploadToolchain | null };

/**
 * One toolchain per project root, collected when a session starts (or at its
 * first upload) and again only when the project's manifest/lockfile set
 * changes. An upload does not wait for a collection in flight: it carries the
 * cached block once there is one, so the session's first envelope may go
 * without it and the next ones carry it. `waitMs` bounds a wait: the
 * session's last snapshot waits a little, so a short session still records
 * its toolchain.
 */
export class ToolchainCache {
  private readonly entries = new Map<string, CacheEntry>();
  collections = 0;

  constructor(private readonly options: CollectOptions & { waitMs?: number; scrub?: (toolchain: UploadToolchain) => UploadToolchain } = {}) {}

  async get(root: string, waitMs = this.options.waitMs ?? 0): Promise<UploadToolchain | null> {
    const files = await projectFiles(root);
    // One entry per root and upload rules: a block scrubbed under one session's rules never goes out under another's.
    const key = `${root}\0${redactionPolicy()}`;
    let entry = this.entries.get(key);
    if (!entry || entry.signature !== files.signature) {
      const previous = entry?.value ?? null;
      this.collections += 1;
      const next: CacheEntry = { signature: files.signature, value: previous, pending: Promise.resolve(null) };
      next.pending = collectToolchain(root, { ...this.options, files })
        .then((toolchain) => (this.options.scrub ? this.options.scrub(toolchain) : toolchain))
        .then((toolchain) => {
          next.value = toolchain;
          return toolchain;
        })
        .catch(() => next.value);
      this.entries.set(key, next);
      entry = next;
    }
    let timer: ReturnType<typeof setTimeout> | undefined;
    await Promise.race([
      entry.pending,
      new Promise<void>((resolvePromise) => {
        // Not unref'd: the wait is bounded, and an unref'd timer could let
        // the process exit with an upload still waiting on it.
        timer = setTimeout(resolvePromise, waitMs);
      }),
    ]);
    clearTimeout(timer);
    return entry.value;
  }
}
