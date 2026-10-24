// @ts-nocheck -- ported from the CLI suite; exercises loosely typed fakes.
import { test } from "bun:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import zlib from "node:zlib";

import * as toolchain from "./toolchain.js";
import { SessionUploader } from "./session-uploader.js";

// environment.toolchain: exact toolchain versions per project, so a session
// can be reproduced. Probes resolve on PATH first, run in the project root
// with a short timeout, and anything that fails is left out; pip freeze is
// sanitised; the block is collected once and again only when the project's
// manifest/lockfile set changes.
const hasZstd = typeof zlib.zstdDecompressSync === "function";

function tempProject(files = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "omnirush-toolchain-"));
  for (const [name, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, name)), { recursive: true });
    fs.writeFileSync(path.join(root, name), content);
  }
  return root;
}

/** A fake runner: `outputs[command]` is a result, a function of args, or missing (fails). */
function fakeRun(outputs, calls = []) {
  return async (file, args, options) => {
    calls.push({ file, args, cwd: options.cwd });
    const name = path.basename(file);
    const output = outputs[name];
    if (output === undefined) return null;
    return typeof output === "function" ? output(args) : output;
  };
}

const ok = (stdout, stderr = "") => ({ code: 0, stdout, stderr });

test("probe parsing takes the first line, reads java from stderr, strips paths and colours, caps at 200", () => {
  assert.equal(toolchain.parseProbeOutput("Python 3.12.3\n", ""), "Python 3.12.3");
  assert.equal(toolchain.parseProbeOutput("deno 2.1.4 (stable, release, x86_64-unknown-linux-gnu)\nv8 13.0\ntypescript 5.6.2\n", ""), "deno 2.1.4 (stable, release, x86_64-unknown-linux-gnu)");
  assert.equal(toolchain.parseProbeOutput("", 'openjdk version "21.0.4" 2024-07-16\nOpenJDK Runtime Environment\n', true), 'openjdk version "21.0.4" 2024-07-16');
  assert.equal(toolchain.parseProbeOutput("\u001b[32mv22.19.0\u001b[0m\n", ""), "v22.19.0");
  assert.equal(toolchain.parseProbeOutput("PHP 8.3.6 (cli) (built: /home/alice/src/php)\nCopyright", ""), "PHP 8.3.6 (cli) (built: <path>)");
  assert.equal(toolchain.parseProbeOutput("tool 1.0 at C:\\Users\\alice\\bin\\tool.exe", ""), "tool 1.0 at <path>");
  assert.equal(toolchain.parseProbeOutput("x".repeat(500), "").length, 200);
  assert.equal(toolchain.parseProbeOutput("\n\n", ""), null);
});

test("a tool that is not on PATH is never spawned and is left out", async () => {
  const root = tempProject();
  const calls = [];
  const result = await toolchain.collectToolchain(root, {
    env: {},
    resolve: (command) => (command === "node" || command === "go" ? `/opt/bin/${command}` : null),
    run: fakeRun({ node: ok("v22.19.0\n"), go: ok("go version go1.23.2 linux/amd64\n") }, calls),
  });
  assert.deepEqual(result.versions, { node: "v22.19.0", go: "go version go1.23.2 linux/amd64" });
  assert.deepEqual(calls.map((call) => path.basename(call.file)).sort(), ["go", "node"]);
  assert.ok(calls.every((call) => call.cwd === root), "probes run in the project root");
  assert.equal(result.python_executable_kind, undefined);
  assert.equal(result.pip_freeze, undefined);
});

test("a failing probe (non-zero exit, error, empty output) is left out; python is kept only when it differs", async () => {
  const root = tempProject();
  const result = await toolchain.collectToolchain(root, {
    resolve: (command) => `/usr/bin/${command}`,
    run: fakeRun({
      python3: ok("Python 3.12.3\n"),
      python: ok("Python 3.12.3\n"),
      ruby: { code: 127, stdout: "", stderr: "pyenv: ruby: command not found" },
      rustc: ok(""),
      java: ok("", 'openjdk version "21.0.4"\n'),
    }),
  });
  assert.deepEqual(result.versions, { python3: "Python 3.12.3", java: 'openjdk version "21.0.4"' });
  const different = await toolchain.collectToolchain(root, {
    resolve: (command) => (command.startsWith("python") ? `/usr/bin/${command}` : null),
    run: fakeRun({ python3: ok("Python 3.12.3\n"), python: ok("Python 2.7.18\n") }),
  });
  assert.deepEqual(different.versions, { python3: "Python 3.12.3", python: "Python 2.7.18" });
});

test.skipIf(process.platform === "win32")("a probe that hangs is killed at its timeout and left out, without holding up the rest", async () => {
  const root = tempProject();
  const bin = fs.mkdtempSync(path.join(os.tmpdir(), "omnirush-toolchain-bin-"));
  // `slow` sleeps; `stuck` leaves a grandchild holding stdout open.
  fs.writeFileSync(path.join(bin, "slow"), "#!/bin/sh\nsleep 30\necho never\n", { mode: 0o755 });
  fs.writeFileSync(path.join(bin, "stuck"), "#!/bin/sh\n(sleep 30; echo late) &\necho stuck 1.0\nsleep 30\n", { mode: 0o755 });
  fs.writeFileSync(path.join(bin, "fast"), "#!/bin/sh\necho fast 2.0\n", { mode: 0o755 });
  const started = Date.now();
  const result = await toolchain.collectToolchain(root, {
    resolve: (command) => toolchain.resolveCommand(command, { pathEnv: bin }),
    probes: [
      { key: "slow", command: "slow", args: [] },
      { key: "stuck", command: "stuck", args: [] },
      { key: "fast", command: "fast", args: [] },
      { key: "missing", command: "definitely-not-installed", args: [] },
    ],
    probeTimeoutMs: 300,
  });
  const elapsed = Date.now() - started;
  assert.deepEqual(result.versions, { fast: "fast 2.0" });
  assert.ok(elapsed < 2_000, `collection settled in ${elapsed} ms`);
});

test("resolveCommand searches PATH with PATHEXT on Windows and skips relative entries and Store aliases", () => {
  const files = new Set([
    "C:\\Users\\a\\AppData\\Local\\Microsoft\\WindowsApps\\python.exe",
    "C:\\Program Files\\nodejs\\npm.cmd",
    "C:\\Python312\\python.exe",
    "/usr/local/bin/node",
    "bin/node",
  ]);
  const isFile = (candidate) => files.has(candidate);
  const winPath = "C:\\Users\\a\\AppData\\Local\\Microsoft\\WindowsApps;.\\tools;\"C:\\Program Files\\nodejs\";C:\\Python312";
  assert.equal(toolchain.resolveCommand("python", { platform: "win32", pathEnv: winPath, pathExt: ".COM;.EXE;.BAT;.CMD;.PS1", isFile }), "C:\\Python312\\python.exe");
  assert.equal(toolchain.resolveCommand("npm", { platform: "win32", pathEnv: winPath, pathExt: ".COM;.EXE;.BAT;.CMD", isFile }), "C:\\Program Files\\nodejs\\npm.cmd");
  assert.equal(toolchain.resolveCommand("node", { platform: "linux", pathEnv: "bin:/usr/local/bin", isFile }), "/usr/local/bin/node");
  assert.equal(toolchain.resolveCommand("cargo", { platform: "linux", pathEnv: "/usr/local/bin", isFile }), null);
});

test("venv detection finds .venv/venv/env interpreters and names the interpreter kind, never its path", () => {
  const root = tempProject({ ".venv/bin/python": "", ".venv/pyvenv.cfg": "home = /usr/bin\n" });
  assert.equal(toolchain.projectVenvPython(root, "linux"), path.join(root, ".venv", "bin", "python"));
  assert.equal(toolchain.projectVenvPython(tempProject({ "README.md": "" }), "linux"), null);
  const winFiles = new Set(["C:\\proj\\env\\Scripts\\python.exe"]);
  assert.equal(toolchain.projectVenvPython("C:\\proj", "win32", (p) => winFiles.has(p)), "C:\\proj\\env\\Scripts\\python.exe");

  const none = () => false;
  assert.equal(toolchain.pythonExecutableKind("/x/.venv/bin/python", { venv: true }), "venv");
  assert.equal(toolchain.pythonExecutableKind("/home/a/.pyenv/shims/python3", { isFile: none }), "pyenv");
  assert.equal(toolchain.pythonExecutableKind("C:\\Users\\a\\.pyenv\\pyenv-win\\shims\\python.bat", { isFile: none }), "pyenv");
  assert.equal(toolchain.pythonExecutableKind("/opt/miniconda3/bin/python3", { isFile: none }), "conda");
  assert.equal(toolchain.pythonExecutableKind("/home/a/.asdf/shims/python3", { isFile: none }), "asdf");
  assert.equal(toolchain.pythonExecutableKind("/usr/bin/python3", { isFile: none }), "system");
  assert.equal(toolchain.pythonExecutableKind(path.join(root, ".venv", "bin", "python")), "venv");
});

test("pip freeze is sanitised: local and vcs references keep only the name, credentials and index options go", () => {
  const { lines, truncated } = toolchain.sanitizeFreezeLines([
    "requests==2.32.3",
    "--index-url https://user:secret@pypi.example.com/simple",
    "--extra-index-url https://token@pkgs.example.com/simple",
    "-i https://u:p@mirror/simple",
    "# Editable install with no version control (myproj==0.1.0)",
    "-e /home/alice/work/myproj",
    "-e git+https://alice:ghp_secret@github.com/acme/tool.git@0123abc#egg=acme-tool",
    "localpkg @ file:///home/alice/wheels/localpkg-1.0-py3-none-any.whl",
    "vcspkg @ git+https://bob:pass@gitlab.example.com/x/vcspkg.git@v1",
    "wheelpkg @ https://user:pw@files.example.com/wheelpkg-2.0.whl",
    "numpy==2.1.0 ; python_version >= \"3.10\"",
    "-e C:\\Users\\alice\\proj\\winpkg",
    "",
  ].join("\n"));
  assert.equal(truncated, false);
  assert.deepEqual(lines, [
    "requests==2.32.3",
    "myproj @ local",
    "acme-tool @ vcs",
    "localpkg @ local",
    "vcspkg @ vcs",
    "wheelpkg @ url",
    "numpy==2.1.0",
    "winpkg @ local",
  ]);
  const joined = lines.join("\n");
  for (const leak of ["alice", "bob", "secret", "ghp_", "token", "example.com", "/home", "C:\\"]) {
    assert.ok(!joined.includes(leak), `freeze output leaks ${leak}`);
  }
  const many = toolchain.sanitizeFreezeLines(Array.from({ length: 2500 }, (_, i) => `pkg${i}==1.0`).join("\n"));
  assert.equal(many.lines.length, 2000);
  assert.equal(many.truncated, true);
  const wide = toolchain.sanitizeFreezeLines(Array.from({ length: 1500 }, (_, i) => `${"p".repeat(60)}${i}==1.0`).join("\n"));
  assert.ok(wide.truncated);
  assert.ok(Buffer.byteLength(wide.lines.join("\n")) <= 64 * 1024);
});

test("pip freeze runs only with a Python manifest, against the project venv, preferring uv", async () => {
  const root = tempProject({ "pyproject.toml": "[project]\nname='x'\n", ".venv/bin/python": "", ".venv/pyvenv.cfg": "", "package-lock.json": "{}", "package.json": "{}" });
  const calls = [];
  const result = await toolchain.collectToolchain(root, {
    resolve: (command) => (["python3", "uv", "node"].includes(command) ? `/usr/bin/${command}` : null),
    run: fakeRun({
      python3: ok("Python 3.11.9\n"),
      python: ok("Python 3.11.9\n"),
      node: ok("v22.19.0\n"),
      uv: (args) => (args[0] === "pip" ? ok("Django==5.1\n-e /home/alice/proj\n") : ok("uv 0.5.0\n")),
    }, calls),
  });
  assert.equal(result.python_executable_kind, "venv");
  assert.equal(result.versions.venv_python, "Python 3.11.9");
  assert.equal(result.pip_freeze_tool, "uv");
  assert.deepEqual(result.pip_freeze, ["Django==5.1", "proj @ local"]);
  assert.deepEqual(result.manifests, ["package.json", "pyproject.toml"]);
  assert.deepEqual(result.lockfiles, ["package-lock.json"]);
  const freeze = calls.find((call) => call.args[0] === "pip");
  assert.deepEqual(freeze.args, ["pip", "freeze", "--python", path.join(root, ".venv", "bin", "python")]);

  // No uv: python -m pip freeze. No Python manifest: no freeze at all.
  const pipCalls = [];
  const viaPip = await toolchain.collectToolchain(root, {
    resolve: (command) => (command === "python3" ? "/usr/bin/python3" : null),
    run: fakeRun({ python3: ok("Python 3.11.9\n"), python: ok("attrs==24.2.0\n") }, pipCalls),
  });
  assert.equal(viaPip.pip_freeze_tool, "pip");
  assert.deepEqual(viaPip.pip_freeze, ["attrs==24.2.0"]);
  assert.ok(pipCalls.some((call) => call.file.endsWith(path.join(".venv", "bin", "python")) && call.args.join(" ") === "-m pip freeze --disable-pip-version-check"));
  const nodeOnly = await toolchain.collectToolchain(tempProject({ "package.json": "{}" }), {
    resolve: (command) => `/usr/bin/${command}`,
    run: fakeRun({ python3: ok("Python 3.11.9\n"), uv: ok("Django==5.1\n") }),
  });
  assert.equal(nodeOnly.pip_freeze, undefined);
  assert.equal(nodeOnly.python_executable_kind, "system");
  assert.equal(nodeOnly.skipped?.npm_ls, "not_installed", "a package.json without node_modules says why there is no npm ls");
});

test("a script-only Python project (main.py, no manifest) still records pip freeze of its interpreter", async () => {
  const root = tempProject({ "main.py": "print('hi')\n", "feature.py": "x = 1\n" });
  const result = await toolchain.collectToolchain(root, {
    resolve: (command) => (command === "python3" ? "/usr/bin/python3" : null),
    run: fakeRun({ python3: (args) => (args[0] === "-m" ? ok("requests==2.32.3\n") : ok("Python 3.12.1\n")) }),
  });
  assert.equal(result.pip_freeze_tool, "pip");
  assert.deepEqual(result.pip_freeze, ["requests==2.32.3"]);
  assert.deepEqual(result.manifests, []);
});

test("the cache collects once per project and again only when its manifest/lockfile set changes", async () => {
  const root = tempProject({ "package.json": "{}" });
  let runs = 0;
  const cache = new toolchain.ToolchainCache({
    waitMs: 10_000,
    env: {},
    resolve: (command) => (command === "node" ? "/usr/bin/node" : null),
    run: async () => {
      runs += 1;
      return ok(`v22.${runs}.0\n`);
    },
  });
  const first = await cache.get(root);
  const second = await cache.get(root);
  assert.equal(first.versions.node, "v22.1.0");
  assert.equal(second, first);
  assert.equal(cache.collections, 1);
  fs.writeFileSync(path.join(root, "README.md"), "unrelated\n");
  assert.equal((await cache.get(root)).versions.node, "v22.1.0");
  assert.equal(cache.collections, 1);
  fs.writeFileSync(path.join(root, "package-lock.json"), "{}");
  const third = await cache.get(root);
  assert.equal(cache.collections, 2);
  assert.equal(third.versions.node, "v22.2.0");
  assert.deepEqual(third.lockfiles, ["package-lock.json"]);
});

test("the cache waits only a bounded time; a slow collection lands on a later upload", async () => {
  const root = tempProject({ "package.json": "{}" });
  let release;
  const gate = new Promise((resolve) => (release = resolve));
  const cache = new toolchain.ToolchainCache({
    waitMs: 50,
    resolve: (command) => (command === "node" ? "/usr/bin/node" : null),
    run: async () => {
      await gate;
      return ok("v22.19.0\n");
    },
  });
  const started = Date.now();
  assert.equal(await new toolchain.ToolchainCache({ resolve: () => "/usr/bin/node", run: () => gate.then(() => null) }).get(root), null, "by default get never waits");
  assert.equal(await cache.get(root), null);
  assert.ok(Date.now() - started < 1_000);
  release();
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal((await cache.get(root)).versions.node, "v22.19.0");
  assert.equal(cache.collections, 1);
});

async function envelopesFrom(options, { beforeStopMs = 0 } = {}) {
  const root = tempProject({ "package.json": "{}", "requirements.txt": "attrs\n", "README.md": "# demo\n" });
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "omnirush-toolchain-state-"));
  const envelopes = [];
  const sync = new SessionUploader({
    stateDir,
    fallbackScanMs: 60_000,
    capabilities: async () => ({ schema_versions: [2], canonical_trace: false }),
    upload: async (_sessionId, compressed) => {
      envelopes.push(JSON.parse(zlib.zstdDecompressSync(Buffer.from(compressed)).toString("utf8")));
      return new Response("{}", { status: 201 });
    },
    ...options,
  });
  const sessionId = "01a0dcd2-d8ee-7222-80eb-240063770430";
  sync.startSession(sessionId, "ws", root);
  await sync.idle(sessionId);
  if (beforeStopMs) await new Promise((resolve) => setTimeout(resolve, beforeStopMs));
  await sync.stop();
  return envelopes;
}

test.skipIf(!hasZstd)("the upload envelope carries environment.toolchain, scrubbed, next to the existing fields", async () => {
  const envelopes = await envelopesFrom({
    toolchain: {
      resolve: (command) => (["node", "python3"].includes(command) ? `/usr/bin/${command}` : null),
      run: fakeRun({
        node: ok("v22.19.0\n"),
        python3: (args) => (args[0] === "--version" ? ok("Python 3.12.3\n") : ok("attrs==24.2.0\nsecretpkg @ https://user:hunter2@example.com/x.whl\n")),
      }),
    },
  });
  assert.ok(envelopes.length >= 1);
  const environment = envelopes.at(-1).environment;
  assert.equal(typeof environment.node_version, "string");
  assert.deepEqual(environment.toolchain.versions, { node: "v22.19.0", python3: "Python 3.12.3" });
  assert.deepEqual(environment.toolchain.pip_freeze, ["attrs==24.2.0", "secretpkg @ url"]);
  assert.deepEqual(environment.toolchain.manifests, ["package.json", "requirements.txt"]);
  assert.equal(environment.toolchain.python_executable_kind, "system");
  assert.ok(!JSON.stringify(environment.toolchain).includes("hunter2"));
  for (const envelope of envelopes) {
    if (envelope.environment.toolchain) assert.deepEqual(envelope.environment.toolchain, environment.toolchain);
  }
});

test.skipIf(!hasZstd)("toolchain: false sends the environment block as before", async () => {
  const envelopes = await envelopesFrom({ toolchain: false });
  assert.ok(envelopes.length >= 1);
  assert.equal("toolchain" in envelopes[0].environment, false);
  assert.equal(typeof envelopes[0].environment.os, "string");
});

test.skipIf(!hasZstd)("an upload never waits for a slow collection: the start envelope goes without it, a later one carries it", async () => {
  const started = Date.now();
  const envelopes = await envelopesFrom({
    toolchain: {
      resolve: (command) => (command === "node" ? "/usr/bin/node" : null),
      run: () => new Promise((resolve) => setTimeout(() => resolve(ok("v22.19.0\n")), 400)),
    },
  }, { beforeStopMs: 700 });
  const start = envelopes.find((envelope) => envelope.snapshot_type === "start");
  const end = envelopes.find((envelope) => envelope.snapshot_type === "end");
  assert.equal("toolchain" in start.environment, false);
  assert.deepEqual(end.environment.toolchain.versions, { node: "v22.19.0" });
  assert.ok(Date.now() - started < 5_000);
});

test.skipIf(!hasZstd)("a short session still records it: the last snapshot waits briefly for a collection in flight", async () => {
  const envelopes = await envelopesFrom({
    toolchain: {
      resolve: (command) => (command === "node" ? "/usr/bin/node" : null),
      run: () => new Promise((resolve) => setTimeout(() => resolve(ok("v22.19.0\n")), 800)),
    },
  });
  const start = envelopes.find((envelope) => envelope.snapshot_type === "start");
  const end = envelopes.find((envelope) => envelope.snapshot_type === "end");
  assert.equal("toolchain" in start.environment, false);
  assert.deepEqual(end.environment.toolchain.versions, { node: "v22.19.0" });
});

// Nested projects: a monorepo's apps/web and apps/api, a backend/python with
// its own venv. Manifests are searched a few levels down, each Python project
// is frozen with the environment next to it, each installed Node folder gets
// its own npm ls, and the size caps are shared between them.

const npmTree = (name, deps) => ok(JSON.stringify({ name, version: "1.0.0", dependencies: Object.fromEntries(Object.entries(deps).map(([dep, version]) => [dep, { version }])) }));

test("nested: backend/python with its venv records its manifests, venv interpreter and pip freeze; frontend its npm ls", async () => {
  const root = tempProject({
    "README.md": "# app\n",
    "backend/python/requirements.txt": "fastapi\n",
    "backend/python/venv/pyvenv.cfg": "home = /usr/bin\n",
    "backend/python/venv/bin/python": "",
    "backend/python/venv/lib/python3.12/site-packages/fastapi/setup.py": "",
    "frontend/package.json": "{}",
    "frontend/package-lock.json": "{}",
    "frontend/node_modules/react/package.json": "{}",
  });
  const calls = [];
  const result = await toolchain.collectToolchain(root, {
    env: {},
    resolve: (command) => (["python3", "npm"].includes(command) ? `/usr/bin/${command}` : null),
    run: fakeRun({
      python3: ok("Python 3.10.12\n"),
      python: (args) => (args[0] === "--version" ? ok("Python 3.12.3\n") : ok("fastapi==0.115.0\nuvicorn==0.30.6\n")),
      npm: (args) => (args[0] === "ls" ? npmTree("frontend", { react: "18.3.1" }) : ok("10.8.2\n")),
    }, calls),
  });
  assert.deepEqual(result.manifests, ["backend/python/requirements.txt", "frontend/package.json"]);
  assert.deepEqual(result.lockfiles, ["frontend/package-lock.json"]);
  assert.equal(result.python_executable_kind, "venv");
  assert.equal(result.versions.venv_python, "Python 3.12.3");
  assert.equal(result.versions.python3, "Python 3.10.12");
  assert.deepEqual(result.pip_freeze, ["fastapi==0.115.0", "uvicorn==0.30.6"], "old consumers: the first project's freeze at the top level");
  assert.equal(result.pip_freeze_tool, "pip");
  assert.equal(result.pip_freeze_dir, "backend/python");
  assert.deepEqual(result.pip_freeze_by_dir, { "backend/python": ["fastapi==0.115.0", "uvicorn==0.30.6"] });
  assert.deepEqual(result.python_executable_kind_by_dir, { "backend/python": "venv" });
  assert.deepEqual(result.venv_python_by_dir, { "backend/python": "Python 3.12.3" });
  assert.deepEqual(result.npm_ls, { name: "frontend", version: "1.0.0", dependencies: { react: "18.3.1" } });
  assert.equal(result.npm_ls_dir, "frontend");
  assert.deepEqual(result.npm_ls_by_dir, { frontend: { name: "frontend", version: "1.0.0", dependencies: { react: "18.3.1" } } });
  assert.equal(result.skipped, undefined);
  const venvPython = path.join(root, "backend", "python", "venv", "bin", "python");
  const freeze = calls.find((call) => call.args[0] === "-m");
  assert.equal(freeze.file, venvPython);
  assert.equal(freeze.cwd, path.join(root, "backend", "python"));
  assert.equal(calls.find((call) => call.args[0] === "ls").cwd, path.join(root, "frontend"));
  assert.ok(!calls.some((call) => call.file === "/usr/bin/python3" && call.args[0] === "-m"), "the system interpreter is not frozen for a project with its own venv");
  assert.ok(!JSON.stringify(result).includes(root), "no absolute path is recorded");

  // Without node_modules the nested package.json says why there is no npm ls.
  const bare = await toolchain.collectToolchain(tempProject({ "web/package.json": "{}" }), { env: {}, resolve: () => null, run: fakeRun({}) });
  assert.deepEqual(bare.manifests, ["web/package.json"]);
  assert.equal(bare.skipped?.npm_ls, "not_installed");
});

test("nested: a monorepo with apps/web and apps/api; a venv above a project is found; one interpreter is frozen once", async () => {
  const root = tempProject({
    "package.json": "{}",
    "pnpm-lock.yaml": "",
    "node_modules/turbo/package.json": "{}",
    "apps/web/package.json": "{}",
    "apps/web/node_modules/next/package.json": "{}",
    "apps/api/pyproject.toml": "[project]\nname='api'\n",
    "apps/api/.venv/pyvenv.cfg": "",
    "apps/api/.venv/bin/python": "",
    "apps/api/worker/requirements.txt": "celery\n",
    "apps/docs/package.json": "{}",
    "tools/requirements-dev.txt": "ruff\n",
  });
  const calls = [];
  const result = await toolchain.collectToolchain(root, {
    env: {},
    resolve: (command) => (["python3", "npm", "uv"].includes(command) ? `/usr/bin/${command}` : null),
    run: fakeRun({
      python3: ok("Python 3.11.9\n"),
      python: ok("Python 3.12.3\n"),
      uv: (args) => {
        if (args[0] !== "pip") return ok("uv 0.5.0\n");
        return args[3].includes(".venv") ? ok("fastapi==0.115.0\n") : ok("ruff==0.6.9\n");
      },
      npm: (args) => {
        if (args[0] !== "ls") return ok("10.8.2\n");
        return calls.at(-1).cwd.endsWith("web") ? npmTree("web", { next: "15.0.3" }) : npmTree("mono", { turbo: "2.1.0" });
      },
    }, calls),
  });
  assert.deepEqual(result.manifests, ["apps/api/pyproject.toml", "apps/api/worker/requirements.txt", "apps/docs/package.json", "apps/web/package.json", "package.json", "tools/requirements-dev.txt"]);
  assert.deepEqual(result.lockfiles, ["pnpm-lock.yaml"]);
  // The root is a Node project only: the first Python project found (shallowest, then by name) is the top level.
  assert.equal(result.pip_freeze_dir, "tools");
  assert.deepEqual(result.pip_freeze, ["ruff==0.6.9"]);
  assert.equal(result.python_executable_kind, "system");
  assert.equal(result.pip_freeze_tool, "uv");
  assert.deepEqual(result.pip_freeze_by_dir, {
    tools: ["ruff==0.6.9"],
    "apps/api": ["fastapi==0.115.0"],
    "apps/api/worker": ["fastapi==0.115.0"],
  });
  assert.deepEqual(result.python_executable_kind_by_dir, { tools: "system", "apps/api": "venv", "apps/api/worker": "venv" });
  assert.deepEqual(result.venv_python_by_dir, { "apps/api": "Python 3.12.3", "apps/api/worker": "Python 3.12.3" });
  const freezes = calls.filter((call) => call.args[0] === "pip");
  assert.equal(freezes.length, 2, "apps/api and its worker share the .venv: frozen once");
  assert.equal(result.npm_ls_dir, ".");
  assert.deepEqual(result.npm_ls.dependencies, { turbo: "2.1.0" });
  assert.deepEqual(Object.keys(result.npm_ls_by_dir), [".", "apps/web"]);
  assert.deepEqual(result.npm_ls_by_dir["apps/web"].dependencies, { next: "15.0.3" });
  assert.equal(calls.filter((call) => call.args[0] === "ls").length, 2, "apps/docs has no node_modules: no npm ls there");

  // A project whose root alone is Python looks exactly as before: no per-folder fields.
  const flat = await toolchain.collectToolchain(tempProject({ "requirements.txt": "attrs\n", ".venv/pyvenv.cfg": "", ".venv/bin/python": "" }), {
    env: {},
    resolve: () => null,
    run: fakeRun({ python: (args) => (args[0] === "--version" ? ok("Python 3.12.3\n") : ok("attrs==24.2.0\n")) }),
  });
  assert.deepEqual(flat.pip_freeze, ["attrs==24.2.0"]);
  assert.equal(flat.python_executable_kind, "venv");
  for (const key of ["pip_freeze_dir", "pip_freeze_by_dir", "python_executable_kind_by_dir", "venv_python_by_dir", "npm_ls_dir", "npm_ls_by_dir"]) {
    assert.equal(flat[key], undefined, key);
  }
});

test("nested: dependency, build, cache and environment folders are never searched; three levels down at most; no symlinks", async () => {
  const root = tempProject({
    "package.json": "{}",
    "node_modules/left-pad/package.json": "{}",
    ".git/package.json": "{}",
    ".cache/pyproject.toml": "",
    ".tox/py312/setup.py": "",
    "dist/package.json": "{}",
    "build/requirements.txt": "",
    "target/Cargo.toml": "",
    "vendor/github.com/x/go.mod": "",
    "__pycache__/setup.py": "",
    "env/pyvenv.cfg": "",
    "env/lib/python3.12/site-packages/pkg/setup.py": "",
    "myenv/pyvenv.cfg": "",
    "myenv/lib/python3.12/site-packages/other/pyproject.toml": "",
    "conda/conda-meta/history": "",
    "conda/lib/pkg/setup.py": "",
    "a/b/c/go.mod": "",
    "a/b/c/d/Cargo.toml": "",
    "a/b/c/venv/pyvenv.cfg": "",
    "services/api/Gemfile": "",
    "services/api/Gemfile.lock": "",
    "services/java/pom.xml": "",
    "services/java/build.gradle.kts": "",
    "services/py/setup.cfg": "",
    "services/py/Pipfile": "",
    "services/py/poetry.lock": "",
    "services/py/uv.lock": "",
    "services/js/bun.lockb": "",
    "services/js/yarn.lock": "",
  });
  if (process.platform !== "win32") fs.symlinkSync(path.join(root, "services"), path.join(root, "link"), "dir");
  const files = await toolchain.projectFiles(root);
  assert.deepEqual(files.manifests, [
    "a/b/c/go.mod",
    "package.json",
    "services/api/Gemfile",
    "services/java/build.gradle.kts",
    "services/java/pom.xml",
    "services/py/Pipfile",
    "services/py/setup.cfg",
  ]);
  assert.deepEqual(files.lockfiles, ["services/api/Gemfile.lock", "services/js/bun.lockb", "services/js/yarn.lock", "services/py/poetry.lock", "services/py/uv.lock"]);
  // Any folder with pyvenv.cfg is an environment, found at the last level too.
  assert.deepEqual(files.venvs, ["a/b/c/venv", "env", "myenv"]);
  assert.deepEqual(files.pythonDirs, [".", "services/py", "a/b/c"], "shallowest first");
  assert.equal(files.truncated, false);
  assert.equal(toolchain.venvFor("services/py", files.venvs), "env", "the nearest environment above, preferred names first");
  assert.equal(toolchain.venvFor("a/b/c", files.venvs), "a/b/c/venv");
  assert.equal(toolchain.venvFor(".", ["myenv", ".venv", "venv"]), ".venv");
  assert.equal(toolchain.venvFor("x", []), null);
});

test("nested: the search stops at 200 folders and 2 s, and says so", async () => {
  const many = {};
  for (let i = 0; i < 260; i += 1) many[`pkg${String(i).padStart(3, "0")}/package.json`] = "{}";
  const root = tempProject(many);
  const files = await toolchain.projectFiles(root);
  assert.equal(files.truncated, true);
  assert.equal(files.manifests.length, 199, "the root and 199 folders read");
  assert.equal(toolchain.MANIFEST_SCAN_MAX_DIRS, 200);
  assert.equal(toolchain.MANIFEST_SCAN_BUDGET_MS, 2_000);

  let clock = 0;
  const slow = await toolchain.projectFiles(root, { now: () => (clock += 500) });
  assert.equal(slow.truncated, true);
  assert.ok(slow.manifests.length <= 4, `${slow.manifests.length} folders read past the deadline`);

  const result = await toolchain.collectToolchain(root, { env: {}, files, resolve: () => null, run: fakeRun({}) });
  assert.equal(result.manifests_truncated, true);
  assert.equal(result.manifests.length, 199);
});

test("nested: more than 8 projects are not all probed; the freeze caps are shared, the top level keeps its own", async () => {
  const layout = {};
  for (let i = 0; i < 10; i += 1) {
    layout[`svc${i}/requirements.txt`] = "x\n";
    layout[`svc${i}/.venv/pyvenv.cfg`] = "";
    layout[`svc${i}/.venv/bin/python`] = "";
  }
  const root = tempProject(layout);
  const freezeOf = (cwd) => {
    const n = Number(/svc(\d)/.exec(cwd)[1]);
    // svc0: small; the rest: 1500 entries each.
    return n === 0 ? "tiny==1.0\n" : Array.from({ length: 1500 }, (_, i) => `svc${n}-package-with-a-long-name-${i}==1.0.${i}`).join("\n");
  };
  const calls = [];
  const result = await toolchain.collectToolchain(root, {
    env: {},
    resolve: () => null,
    run: async (file, args, options) => {
      calls.push({ file, args, cwd: options.cwd });
      return args[0] === "--version" ? ok("Python 3.12.3\n") : ok(freezeOf(options.cwd));
    },
  });
  assert.equal(result.projects_truncated, true);
  assert.equal(calls.filter((call) => call.args[0] === "-m").length, 8);
  const byDir = result.pip_freeze_by_dir;
  assert.equal(Object.keys(byDir).length, 8);
  assert.deepEqual(byDir.svc0, ["tiny==1.0"]);
  const all = Object.values(byDir).flat();
  assert.ok(all.length <= toolchain.MAX_FREEZE_LINES, `${all.length} lines in all`);
  assert.ok(all.reduce((sum, line) => sum + Buffer.byteLength(line) + 1, 0) <= toolchain.MAX_FREEZE_BYTES);
  assert.deepEqual(result.pip_freeze_truncated_dirs, ["svc1", "svc2", "svc3", "svc4", "svc5", "svc6", "svc7"]);
  assert.equal(result.pip_freeze_dir, "svc0");
  assert.deepEqual(result.pip_freeze, ["tiny==1.0"]);

  assert.deepEqual(toolchain.splitBudget([10, 5000, 5000], 2000), [10, 995, 995]);
  assert.deepEqual(toolchain.splitBudget([100, 200], 2000), [100, 200]);
  assert.deepEqual(toolchain.splitBudget([], 2000), []);

  // npm ls: one 64 KiB cap shared between folders.
  const web = tempProject({ "a/package.json": "{}", "a/node_modules/x/package.json": "{}", "b/package.json": "{}", "b/node_modules/x/package.json": "{}" });
  const big = (prefix) => ok(JSON.stringify({ dependencies: Object.fromEntries(Array.from({ length: 3000 }, (_, i) => [`${prefix}-dependency-${i}`, { version: "1.2.3" }])) }));
  const npm = await toolchain.collectToolchain(web, {
    env: {},
    resolve: (command) => (command === "npm" ? "/usr/bin/npm" : null),
    run: async (_file, args, options) => (args[0] === "ls" ? big(path.basename(options.cwd)) : ok("10.8.2\n")),
  });
  assert.equal(npm.npm_ls_dir, "a");
  assert.ok(npm.npm_ls.truncated);
  const sizes = Object.values(npm.npm_ls_by_dir).map((summary) => JSON.stringify(summary).length);
  assert.equal(sizes.length, 2);
  assert.ok(sizes.reduce((a, b) => a + b, 0) <= toolchain.MAX_NPM_LS_BYTES + 64, sizes.join(" + "));
  assert.ok(Object.values(npm.npm_ls_by_dir).every((summary) => summary.truncated));
});

test.skipIf(process.platform === "win32")("nested: a project's freeze that hangs is killed at its timeout; the others are still recorded", async () => {
  const script = (freeze) => `#!/bin/sh\nif [ "$1" = "--version" ]; then echo "Python 3.12.3"; exit 0; fi\n${freeze}\n`;
  const root = tempProject({
    "fast/requirements.txt": "attrs\n",
    "fast/venv/pyvenv.cfg": "",
    "fast/venv/bin/python": script('echo "attrs==24.2.0"'),
    "slow/requirements.txt": "attrs\n",
    "slow/venv/pyvenv.cfg": "",
    "slow/venv/bin/python": script("exec sleep 30"),
  });
  fs.chmodSync(path.join(root, "fast/venv/bin/python"), 0o755);
  fs.chmodSync(path.join(root, "slow/venv/bin/python"), 0o755);
  const started = Date.now();
  const result = await toolchain.collectToolchain(root, { env: {}, resolve: () => null, freezeTimeoutMs: 300, probes: [] });
  assert.ok(Date.now() - started < 5_000, `took ${Date.now() - started} ms`);
  assert.deepEqual(result.pip_freeze_by_dir, { fast: ["attrs==24.2.0"] });
  assert.deepEqual(result.python_executable_kind_by_dir, { fast: "venv", slow: "venv" });
  assert.deepEqual(result.venv_python_by_dir, { fast: "Python 3.12.3", slow: "Python 3.12.3" });
});

test("nested: the cache collects again when a nested manifest or environment changes", async () => {
  const root = tempProject({ "backend/requirements.txt": "attrs\n" });
  const cache = new toolchain.ToolchainCache({ waitMs: 10_000, env: {}, resolve: () => null, run: fakeRun({}) });
  await cache.get(root);
  await cache.get(root);
  assert.equal(cache.collections, 1);
  fs.mkdirSync(path.join(root, "backend", "venv"));
  fs.writeFileSync(path.join(root, "backend", "venv", "pyvenv.cfg"), "");
  await cache.get(root);
  assert.equal(cache.collections, 2);
  fs.writeFileSync(path.join(root, "backend", "requirements.txt"), "attrs\nrequests\n");
  const last = await cache.get(root);
  assert.equal(cache.collections, 3);
  assert.deepEqual(last.manifests, ["backend/requirements.txt"]);
});

test("client-raw: the cache keeps one block per upload rules, and raw keeps values, freeze lines and paths as found", async () => {
  const rules = await import("./context/redact-policy.js");
  const { redactUploadJson } = await import("./session-uploader.js");
  const token = "ghp_" + "R8kq2Lw0Zt7Yb3Nc5Vx1Hd9Pf4Gs6Jm2Qa8E";
  const root = tempProject({ "package.json": "{}", ".env": `API_TOKEN=${token}\nOWNER=jane.roe@acme.test\nPORT=3000\n` });
  const cache = new toolchain.ToolchainCache({ waitMs: 10_000, env: {}, resolve: () => null, scrub: (block) => redactUploadJson(block).value as typeof block });
  const values = (block) => Object.fromEntries((block?.env_files?.[0]?.keys ?? []).map((key) => [key.name, key.value]));
  const legacy = await cache.get(root);
  const raw = await rules.withRedactionPolicy("client-raw", () => cache.get(root));
  const legacyAgain = await cache.get(root);
  assert.deepEqual(values(raw), { API_TOKEN: token, OWNER: "jane.roe@acme.test", PORT: "3000" });
  assert.equal(values(legacy).API_TOKEN, undefined);
  assert.equal(values(legacyAgain).API_TOKEN, undefined, "legacy never takes the raw block");
  assert.equal(cache.collections, 2);
  rules.withRedactionPolicy("client-raw", () => {
    const freeze = "requests==2.31.0\nlib @ git+https://bob:hunter2hunter@git.example/l.git\n# a comment\n";
    assert.deepEqual(toolchain.sanitizeFreezeLines(freeze).lines, ["requests==2.31.0", "lib @ git+https://bob:hunter2hunter@git.example/l.git"]);
    assert.equal(toolchain.parseProbeOutput("tool 1.2 (/home/jane/.local/bin/tool)\n", ""), "tool 1.2 (/home/jane/.local/bin/tool)");
  });
}, 30_000);
