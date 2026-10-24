// @ts-nocheck -- ported from the CLI suite (test/install-log.test.js); exercises loosely typed fakes.
import { test } from "bun:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import * as il from "./context/install-log.js";
import * as assets from "./context/install-log-assets.js";
import * as context from "./context/index.js";
import { engineInstallLogEnv, prepareDesktopInstallLog, resetDesktopInstallLog } from "./install-log-host.js";
import * as uploader from "./session-uploader.js";

// Install log (reproducible environments, phase 1): the engines' wrappers note
// package installs of the agent's shell; the capture context sends them as
// `context.install` lines with exact versions, and `context.env_turn` per turn,
// only while the server's capabilities say `install_log.enabled`.
const SCRUB = {
  text: (text) => uploader.redactUploadText(text).text,
  json: (value) => uploader.redactUploadJson(value).value,
  content: (p, text) => uploader.redactUploadContent(p, text),
};
const posix = process.platform !== "win32";
const tmpdir = (prefix) => fs.mkdtempSync(path.join(os.tmpdir(), prefix));
const has = (cmd) => spawnSync("sh", ["-c", `command -v ${cmd}`], { encoding: "utf8" }).status === 0;
const online = (() => {
  if (process.env.OMNIRUSH_TEST_OFFLINE === "1" || !has("npm")) return false;
  const probe = spawnSync("npm", ["view", "is-number@7.0.0", "version"], { encoding: "utf8", timeout: 20_000 });
  return probe.status === 0 && probe.stdout.trim() === "7.0.0";
})();

test("the embedded wrappers match their digests; the Windows one needs only kernel32", () => {
  const sha = (data) => createHash("sha256").update(data).digest("hex");
  assert.equal(sha(assets.POSIX_WRAPPER), assets.POSIX_WRAPPER_SHA256);
  assert.equal(sha(assets.PYTHON_HOOK), assets.PYTHON_HOOK_SHA256);
  const exe = Buffer.from(assets.WINDOWS_WRAPPER_BASE64, "base64");
  assert.equal(sha(exe), assets.WINDOWS_WRAPPER_SHA256);
  assert.equal(exe.subarray(0, 2).toString(), "MZ");
  assert.doesNotMatch(exe.toString("latin1"), /msvcrt|ucrtbase|api-ms-win-crt/i);
});

test("the server switch comes from the capabilities answer; a missing key is off", () => {
  assert.deepEqual(il.installLogGate({ schema_versions: [1, 2, 3], canonical_trace: true }), { enabled: false, samplePercent: 0 });
  assert.deepEqual(il.installLogGate({ install_log: { enabled: true, sample_percent: 10 } }), { enabled: true, samplePercent: 10 });
  assert.deepEqual(il.installLogGate({ install_log: { enabled: false, sample_percent: 100 } }), { enabled: false, samplePercent: 0 });
});

test("managed engines get the wrappers first on PATH (and only once the desktop prepared them)", async () => {
  const root = tmpdir("omnirush-pkglog-host-");
  try {
    resetDesktopInstallLog();
    assert.deepEqual(engineInstallLogEnv({ PATH: "/usr/bin" }), {});
    assert.equal(await prepareDesktopInstallLog(path.join(root, "state"), { OMNIRUSH_INSTALL_LOG: "0" }), null);
    const paths = await prepareDesktopInstallLog(path.join(root, "state"), {});
    assert.ok(paths);
    const env = engineInstallLogEnv({ PATH: "/usr/bin:/bin", PYTHONPATH: "/x" });
    assert.equal(env.PATH, `${paths.bin}${path.delimiter}/usr/bin:/bin`);
    assert.equal(env.PYTHONPATH, `${paths.py}${path.delimiter}/x`);
    assert.equal(env.OMNIRUSH_PKGLOG_DIR, paths.raw);
    if (posix) assert.ok(fs.lstatSync(path.join(paths.bin, "npm")).isSymbolicLink());
  } finally {
    resetDesktopInstallLog();
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("the wrapper is transparent and a broken log never breaks the tool", { skip: !posix }, async () => {
  const root = tmpdir("omnirush-pkglog-wrap-");
  try {
    const paths = await il.prepareInstallLog({ stateDir: path.join(root, "state") });
    const real = path.join(root, "real");
    fs.mkdirSync(real);
    fs.writeFileSync(path.join(real, "npm"), "#!/bin/sh\nprintf 'args:'; for a in \"$@\"; do printf ' [%s]' \"$a\"; done; printf '\\n'; cat; echo err >&2; exit 5\n", { mode: 0o755 });
    await il.setInstallLogActive(paths.raw, true);
    const env = { ...process.env, PATH: `${paths.bin}:${real}:/usr/bin:/bin`, OMNIRUSH_PKGLOG_DIR: paths.raw };
    const run = spawnSync("npm", ["install", "a b", "$X"], { env, input: "in", encoding: "utf8" });
    assert.equal(run.status, 5);
    assert.equal(run.stdout, "args: [install] [a b] [$X]\nin");
    assert.equal(run.stderr, "err\n");
    assert.equal(fs.readdirSync(paths.raw).filter((name) => name !== "on").length, 1);
    fs.rmSync(paths.raw, { recursive: true, force: true });
    const broken = spawnSync("npm", ["install", "x"], { env, input: "", encoding: "utf8" });
    assert.equal(broken.status, 5);
    assert.equal(broken.stdout, "args: [install] [x]\n");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("a continued session numbers its turns on from the turns it had", { skip: !posix }, async () => {
  const root = tmpdir("omnirush-pkglog-cont-");
  try {
    const paths = await il.prepareInstallLog({ stateDir: path.join(root, "state") });
    const events = [];
    const cap = new context.ContextCapture({
      client: "gui",
      scrub: SCRUB,
      record: (sessionId, type, data) => events.push({ sessionId, type, data }),
      sections: { system_packages: false, services: false, setup: false, pm_config: false, shell_aliases: false, processes: false },
      network: false,
      installLog: { raw: paths.raw, bin: paths.bin, gate: async () => ({ enabled: true, samplePercent: 100 }) },
    });
    cap.sessionStarted("ses_gui_new1", root);
    cap.sessionStarted("ses_gui_cont1", root, undefined, 3);
    await new Promise((resolve) => setTimeout(resolve, 300));
    const envTurns = () => events.filter((e) => e.type === "context.env_turn");
    for (const id of ["ses_gui_new1", "ses_gui_cont1", "ses_gui_cont1"]) {
      const before = envTurns().length;
      cap.turnStarted(id);
      cap.turnEnded(id);
      cap.turnMessages(id, [], true);
      for (let i = 0; i < 200 && envTurns().length === before; i++) await new Promise((resolve) => setTimeout(resolve, 100));
    }
    assert.deepEqual(envTurns().map((e) => [e.sessionId, e.data.turn]), [["ses_gui_new1", 1], ["ses_gui_cont1", 4], ["ses_gui_cont1", 5]]);
    cap.sessionEnded("ses_gui_new1");
    cap.sessionEnded("ses_gui_cont1");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("integration: an npm install the engine's shell runs becomes one context.install line with exact versions", { skip: !posix || !online, timeout: 180_000 }, async () => {
  const root = tmpdir("omnirush-pkglog-npm-");
  try {
    const paths = await il.prepareInstallLog({ stateDir: path.join(root, "state") });
    const project = path.join(root, "proj");
    fs.mkdirSync(project);
    fs.writeFileSync(path.join(project, "package.json"), JSON.stringify({ name: "p", version: "1.0.0" }));
    const events = [];
    const cap = new context.ContextCapture({
      client: "gui",
      scrub: SCRUB,
      record: (sessionId, type, data) => events.push({ sessionId, type, data }),
      sections: { system_packages: false, services: false, setup: false, pm_config: false, shell_aliases: false, processes: false },
      network: false,
      installLog: { raw: paths.raw, bin: paths.bin, gate: async () => ({ enabled: true, samplePercent: 100 }) },
    });
    cap.sessionStarted("ses_gui_pkglog1", project);
    cap.turnStarted("ses_gui_pkglog1");
    for (let i = 0; i < 50 && !fs.existsSync(path.join(paths.raw, "on")); i++) await new Promise((resolve) => setTimeout(resolve, 100));
    const env = { ...process.env, ...il.installLogEnv(paths, process.env), npm_config_audit: "false", npm_config_fund: "false" };
    cap.toolEvent("ses_gui_pkglog1", { callId: "call_1", tool: "bash", status: "running", command: "npm i is-number@7.0.0", workdir: project, at: Date.now() });
    const run = spawnSync("sh", ["-c", "npm i is-number@7.0.0 --registry https://registry.npmjs.org/"], { cwd: project, env, encoding: "utf8", timeout: 120_000 });
    assert.equal(run.status, 0, run.stderr);
    cap.toolEvent("ses_gui_pkglog1", { callId: "call_1", tool: "bash", status: "completed", at: Date.now() });
    cap.turnEnded("ses_gui_pkglog1");
    cap.turnMessages("ses_gui_pkglog1", [], true);
    for (let i = 0; i < 200 && !events.some((e) => e.type === "context.env_turn"); i++) await new Promise((resolve) => setTimeout(resolve, 100));
    const lines = events.filter((e) => e.type === "context.install").map((e) => JSON.parse(JSON.stringify(e.data)));
    assert.equal(lines.length, 1);
    assert.equal(lines[0].call, "call_1");
    assert.deepEqual(lines[0].resolved.map((p) => `${p.name}@${p.version}`), ["is-number@7.0.0"]);
    assert.equal(lines[0].lockfile_rel, "package-lock.json");
    assert.ok(events.some((e) => e.type === "context.env_turn" && e.data.installs === 1));
    cap.sessionEnded("ses_gui_pkglog1");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("the uploader reads the switch from the host's capabilities, or asks the server itself with its own gateway token", async () => {
  const root = tmpdir("omnirush-pkglog-gate-");
  try {
    const paths = await il.prepareInstallLog({ stateDir: path.join(root, "pk") });
    const asked = [];
    const fetcher = async (url, init) => {
      asked.push({ url: String(url), auth: init?.headers?.Authorization ?? null });
      return Response.json({ schema_versions: [1, 2, 3], canonical_trace: true, install_log: { enabled: true, sample_percent: 100 } });
    };
    const viaToken = new uploader.SessionUploader({ stateDir: path.join(root, "a"), gatewayUrl: "http://127.0.0.1:9/omnirush/v1", accessToken: "tok-e2e", fetch: fetcher, installLog: { raw: paths.raw, bin: paths.bin }, context: { sections: { system_packages: false, services: false, setup: false, pm_config: false, shell_aliases: false, processes: false }, network: false } });
    viaToken.startSession("ses_gate_token_01", "ws", root);
    for (let i = 0; i < 50 && !fs.existsSync(path.join(paths.raw, "on")); i++) await new Promise((resolve) => setTimeout(resolve, 100));
    assert.equal(fs.existsSync(path.join(paths.raw, "on")), true);
    assert.ok(asked.some((call) => call.url === "http://127.0.0.1:9/omnirush/collect/capabilities" && call.auth === "Bearer tok-e2e"), JSON.stringify(asked));
    await il.setInstallLogActive(paths.raw, false);
    const off = new uploader.SessionUploader({ stateDir: path.join(root, "b"), upload: async () => new Response("{}", { status: 201 }), capabilities: async () => ({ schema_versions: [1, 2, 3], canonical_trace: true }), installLog: { raw: paths.raw, bin: paths.bin }, context: { sections: { system_packages: false, services: false, setup: false, pm_config: false, shell_aliases: false, processes: false }, network: false } });
    off.startSession("ses_gate_off_0001", "ws", root);
    await new Promise((resolve) => setTimeout(resolve, 500));
    assert.equal(fs.existsSync(path.join(paths.raw, "on")), false, "an answer without install_log is off");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("the shared install drain resolves each install under its own session's pinned rules", { skip: !posix }, async () => {
  const rules = await import("./context/redact-policy.js");
  const root = tmpdir("omnirush-pkglog-pin-");
  try {
    const project = path.join(root, "proj");
    fs.mkdirSync(project, { recursive: true });
    const paths = await il.prepareInstallLog({ stateDir: path.join(root, "state") });
    const real = path.join(root, "real");
    fs.mkdirSync(real, { recursive: true });
    fs.writeFileSync(path.join(real, "npm"), "#!/bin/sh\nexit 0\n", { mode: 0o755 });
    const events = [];
    const pins = { ses_gui_pin_raw: { policy: "client-raw" }, ses_gui_pin_old: { policy: "legacy" } };
    const cap = new context.ContextCapture({
      client: "gui",
      scrub: SCRUB,
      record: (sessionId, type, data) => events.push({ sessionId, type, data }),
      sections: { system_packages: false, services: false, setup: false, pm_config: false, shell_aliases: false, processes: false },
      network: false,
      installLog: { raw: paths.raw, bin: paths.bin, gate: async () => ({ enabled: true, samplePercent: 100 }) },
      pin: (sessionId) => pins[sessionId],
    });
    for (const id of Object.keys(pins)) {
      cap.sessionStarted(id, project);
      cap.turnStarted(id);
    }
    for (let i = 0; i < 200 && !fs.existsSync(path.join(paths.raw, "on")); i++) await new Promise((resolve) => setTimeout(resolve, 100));
    const env = { ...process.env, ...il.installLogEnv(paths, process.env), PATH: `${paths.bin}:${real}:/usr/bin:/bin` };
    const secret = "--registry=https://bob:hunter2Secret@registry.example.com/";
    const t0 = Date.now();
    for (const id of Object.keys(pins)) cap.toolEvent(id, { callId: `call_${id}`, tool: "bash", status: "running", command: "npm install x", workdir: project, at: t0 });
    for (const id of Object.keys(pins)) assert.equal(spawnSync("npm", ["install", "x", secret], { cwd: project, env: { ...env, OMNIRUSH_CALL: `call_${id}`, OMNIRUSH_SESSION: id } }).status, 0);
    for (const id of Object.keys(pins)) cap.toolEvent(id, { callId: `call_${id}`, tool: "bash", status: "completed", at: Date.now() + 50 });
    rules.setRedactionPolicy("client-v3");
    for (const id of Object.keys(pins)) {
      cap.turnEnded(id);
      cap.turnMessages(id, [], true);
    }
    const installs = () => events.filter((e) => e.type === "context.install");
    for (let i = 0; i < 200 && installs().length < 2; i++) await new Promise((resolve) => setTimeout(resolve, 100));
    const argvOf = (id) => JSON.stringify(installs().find((e) => e.sessionId === id).data.argv);
    assert.ok(argvOf("ses_gui_pin_raw").includes("hunter2Secret"), "raw session keeps its argument");
    assert.ok(!argvOf("ses_gui_pin_old").includes("hunter2Secret"), "legacy session's argument is cleaned");
    for (const id of Object.keys(pins)) cap.sessionEnded(id);
  } finally {
    rules.setRedactionPolicy("legacy");
    fs.rmSync(root, { recursive: true, force: true });
  }
}, 60_000);
