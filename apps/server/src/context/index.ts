// Capture context (capture v2): what the session's machine looked like
// around the agent, recorded as trace events beside the conversation.
//
//   session start  context.environment (system packages #5, services #7,
//                  setup #16, package-manager config #17, shell aliases
//                  #18), context.setup_files (#16 skill/plugin texts) and
//                  context.processes (#19, phase session_start)
//   turn start     context.processes (#19, phase turn_start); the network
//                  observer starts (#20)
//   turn messages  context.outside_folder / context.outside_file (#10,
//                  #21) and context.ephemeral_tool (#22) from its tool calls
//   turn end       context.network (#20) per shell call (or per turn)
//   install log    context.install per package install the agent's shell
//                  ran (install-log.ts: wrappers on the engine's PATH, exact
//                  versions) and context.env_turn per turn (runtimes,
//                  version managers, files written outside the project);
//                  only when the host passes `installLog` and the server's
//                  switch is on for the session
//
// Everything runs in the background with timeouts and never delays a turn
// or an upload; every item is capped, has the home directory as `~`, and
// goes through the uploader's CONFIG secret scrub (here, and again when the
// trace is uploaded). OMNIRUSH_CAPTURE_CONTEXT=0 turns the whole module off;
// OMNIRUSH_CAPTURE_NETWORK=0 only the network observer.

import { toolCallsOf, commandEffects, toolKind, type ToolCall } from "./commands.js";
import { resolveEphemeral, type ResolveEphemeralOptions } from "./ephemeral.js";
import { attributeConnections, defaultSampler, NetworkObserver, socketDiffConnections, socketPairs, type HostResolver, type Root, type Sampler } from "./network.js";
import { OutsideTracker } from "./outside.js";
import { outsideFilesEnabled, outsideFilesOfTurn } from "./outside-files.js";
import {
  envFingerprint,
  inInstallLogSample,
  INSTALL_LOG_OFF,
  InstallLogReader,
  lineOf,
  matchCall,
  notedCallId,
  outsideWrites,
  powershellDownloads,
  powershellModules,
  powershellModuleVersions,
  powershellPath,
  setInstallLogActive,
  sha256File,
  ENV_TURN_SCHEMA,
  INSTALL_LOG_SCHEMA,
  relativeTo,
  type CallWindow,
  type InstallLine,
  type InstallLogGate,
  type InstallLogHost,
} from "./install-log.js";
import { collectPmConfig } from "./pm-config.js";
import { cleanUrl, currentPrivacy, tildeText, type PrivacyContext, type Scrubber } from "./privacy.js";
import { withRedactionPolicy, type RedactionPin } from "./redact-policy.js";
import { boxProcessSnapshot, processSnapshot, processTable, listeningPorts, type ProcessInfo, type ListeningPort, type SnapshotScope } from "./processes.js";
import { collectServices } from "./services.js";
import { collectSetup, type SetupFile, type SetupModel } from "./setup.js";
import { collectShellAliases } from "./shell-aliases.js";
import { systemPackages } from "./system-packages.js";
import { runCommand, type Runner } from "./exec.js";
import { arch as osArch, release as osRelease } from "node:os";

export const CONTEXT_SCHEMA = 1;
const SECTION_TIMEOUT_MS = 30_000;
const SETTLE_TIMEOUT_MS = 3_000;
const MAX_SETUP_FILES_EVENT_BYTES = 512 * 1024;
const MAX_EPHEMERAL_PER_SESSION = 500;

export type ContextEventType =
  | "context.environment"
  | "context.setup_files"
  | "context.processes"
  | "context.network"
  | "context.ephemeral_tool"
  | "context.outside_folder"
  | "context.outside_file"
  | "context.install"
  | "context.env_turn"
  | "context.outside_files";

/** Whether capture context is on: OMNIRUSH_CAPTURE_CONTEXT=0 (or false/off/no) turns it off. */
export function captureContextEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return !/^(?:0|false|off|no)$/i.test((env.OMNIRUSH_CAPTURE_CONTEXT ?? "").trim());
}

/** Whether the network observer (#20) is on: OMNIRUSH_CAPTURE_NETWORK=0 turns it off. */
export function captureNetworkEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return captureContextEnabled(env) && !/^(?:0|false|off|no)$/i.test((env.OMNIRUSH_CAPTURE_NETWORK ?? "").trim());
}

export type ContextOptions = {
  client: "cli" | "gui";
  appVersion?: string | null;
  engineVersion?: string | null;
  /** Where the once-a-day system package list is cached (the app's state directory). */
  cacheDir?: string | null;
  scrub: Scrubber;
  /** A session's pinned upload rules (the uploader's): shared work done for one session runs under them. */
  pin?: (sessionId: string) => RedactionPin | undefined;
  /** Appends a trace event to the session (the uploader's trace, scrubbed again on upload). */
  record: (sessionId: string, type: ContextEventType, data: unknown) => void;
  /** Reports an absolute outside file to the project archive (byte-exact copy). */
  reportPath?: (sessionId: string, absolute: string) => void;
  /** The archive's exclusion of an absolute outside path (credential, app state, dependency, system), else null. */
  exclusion?: (absolute: string) => string | null;
  /** The upload denylist for a relative path (credential files), applied to skill/plugin files. */
  denied?: (relPath: string) => boolean;
  /** The session's latest model (the uploader's session.model). */
  model?: (sessionId: string) => SetupModel | null;
  settings?: () => Record<string, unknown>;
  bundledSkillDirs?: string[];
  bundledSkills?: Array<{ name: string; version: string | null; sha256: string }>;
  configFiles?: string[];
  mcpFiles?: string[];
  env?: NodeJS.ProcessEnv;
  platform?: NodeJS.Platform;
  /** The app's process, whose descendants are the session's processes (process.pid by default). */
  rootPid?: number;
  /** Tests: overrides. */
  enabled?: boolean;
  network?: boolean;
  sampler?: Sampler | null;
  resolver?: HostResolver;
  privacy?: PrivacyContext;
  ephemeral?: ResolveEphemeralOptions;
  /** Tests: skip the slow machine-wide sections. */
  sections?: Partial<Record<"system_packages" | "services" | "setup" | "pm_config" | "shell_aliases" | "processes", boolean>>;
  log?: (level: "info" | "warn", message: string, data?: Record<string, unknown>) => void;
  /**
   * The install log (install-log.ts): the raw folder the engine's wrappers
   * write to and the server's switch. Absent: no install log.
   */
  installLog?: InstallLogHost | null;
  /** Tests: the install log's command runner (version probes). */
  installRun?: Runner;
  /** The app's own state folders: never listed as files a turn wrote. */
  appDirs?: string[];
  /**
   * The OmniRush box a session's shell tool runs in (src/box): a runner for
   * commands inside it, else null. The session's processes, servers and
   * runtimes are the box's, so `context.processes` and `context.env_turn`
   * read them there instead of on this machine.
   */
  box?: (sessionId: string, root: string) => Runner | null;
};

/** Shell call windows kept per session for matching the install log's noted calls. */
const MAX_CALL_WINDOWS = 400;
/** A noted call no shell call window claims is given to the only active session after this long (else dropped). */
const UNMATCHED_INSTALL_MS = 2 * 60_000;

type SessionContext = {
  id: string;
  root: string;
  startedAt: number;
  turn: number;
  outside: OutsideTracker;
  observer: NetworkObserver | null;
  /** Tool calls of the current turn, by call id (or position). */
  calls: Map<string, ToolCall>;
  processedCalls: Set<string>;
  /** Shell calls the engine reported starting this turn (tool events), by call id. */
  liveCalls: Map<string, ToolCall>;
  /** Linux: the socket table as each live shell call started (its diff at the end names short connections). */
  socketsAtStart: Map<string, Promise<Map<string, { ip: string; port: number }>>>;
  /** Connections found by a call's socket-table diff, as roots for the attribution. */
  diffRoots: Promise<Root | null>[];
  /** Resolves when the turn's last messages arrived (the uploader's final trace flush). */
  finalMessages: { promise: Promise<void>; resolve: () => void };
  ephemeral: number;
  pending: Set<Promise<unknown>>;
  ended: boolean;
  /** Install log: shell call windows (all turns, newest last), the turn's start, installs noted this turn, in the server's sample. */
  windows: CallWindow[];
  turnStartedAt: number;
  installs: number;
  installSampled: boolean;
};

/** Overhead bookkeeping (milliseconds of wall time spent in each phase). */
export type ContextTimings = { session_start: number[]; turn_start: number[]; turn_messages: number[]; turn_end: number[]; network_sample_ms: number; network_samples: number };

/** Active turns across every capture in this process: an unmatched tool shell is only a turn's when one turn runs. */
const activeTurns = new Set<string>();
/** Sessions whose turn runs now (every session, not only those with a network observer): a shared window for outside files. */
const runningTurns = new Set<string>();

function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve: () => void = () => undefined;
  const promise = new Promise<void>((done) => (resolve = done));
  return { promise, resolve };
}

/** A tool call the engine reported starting or ending (its event stream, or pi's tool hooks). */
export type ToolEvent = {
  callId: string;
  tool: string;
  status: "running" | "completed" | "error";
  /** The shell command (shell tools). */
  command?: string | null;
  /** Its working directory input, as given. */
  workdir?: string | null;
  at?: number;
};

/** How long a turn's outside files wait for the turn's last messages (its shell calls' windows). */
const OUTSIDE_FILES_MESSAGES_WAIT_MS = 1_500;
/** How long a turn's network attribution waits for the turn's last messages. */
const FINAL_MESSAGES_WAIT_MS = 5_000;

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<{ value: T } | { timeout: true } | { error: true }> {
  return Promise.race([
    promise.then((value) => ({ value }), () => ({ error: true as const })),
    new Promise<{ timeout: true }>((resolve) => setTimeout(() => resolve({ timeout: true }), ms).unref?.()),
  ]);
}

export class ContextCapture {
  readonly enabled: boolean;
  readonly networkEnabled: boolean;
  readonly timings: ContextTimings = { session_start: [], turn_start: [], turn_messages: [], turn_end: [], network_sample_ms: 0, network_samples: 0 };
  private readonly sessions = new Map<string, SessionContext>();
  private readonly privacy: PrivacyContext;
  private readonly platform: NodeJS.Platform;
  private readonly env: NodeJS.ProcessEnv;
  private readonly installReader: InstallLogReader | null;
  private installGate: InstallLogGate = INSTALL_LOG_OFF;
  private installDrainTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(private readonly options: ContextOptions) {
    this.env = options.env ?? process.env;
    this.enabled = options.enabled ?? captureContextEnabled(this.env);
    this.networkEnabled = this.enabled && (options.network ?? captureNetworkEnabled(this.env));
    this.privacy = options.privacy ?? currentPrivacy();
    this.platform = options.platform ?? process.platform;
    this.installReader = this.enabled && options.installLog ? new InstallLogReader(options.installLog.raw) : null;
  }

  /** The session's processes: the app's process tree, and processes working in the project or its outside folders. */
  private boxOf(state: SessionContext): Runner | null {
    return this.options.box?.(state.id, state.root) ?? null;
  }

  private scopeOf(state: SessionContext): SnapshotScope {
    return { rootPid: this.options.rootPid ?? process.pid, folders: () => [state.root, ...state.outside.folderPaths()] };
  }

  private section(name: keyof NonNullable<ContextOptions["sections"]>): boolean {
    return this.options.sections?.[name] !== false;
  }

  private emit(sessionId: string, type: ContextEventType, data: unknown): void {
    try {
      this.options.record(sessionId, type, this.options.scrub.json(data));
    } catch (error) {
      this.options.log?.("warn", "capture context: event dropped", { type, error: error instanceof Error ? error.message : String(error) });
    }
  }

  private track(state: SessionContext, work: Promise<unknown>): void {
    const guarded = work.catch((error) => this.options.log?.("warn", "capture context failed", { error: error instanceof Error ? error.message : String(error) }));
    state.pending.add(guarded);
    void guarded.finally(() => state.pending.delete(guarded));
  }

  /**
   * A session started. `after`: the uploader's start snapshot; the
   * machine-wide collection waits for it (bounded) so it never competes
   * with the snapshot for the disk and the event loop. `turnsBefore`: the
   * turns a continued or resumed session already had, so its turn numbers
   * (context.install, context.env_turn, ...) carry on from them.
   */
  sessionStarted(sessionId: string, root: string, after?: Promise<unknown>, turnsBefore = 0): void {
    if (!this.enabled || this.sessions.has(sessionId)) return;
    const state: SessionContext = {
      id: sessionId,
      root,
      startedAt: Date.now(),
      turn: Number.isSafeInteger(turnsBefore) && turnsBefore > 0 ? turnsBefore : 0,
      outside: new OutsideTracker({
        root,
        sessionStartMs: Date.now(),
        privacy: this.privacy,
        scrub: this.options.scrub,
        exclusion: this.options.exclusion ?? (() => null),
        reportPath: (absolute) => this.options.reportPath?.(sessionId, absolute),
      }),
      observer: null,
      calls: new Map(),
      processedCalls: new Set(),
      liveCalls: new Map(),
      socketsAtStart: new Map(),
      diffRoots: [],
      finalMessages: deferred(),
      ephemeral: 0,
      pending: new Set(),
      ended: false,
      windows: [],
      turnStartedAt: Date.now(),
      installs: 0,
      installSampled: false,
    };
    if (this.networkEnabled) {
      const sampler = this.options.sampler === undefined ? defaultSampler(this.platform) : this.options.sampler;
      if (sampler) state.observer = new NetworkObserver({ sampler });
    }
    this.sessions.set(sessionId, state);
    this.refreshInstallGate(state);
    this.track(state, (async () => {
      if (after) await withTimeout(after, SECTION_TIMEOUT_MS);
      await this.collectSessionStart(state);
    })());
  }

  // --- install log (install-log.ts) -----------------------------------------------

  /** Asks the server's switch (the host caches it) and turns the wrappers' noting on while any open session is in the sample. */
  private refreshInstallGate(state: SessionContext): void {
    const host = this.options.installLog;
    if (!host || !this.installReader) return;
    this.track(state, (async () => {
      const gate = await withTimeout(host.gate(), 10_000);
      this.installGate = "value" in gate ? gate.value : this.installGate;
      state.installSampled = this.installGate.enabled && inInstallLogSample(state.id, this.installGate.samplePercent);
      const any = [...this.sessions.values()].some((item) => !item.ended && item.installSampled);
      await setInstallLogActive(host.raw, any);
    })());
  }

  private noteWindow(state: SessionContext, window: Omit<CallWindow, "sessionId" | "turn">): void {
    if (!this.installReader) return;
    const known = window.callId ? state.windows.find((item) => item.callId === window.callId) : undefined;
    if (known) {
      known.end ??= window.end;
      known.cwd ??= window.cwd;
      known.command ??= window.command;
      return;
    }
    state.windows.push({ ...window, sessionId: state.id, turn: state.turn });
    if (state.windows.length > MAX_CALL_WINDOWS) state.windows.splice(0, state.windows.length - MAX_CALL_WINDOWS);
  }

  /** Reads the noted calls soon (a shell call just ended). */
  private scheduleInstallDrain(): void {
    if (!this.installReader || this.installDrainTimer) return;
    this.installDrainTimer = setTimeout(() => {
      this.installDrainTimer = null;
      void this.drainInstalls(false).catch(() => undefined);
    }, 750);
    this.installDrainTimer.unref?.();
  }

  /** The noted calls: matched to their session and call, resolved, sent as `context.install`; then removed. */
  private drainInstalls(final: boolean): Promise<void> {
    const reader = this.installReader;
    if (!reader) return Promise.resolve();
    return reader.serial(async () => {
      const now = Date.now();
      const calls = await reader.pending(now);
      if (calls.length === 0) return;
      const windows = [...this.sessions.values()].flatMap((state) => state.windows);
      const active = [...this.sessions.values()].filter((state) => !state.ended);
      for (const call of calls) {
        let match = matchCall(call, windows, now);
        if (!match) {
          if (!final && now - call.start < UNMATCHED_INSTALL_MS) continue;
          // The session its wrapper names (OMNIRUSH_SESSION), when it is one of these.
          const named = call.meta.session ?? call.hooks[0]?.meta.session;
          const own = named ? this.sessions.get(named) : undefined;
          match = own ? { sessionId: own.id, callId: null, start: call.start, end: null, cwd: null, command: null, turn: own.turn } : active.length === 1 ? { sessionId: active[0]!.id, callId: null, start: call.start, end: null, cwd: null, command: null, turn: active[0]!.turn } : null;
        }
        const state = match ? this.sessions.get(match.sessionId) : undefined;
        if (match && state && state.installSampled) {
          const started = performance.now();
          // The call its wrapper names wins over the time window (a sub-agent's call, one of parallel calls).
          const callId = notedCallId(call) ?? match.callId;
          const pin = this.options.pin?.(state.id);
          const line = await withRedactionPolicy(pin, () => lineOf(call, {
            root: state.root,
            turn: match.turn || null,
            callId,
            command: callId !== null && callId === match.callId ? match.command : null,
            privacy: this.privacy,
            scrub: this.options.scrub,
            platform: this.platform,
            env: this.env,
            run: this.options.installRun ?? runCommand,
          })).catch(() => null);
          if (line) {
            state.installs += 1;
            withRedactionPolicy(pin, () => this.emit(state.id, "context.install", line));
          }
          this.timings.turn_messages.push(Math.round(performance.now() - started));
        }
        await reader.remove(call);
      }
    });
  }

  /** PowerShell downloads and Gallery installs of the turn's calls (cmdlets are not programs: no PATH wrapper sees them). */
  private async commandDownloads(state: SessionContext, calls: ToolCall[]): Promise<void> {
    const tilde = (text: string) => this.options.scrub.text(tildeText(text, this.privacy));
    const os = this.platform === "win32" ? "windows" : this.platform === "darwin" ? "darwin" : "linux";
    const line = (call: ToolCall, fields: Partial<InstallLine>): InstallLine => {
      const cwd = call.cwd || state.root;
      const start = call.start ?? Date.now();
      return {
        v: 1,
        schema: INSTALL_LOG_SCHEMA,
        ts: new Date(start).toISOString(),
        end: call.end ? new Date(call.end).toISOString() : null,
        dur_ms: call.end ? Math.max(0, call.end - start) : null,
        turn: state.turn,
        call: call.callId,
        tool: "powershell",
        via: "command",
        real: null,
        argv: [],
        cwd: tilde(cwd),
        cwd_rel: relativeTo(state.root, cwd, this.platform),
        exit: call.status === "completed" ? 0 : null,
        os,
        scope: "project",
        ecosystem: "url",
        target: null,
        target_rel: null,
        python: null,
        requested: [],
        resolved: [],
        removed: [],
        downloads: [],
        lockfile: null,
        lockfile_rel: null,
        lockfile_sha256: null,
        ...fields,
      };
    };
    for (const call of calls) {
      if (toolKind(call.tool) !== "shell" || !call.command) continue;
      const cwd = call.cwd || state.root;
      for (const found of powershellDownloads(call.command)) {
        const expanded = found.out ? powershellPath(found.out, this.env, this.privacy.home) : null;
        const file = expanded ? (/^[A-Za-z]:[\\/]|^[\\/]/.test(expanded) ? expanded : `${cwd}${this.platform === "win32" ? "\\" : "/"}${expanded}`) : null;
        const hashed = file ? await sha256File(file) : null;
        state.installs += 1;
        this.emit(state.id, "context.install", line(call, {
          downloads: [{
            url: cleanUrl(found.url),
            path: file ? tilde(file) : found.unresolved ? "(unknown)" : "(piped)",
            path_rel: file ? relativeTo(state.root, file, this.platform) : null,
            ...(hashed?.sha256 ? { sha256: hashed.sha256 } : {}),
            ...(hashed ? { size: hashed.size } : {}),
          }],
        }));
      }
      for (const found of powershellModules(call.command)) {
        const resolved = [];
        for (const name of found.names.slice(0, 20)) {
          const versions = await powershellModuleVersions(name, this.env, this.privacy.home);
          const version = found.version && versions.includes(found.version) ? found.version : versions[0];
          if (version) resolved.push({ name, version, source: "https://www.powershellgallery.com/api/v2" });
        }
        state.installs += 1;
        this.emit(state.id, "context.install", line(call, {
          ecosystem: "psgallery",
          scope: found.scope,
          argv: [found.cmdlet],
          requested: found.names.map((name) => (found.version ? `${name}@${found.version}` : name)),
          resolved,
        }));
      }
    }
  }

  /**
   * The turn's end: the files its commands wrote outside the project's
   * tracked files (`context.outside_files`, outside-files.ts), whatever the
   * install log's switch; off with OMNIRUSH_OUTSIDE_FILES=0.
   */
  private outsideFilesTurnEnded(state: SessionContext): void {
    if (!outsideFilesEnabled(this.env) || state.turn < 1) return;
    const turn = state.turn;
    const since = state.turnStartedAt;
    const until = Date.now();
    const finalMessages = state.finalMessages.promise;
    const sharedWindow = [...runningTurns].some((id) => id !== state.id);
    const live = state.liveCalls;
    this.track(state, (async () => {
      // The turn's calls are known once its last messages arrived (a short wait: they only attribute files).
      await withTimeout(finalMessages, OUTSIDE_FILES_MESSAGES_WAIT_MS);
      const shells = [...state.calls.values(), ...[...live.values()].filter((call) => !state.calls.has(call.callId ?? ""))]
        .filter((call) => toolKind(call.tool) === "shell");
      const calls = shells.map((call) => ({ callId: call.callId, start: call.start, end: call.end }));
      const effects = shells.filter((call) => call.command).map((call) => {
        try {
          return commandEffects(call.command!, call.cwd ?? state.root, this.privacy.home);
        } catch {
          return { folders: [], writes: [] };
        }
      });
      const host = this.options.installLog;
      const event = await outsideFilesOfTurn({
        root: state.root,
        turn,
        since,
        until,
        home: this.privacy.home,
        platform: this.platform,
        env: this.env,
        privacy: this.privacy,
        scrub: this.options.scrub,
        exclude: [...(host ? [host.raw, ...(host.bin ? [host.bin] : []), ...(host.appDirs ?? [])] : []), ...(this.options.cacheDir ? [this.options.cacheDir] : []), ...(this.options.appDirs ?? [])],
        commandFolders: [...state.outside.folderPaths(), ...effects.flatMap((effect) => effect.folders.filter((folder) => folder.created).map((folder) => folder.path))],
        commandFiles: effects.flatMap((effect) => effect.writes),
        calls,
        sharedWindow,
      });
      if (event) this.emit(state.id, "context.outside_files", event);
    })());
  }

  /** The turn's end: its noted calls, its PowerShell downloads, then `context.env_turn`. */
  private installTurnEnded(state: SessionContext): void {
    const host = this.options.installLog;
    if (!host || !this.installReader || !state.installSampled) return;
    const turn = state.turn;
    const since = state.turnStartedAt;
    const until = Date.now();
    const finalMessages = state.finalMessages.promise;
    this.track(state, (async () => {
      await withTimeout(finalMessages, FINAL_MESSAGES_WAIT_MS);
      await this.drainInstalls(false);
      const started = performance.now();
      const turnCalls = [...state.calls.values()].filter((call) => call.start === null || call.start >= since - 1_000);
      await this.commandDownloads(state, turnCalls);
      const timings: Record<string, number> = {};
      let at = performance.now();
      const pathKey = Object.keys(this.env).find((key) => key.toUpperCase() === "PATH") ?? "PATH";
      const fingerprint = await envFingerprint({
        root: state.root,
        pathValue: this.env[pathKey] ?? "",
        skipDir: host.bin ?? null,
        env: this.env,
        platform: this.platform,
        arch: osArch(),
        osVersion: (() => {
          try {
            return osRelease();
          } catch {
            return null;
          }
        })(),
        privacy: this.privacy,
        run: this.options.installRun ?? runCommand,
        box: this.boxOf(state),
      });
      timings.fingerprint = Math.round(performance.now() - at);
      at = performance.now();
      const outside = await outsideWrites({
        root: state.root,
        since,
        until: Date.now(),
        home: this.privacy.home,
        platform: this.platform,
        env: this.env,
        privacy: this.privacy,
        scrub: this.options.scrub,
        exclude: [host.raw, ...(host.bin ? [host.bin] : []), ...(host.appDirs ?? []), ...(this.options.cacheDir ? [this.options.cacheDir] : [])],
      });
      timings.outside = Math.round(performance.now() - at);
      timings.outside_scanned = outside.scanned;
      this.emit(state.id, "context.env_turn", {
        schema: ENV_TURN_SCHEMA,
        turn,
        at: new Date(until).toISOString(),
        ...fingerprint,
        installs: state.installs,
        outside_writes: outside.files,
        outside_truncated: outside.truncated,
        timings_ms: timings,
      });
      this.timings.turn_end.push(Math.round(performance.now() - started));
    })());
  }

  private async collectSessionStart(state: SessionContext): Promise<void> {
    const started = performance.now();
    const timings: Record<string, number> = {};
    const errors: Record<string, string> = {};
    const timed = async <T>(name: string, work: () => Promise<T>): Promise<T | undefined> => {
      const at = performance.now();
      const result = await withTimeout(work(), SECTION_TIMEOUT_MS);
      timings[name] = Math.round(performance.now() - at);
      if ("value" in result) return result.value;
      errors[name] = "timeout" in result ? "timeout" : "failed";
      return undefined;
    };
    const { privacy } = this;
    const scrub = this.options.scrub;
    const runOpts = { platform: this.platform };

    // Processes and ports first: services reads the listening ports.
    let table: ProcessInfo[] = [];
    let listening: ListeningPort[] = [];
    if (this.section("processes")) {
      const box = this.boxOf(state);
      const snapshot = await timed("processes", async () => {
        if (box) return boxProcessSnapshot("session_start", 0, box, { ...runOpts, privacy, scrub });
        const { processes, method } = await processTable(runOpts);
        table = processes;
        const ports = await listeningPorts(processes, runOpts);
        listening = ports.ports;
        return processSnapshot("session_start", 0, { ...runOpts, privacy, scrub, scope: this.scopeOf(state), precomputed: { processes, listening, method: `${method}+${ports.method}` } });
      });
      if (snapshot) this.emit(state.id, "context.processes", snapshot);
    }

    const [packages, services, setup, pmConfig, aliases] = await Promise.all([
      this.section("system_packages") ? timed("system_packages", () => systemPackages({ platform: this.platform, cacheDir: this.options.cacheDir ?? null })) : undefined,
      this.section("services") ? timed("services", () => collectServices({ root: state.root, listening, processes: table, privacy, scrub, platform: this.platform, sessionStartMs: state.startedAt, folders: state.outside.folderPaths() })) : undefined,
      this.section("setup")
        ? timed("setup", () => collectSetup({
          root: state.root,
          client: this.options.client,
          appVersion: this.options.appVersion ?? null,
          engineVersion: this.options.engineVersion ?? null,
          model: this.options.model?.(state.id) ?? null,
          settings: this.options.settings?.() ?? {},
          bundledSkillDirs: this.options.bundledSkillDirs ?? [],
          bundledSkills: this.options.bundledSkills ?? [],
          configFiles: this.options.configFiles ?? [],
          mcpFiles: this.options.mcpFiles ?? [],
          privacy,
          scrub,
          ...(this.options.denied ? { denied: this.options.denied } : {}),
          env: this.env,
        }))
        : undefined,
      this.section("pm_config") ? timed("pm_config", () => collectPmConfig({ privacy, scrub, platform: this.platform, env: this.env })) : undefined,
      this.section("shell_aliases") ? timed("shell_aliases", () => collectShellAliases({ privacy, scrub, platform: this.platform, env: this.env })) : undefined,
    ]);
    timings.total = Math.round(performance.now() - started);
    this.timings.session_start.push(timings.total);
    this.emit(state.id, "context.environment", {
      schema: CONTEXT_SCHEMA,
      collected_at: new Date().toISOString(),
      platform: this.platform,
      ...(packages ? { system_packages: packages } : {}),
      ...(services ? { services } : {}),
      ...(setup ? { setup: setup.setup } : {}),
      ...(pmConfig ? { pm_config: pmConfig } : {}),
      ...(aliases ? { shell_aliases: aliases } : {}),
      timings_ms: timings,
      ...(Object.keys(errors).length > 0 ? { errors } : {}),
    });
    if (setup && setup.files.length > 0) this.emitSetupFiles(state.id, setup.files);
  }

  /** The skill/plugin texts in events of at most ~512 KiB each. */
  private emitSetupFiles(sessionId: string, files: SetupFile[]): void {
    const parts: SetupFile[][] = [[]];
    let bytes = 0;
    for (const file of files) {
      const size = Buffer.byteLength(JSON.stringify(file));
      if (bytes + size > MAX_SETUP_FILES_EVENT_BYTES && parts[parts.length - 1]!.length > 0) {
        parts.push([]);
        bytes = 0;
      }
      parts[parts.length - 1]!.push(file);
      bytes += size;
    }
    parts.forEach((part, index) => this.emit(sessionId, "context.setup_files", { files: part, part: index + 1, parts: parts.length }));
  }

  /**
   * A prompt was dispatched. `after`: work the turn's own capture does first
   * (the uploader's artifact baseline listing); the process snapshot waits
   * for it so the two never compete for the disk and the event loop.
   */
  turnStarted(sessionId: string, after?: Promise<unknown>): void {
    const state = this.sessions.get(sessionId);
    if (!state || state.ended) return;
    state.turn += 1;
    state.turnStartedAt = Date.now();
    state.installs = 0;
    this.refreshInstallGate(state);
    state.calls = new Map();
    state.liveCalls = new Map();
    state.socketsAtStart = new Map();
    state.diffRoots = [];
    state.finalMessages = deferred();
    runningTurns.add(sessionId);
    if (state.observer) {
      activeTurns.add(sessionId);
      state.observer.start();
    }
    if (!this.section("processes")) return;
    const turn = state.turn;
    this.track(state, (async () => {
      if (after) await withTimeout(after, SECTION_TIMEOUT_MS);
      const started = performance.now();
      const box = this.boxOf(state);
      const snapshot = await withTimeout(box
        ? boxProcessSnapshot("turn_start", turn, box, { platform: this.platform, privacy: this.privacy, scrub: this.options.scrub })
        : processSnapshot("turn_start", turn, { platform: this.platform, privacy: this.privacy, scrub: this.options.scrub, scope: this.scopeOf(state) }), SECTION_TIMEOUT_MS);
      this.timings.turn_start.push(Math.round(performance.now() - started));
      // A box that did not answer gives no snapshot (null), never an empty one.
      if ("value" in snapshot && snapshot.value) this.emit(sessionId, "context.processes", snapshot.value);
    })());
  }

  /**
   * A tool call started or ended (the engine's event stream, pi's tool
   * hooks). A shell call's start makes the network observer sample every
   * 50 ms for its first 2 s and, on Linux, notes the socket table so that a
   * connection too short to be sampled is still found from the table's
   * diff at its end (only for hosts its command names).
   */
  toolEvent(sessionId: string, event: ToolEvent): void {
    const state = this.sessions.get(sessionId);
    if (!state || state.ended || !event.callId || toolKind(event.tool) !== "shell") return;
    const at = event.at ?? Date.now();
    const known = state.liveCalls.get(event.callId);
    if (this.installReader) {
      const command = typeof event.command === "string" ? event.command : null;
      const workdir = typeof event.workdir === "string" && event.workdir.trim() ? event.workdir.trim() : null;
      if (event.status === "running") this.noteWindow(state, { callId: event.callId, start: at, end: null, cwd: workdir ?? state.root, command });
      else {
        this.noteWindow(state, { callId: event.callId, start: known?.start ?? at, end: at, cwd: workdir, command });
        this.scheduleInstallDrain();
      }
    }
    if (event.status === "running") {
      if (known) return;
      const command = typeof event.command === "string" ? event.command : null;
      const workdir = typeof event.workdir === "string" && event.workdir.trim() ? event.workdir.trim() : null;
      state.liveCalls.set(event.callId, { callId: event.callId, tool: event.tool, input: {}, status: "running", start: at, end: null, command, cwd: workdir ? workdir : state.root });
      state.observer?.boost();
      if (this.platform === "linux" && state.observer && command) state.socketsAtStart.set(event.callId, socketPairs().catch(() => new Map()));
      return;
    }
    if (!known) return;
    known.end = at;
    known.status = event.status;
    if (typeof event.command === "string" && !known.command) known.command = event.command;
    const before = state.socketsAtStart.get(event.callId);
    state.socketsAtStart.delete(event.callId);
    if (before && known.command) {
      const command = known.command;
      const callId = event.callId;
      state.diffRoots.push((async () => {
        const connections = await socketDiffConnections(await before, await socketPairs().catch(() => new Map()), command, known.start ?? at, this.options.resolver);
        return connections.size > 0 ? { pid: -1, command, firstSeen: known.start ?? at, connections, callId, method: "socket_table" } : null;
      })().catch(() => null));
    }
  }

  /** The turn's engine messages (possibly in several parts): its tool calls feed #10, #21 and #22. `final`: the turn's last part. */
  turnMessages(sessionId: string, messages: unknown, final = false): void {
    const state = this.sessions.get(sessionId);
    if (!state) return;
    if (final) queueMicrotask(() => state.finalMessages.resolve());
    const calls = toolCallsOf(messages, state.root, this.privacy.home);
    const fresh: ToolCall[] = [];
    calls.forEach((call, index) => {
      const key = call.callId ?? `${state.turn}:${index}:${call.tool}:${call.start ?? ""}`;
      state.calls.set(key, call);
      if (this.installReader && toolKind(call.tool) === "shell" && call.start !== null) this.noteWindow(state, { callId: call.callId, start: call.start, end: call.end, cwd: call.cwd, command: call.command });
      if (state.processedCalls.has(key) || (call.status !== null && call.status !== "completed" && call.status !== "error")) return;
      state.processedCalls.add(key);
      fresh.push(call);
    });
    if (fresh.length === 0) return;
    this.track(state, (async () => {
      const started = performance.now();
      const outside = await state.outside.processCalls(fresh);
      for (const folder of outside.folders) this.emit(sessionId, "context.outside_folder", folder);
      for (const file of outside.files) this.emit(sessionId, "context.outside_file", file);
      for (const call of fresh) {
        if (toolKind(call.tool) !== "shell" || !call.command) continue;
        for (const tool of commandEffects(call.command, call.cwd, this.privacy.home).ephemeral) {
          if (state.ephemeral >= MAX_EPHEMERAL_PER_SESSION) break;
          state.ephemeral += 1;
          const runner = tool.runner === "bun x" ? "bunx" : tool.runner;
          const resolved = await resolveEphemeral(
            { tool_call_id: call.callId, runner, package: tool.package, requested: tool.requested },
            { home: this.privacy.home, platform: this.platform, env: this.env, ...(this.options.ephemeral ?? {}) },
          );
          this.emit(sessionId, "context.ephemeral_tool", resolved);
        }
      }
      this.timings.turn_messages.push(Math.round(performance.now() - started));
    })());
  }

  /** The turn ended: the network observer stops and its connections are attributed to the turn's calls. */
  turnEnded(sessionId: string): void {
    const found = this.sessions.get(sessionId);
    if (found && !found.ended) {
      this.installTurnEnded(found);
      this.outsideFilesTurnEnded(found);
    }
    runningTurns.delete(sessionId);
    const state = found;
    if (!state || !state.observer) return;
    const observer = state.observer;
    const turn = state.turn;
    const alone = activeTurns.size <= 1;
    activeTurns.delete(sessionId);
    const finalMessages = state.finalMessages.promise;
    const live = state.liveCalls;
    const diffs = state.diffRoots;
    this.track(state, (async () => {
      const roots: Root[] = await observer.stop();
      // The turn's calls are known once its last messages arrived (the uploader flushes them right after this milestone).
      await withTimeout(finalMessages, FINAL_MESSAGES_WAIT_MS);
      const started = performance.now();
      for (const root of await Promise.all(diffs)) if (root) roots.push(root);
      const calls = [...state.calls.values()];
      // Calls the tool events saw but no message carried yet (the engine had not stored them).
      for (const call of live.values()) if (!calls.some((known) => known.callId === call.callId)) calls.push(call);
      // A message's call takes the tool event's start and end when it has none.
      for (const call of calls) {
        const seen = call.callId ? live.get(call.callId) : undefined;
        if (seen) {
          call.start ??= seen.start;
          call.end ??= seen.end;
        }
      }
      this.timings.network_sample_ms = observer.sampleMs;
      this.timings.network_samples = observer.samples;
      const events = await attributeConnections(roots, calls, { turn, method: observer.method, pollMs: observer.pollMs, ...(this.options.resolver ? { resolver: this.options.resolver } : {}) });
      for (const event of events) {
        // Another session's turn ran at the same time: an unmatched shell may be its.
        if (event.scope === "turn" && !alone) continue;
        this.emit(sessionId, "context.network", event);
      }
      this.timings.turn_end.push(Math.round(performance.now() - started));
    })());
  }

  /** Resolves once the session's background work is done (or after `timeoutMs`). */
  async settled(sessionId: string, timeoutMs = SETTLE_TIMEOUT_MS): Promise<void> {
    const state = this.sessions.get(sessionId);
    if (!state) return;
    const deadline = Date.now() + timeoutMs;
    while (state.pending.size > 0 && Date.now() < deadline) {
      await withTimeout(Promise.all([...state.pending]), Math.max(1, deadline - Date.now()));
    }
  }

  sessionEnded(sessionId: string): void {
    const state = this.sessions.get(sessionId);
    if (!state || state.ended) return;
    if (state.observer && activeTurns.has(sessionId)) this.turnEnded(sessionId);
    state.finalMessages.resolve();
    state.ended = true;
    runningTurns.delete(sessionId);
    if (this.installReader) {
      this.track(state, this.drainInstalls(true));
      const host = this.options.installLog;
      if (host && ![...this.sessions.values()].some((item) => !item.ended && item.installSampled)) this.track(state, setInstallLogActive(host.raw, false));
    }
    void this.settled(sessionId, SETTLE_TIMEOUT_MS).finally(() => this.sessions.delete(sessionId));
  }
}
