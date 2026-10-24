import { afterEach, describe, expect, test } from "bun:test";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { appendFile, mkdir, mkdtemp, readFile, readdir, rename, rm, stat, symlink, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join, posix, win32 } from "node:path";
import { promisify } from "node:util";
import { zstdDecompressSync } from "node:zlib";

import {
  UPLOAD_SCHEMA_VERSION,
  MAX_UPLOAD_ATTACHMENT_TEXT_BYTES,
  MAX_UPLOAD_DIFF_BYTES,
  MAX_UPLOAD_FILE_BYTES,
  MAX_UPLOAD_FILES,
  MAX_UPLOAD_TRACE_BYTES,
  MAX_UPLOAD_TRACE_EVENTS,
  MAX_UPLOAD_WEB_VISIT_TEXT_BYTES,
  MAX_SPOOL_AGE_MS,
  uploadIdempotencyKey,
  serverSessionPosition,
  parseJournal,
  integrityFindings,
  SessionUploader,
  isRetryableUploadStatus,
  mapBounded,
  retryAfterMs,
  clampUploadBytes,
  clampUploadText,
  collectGitBlock,
  diffHeaderPath,
  filterUploadDiff,
  isUploadableWebUrl,
  isUploadPathDenied,
  isUploadFileDenied,
  isPathLikeKey,
  isSecretAssignmentKey,
  isSecretAssignmentValue,
  redactUploadContent,
  redactUploadJson,
  redactUploadJsonText,
  redactUploadText,
  redactModeForPath,
  stripRemoteUserinfo,
  workspaceRelativePath,
} from "./session-uploader.js";
import { setRedactionPolicy } from "./context/redact-policy.js";
import { SESSION_UPLOAD_BUDGET, sessionUploadTimeoutMs, type SessionUploadBudget } from "./session-upload-budget.js";

/** Schema 1/2 trace uploads carry their events only in files[0] (__omnirush__/trace.json): read them back as `trace`. */
function withTraceEvents<T>(envelope: T): T {
  const record = envelope as Record<string, unknown>;
  if (record.trace !== undefined || !Array.isArray(record.files)) return envelope;
  const file = (record.files as Array<{ path?: string; content?: string }>).find((item) => item.path === "__omnirush__/trace.json");
  if (!file?.content) return envelope;
  return { ...record, trace: (JSON.parse(file.content) as { events?: unknown[] }).events ?? [] } as T;
}


const execFileAsync = promisify(execFile);
const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("session uploader privacy", () => {
  test("denies repository internals and credential files", () => {
    for (const path of [".git/config", ".env.local", "node_modules/pkg/index.js", ".ssh/config", "keys/service.json", "cert.pem"]) {
      expect(isUploadPathDenied(path)).toBe(true);
    }
    expect(isUploadPathDenied("src/app.ts")).toBe(false);
  });

  test("keeps a .env template in scrubbed snapshots; the archive and every real .env still deny it", () => {
    for (const path of [".env.example", "app/.env.sample", "config/.env.template", ".env.dist", ".ENV.EXAMPLE", ".env.defaults"]) {
      expect(isUploadFileDenied(path)).toBe(false);
      // What is stored byte for byte never takes one.
      expect(isUploadPathDenied(path)).toBe(true);
    }
    for (const path of [".env", ".env.local", ".env.production", ".env.example.local", "secrets/.env.example", ".env.example/x.txt", "keys/.env.sample"]) {
      expect(isUploadFileDenied(path)).toBe(true);
    }
    // A template's values are scrubbed as its .env's would be, under both rule sets.
    const filled = "PORT=3000\nAPI_TOKEN=abcdefgh123\nDATABASE_PASSWORD=Summer2024!\nJWT_SECRET=supersecretjwt\nAPI_KEY=<your-api-key>\n";
    const policy = Symbol.for("omnirush.redactionPolicy");
    const holder = globalThis as unknown as Record<symbol, unknown>;
    const before = holder[policy];
    try {
      for (const rules of ["legacy", "client-v3"]) {
        holder[policy] = rules;
        for (const file of [".env.example", "app/.env.sample"]) {
          expect(redactUploadContent(file, filled)).toMatch(/^PORT=3000\nAPI_TOKEN=\[REDACTED[^\n]*\nDATABASE_PASSWORD=\[REDACTED[^\n]*\nJWT_SECRET=\[REDACTED[^\n]*\nAPI_KEY=<your-api-key>\n$/);
          const diff = filterUploadDiff(`diff --git a/${file} b/${file}\n--- a/${file}\n+++ b/${file}\n@@ -0,0 +1 @@\n+DATABASE_PASSWORD=Summer2024!\n`).diff;
          expect(diff).toMatch(/\+DATABASE_PASSWORD=\[REDACTED/);
        }
      }
    } finally {
      holder[policy] = before;
    }
  });

  test("denies a named env file (prod.env) everywhere and scrubs it as a credential file", () => {
    for (const path of ["prod.env", "app.env", "docker/production.env", "Config/Staging.ENV", ".local.env", "tests/fixtures/app.env"]) {
      expect(isUploadFileDenied(path)).toBe(true);
      expect(isUploadPathDenied(path)).toBe(true);
    }
    for (const path of ["src/env.ts", "prod.env.example", "environment.yml", "src/load.env.ts", "envs/readme.md"]) {
      expect(isUploadFileDenied(path)).toBe(false);
    }
    const policy = Symbol.for("omnirush.redactionPolicy");
    const holder = globalThis as unknown as Record<symbol, unknown>;
    const before = holder[policy];
    try {
      for (const rules of ["legacy", "client-v3"]) {
        holder[policy] = rules;
        for (const file of ["prod.env", "docker/production.env"]) {
          const text = redactUploadText("PORT=3000\nDATABASE_PASSWORD=Summer2024!\n", { context: file, mode: redactModeForPath(file) }).text;
          expect(text).toMatch(/^PORT=3000\nDATABASE_PASSWORD=\[REDACTED/);
        }
      }
    } finally {
      holder[policy] = before;
    }
  });

  test("redacts private keys and provider-style secrets before upload", () => {
    const result = redactUploadText([
      "AWS_ACCESS_KEY_ID=AKIA1234567890123456",
      "OPENAI_API_KEY=sk-1234567890abcdefghijklmnop",
      "-----BEGIN PRIVATE KEY-----\nprivate\n-----END PRIVATE KEY-----",
    ].join("\n"));
    expect(result.text).not.toContain("AKIA1234567890123456");
    expect(result.text).not.toContain("sk-1234567890abcdefghijklmnop");
    expect(result.text).not.toContain("private\n");
    expect(result.count).toBeGreaterThanOrEqual(3);
  });

  test("scrubs common personal identifiers before upload", () => {
    const result = redactUploadText("jane@acme-mail.io +1 (415) 555-0132 52.14.7.25");
    expect(result.text).not.toContain("jane@acme-mail.io");
    expect(result.text).not.toContain("415");
    expect(result.text).not.toContain("52.14.7.25");
    expect(result.count).toBe(3);
  });

  test("uploads correlated start, trace, and end artifacts without ignored or binary files", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-"));
    roots.push(root);
    await execFileAsync("git", ["init", "-q", root]);
    await writeFile(join(root, ".gitignore"), "ignored.txt\n");
    await mkdir(join(root, "nested"));
    await writeFile(join(root, "nested", ".gitignore"), "ignored-nested.txt\n");
    await writeFile(join(root, "app.txt"), "hello sk-1234567890abcdefghijklmnop\n");
    await writeFile(join(root, "ignored.txt"), "do not upload\n");
    await writeFile(join(root, ".env.local"), "PASSWORD=secret-value\n");
    await writeFile(join(root, "binary.dat"), Buffer.from([0, 1, 2, 3]));
    await writeFile(join(root, "nested", "ignored-nested.txt"), "do not upload\n");

    const uploads: Array<{ sessionId: string; envelope: Record<string, unknown> }> = [];
    const sessionUploader = new SessionUploader({
      upload: async (sessionId, compressed) => {
        uploads.push({
          sessionId,
          envelope: withTraceEvents(JSON.parse(zstdDecompressSync(compressed).toString("utf8"))),
        });
        return Response.json({ ok: true }, { status: 201 });
      },
      changeDebounceMs: 10,
      fallbackScanMs: 60_000,
    });
    const sessionId = "session-test-1234";
    sessionUploader.startSession(sessionId, "workspace-test", root);
    sessionUploader.recordTrace(sessionId, "tool.call", { token: "sk-1234567890abcdefghijklmnop" });
    sessionUploader.flushTrace(sessionId);
    await sessionUploader.stop();

    expect(uploads.map((upload) => upload.envelope.snapshot_type)).toEqual(["start", "trace", "end"]);
    expect(uploads.every((upload) => upload.sessionId === sessionId)).toBe(true);
    const paths = uploads.flatMap((upload) => (upload.envelope.files as Array<{ path: string }>).map((file) => file.path));
    expect(paths).toContain("app.txt");
    expect(paths).not.toContain("ignored.txt");
    expect(paths).not.toContain("nested/ignored-nested.txt");
    expect(paths).not.toContain(".env.local");
    expect(paths).not.toContain("binary.dat");
    expect(JSON.stringify(uploads)).not.toContain("sk-1234567890abcdefghijklmnop");
  });

  test("does not drop trace events recorded while an upload is in flight", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-race-"));
    roots.push(root);
    let release!: () => void;
    const blocked = new Promise<void>((resolve) => { release = resolve; });
    let traceStarted!: () => void;
    const traceObserved = new Promise<void>((resolve) => { traceStarted = resolve; });
    const uploads: Array<Record<string, unknown>> = [];
    const sessionUploader = new SessionUploader({
      upload: async (_sessionId, compressed) => {
        const envelope = withTraceEvents(JSON.parse(zstdDecompressSync(compressed).toString("utf8"))) as Record<string, unknown>;
        uploads.push(envelope);
        if (envelope.snapshot_type === "trace" && uploads.filter((item) => item.snapshot_type === "trace").length === 1) {
          traceStarted();
          await blocked;
        }
        return Response.json({ ok: true }, { status: 201 });
      },
      fallbackScanMs: 60_000,
    });
    const sessionId = "session-race-1234";
    sessionUploader.startSession(sessionId, "workspace-race", root);
    await new Promise((resolve) => setTimeout(resolve, 40));
    sessionUploader.recordTrace(sessionId, "first.event");
    sessionUploader.flushTrace(sessionId);
    await traceObserved;
    sessionUploader.recordTrace(sessionId, "second.event");
    sessionUploader.flushTrace(sessionId);
    release();
    await sessionUploader.stop();

    const traceEvents = uploads
      .filter((item) => item.snapshot_type === "trace")
      .flatMap((item) => ((item.files as Array<{ content: string }>)[0]?.content ? JSON.parse((item.files as Array<{ content: string }>)[0].content).events : [])) as Array<{ type: string }>;
    expect(traceEvents.map((event) => event.type)).toContain("first.event");
    expect(traceEvents.map((event) => event.type)).toContain("second.event");
  });

  test("keeps oversized traces valid JSON and marks dropped events", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-truncate-"));
    roots.push(root);
    const uploads: Array<Record<string, unknown>> = [];
    const sessionUploader = new SessionUploader({
      upload: async (_sessionId, compressed) => {
        uploads.push(withTraceEvents(JSON.parse(zstdDecompressSync(compressed).toString("utf8"))) as Record<string, unknown>);
        return Response.json({ ok: true }, { status: 201 });
      },
      fallbackScanMs: 60_000,
    });
    const sessionId = "session-truncate-1234";
    sessionUploader.startSession(sessionId, "workspace-truncate", root);
    sessionUploader.recordTrace(sessionId, "huge.event", { text: "x".repeat(MAX_UPLOAD_TRACE_BYTES + 1024 * 1024) });
    sessionUploader.flushTrace(sessionId);
    await sessionUploader.stop();

    // The session's leading client.launch event goes out in a batch of its own.
    const traces = uploads
      .filter((item) => item.snapshot_type === "trace")
      .map((item) => JSON.parse((item.files as Array<{ content: string }>)[0]!.content) as { trace_truncated: boolean; dropped_event_count: number; events: Array<{ type: string }> });
    expect(traces.length).toBeGreaterThan(0);
    const parsed = traces.find((item) => item.trace_truncated);
    expect(parsed).toBeDefined();
    expect(parsed!.dropped_event_count).toBeGreaterThanOrEqual(1);
  });

  test("every upload carries the Idempotency-Key of its session, segment, sequence and type, and its sequence is taken first", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-keys-"));
    const stateDir = await mkdtemp(join(tmpdir(), "omnirush-upload-keys-state-"));
    roots.push(root, stateDir);
    await writeFile(join(root, "app.txt"), "hello\n");
    const sent: Array<{ key: string | undefined; envelope: Record<string, unknown> }> = [];
    const sessionUploader = new SessionUploader({
      capabilities: async () => ({ schema_versions: [1, 2], canonical_trace: false, idempotency_key: true, integrity: true, integrity_summary: true }),
      stateDir,
      upload: async (_sessionId, compressed, _signal, request) => {
        sent.push({ key: request?.idempotencyKey, envelope: withTraceEvents(JSON.parse(zstdDecompressSync(compressed).toString("utf8"))) as Record<string, unknown> });
        // An envelope the server refuses keeps its sequence: the next one never reuses its key.
        return sent.length === 2 ? Response.json({ detail: "bad" }, { status: 422 }) : Response.json({ ok: true }, { status: 201 });
      },
      fallbackScanMs: 60_000,
    });
    const sessionId = "session-keys-1234";
    sessionUploader.startSession(sessionId, "workspace-keys", root);
    sessionUploader.recordTrace(sessionId, "tool.call", {});
    sessionUploader.flushTrace(sessionId);
    await sessionUploader.idle(sessionId);
    sessionUploader.recordTrace(sessionId, "tool.call", {});
    sessionUploader.flushTrace(sessionId);
    await sessionUploader.stop();
    expect(sent.map((item) => [item.envelope.snapshot_type, item.envelope.sequence])).toEqual([["start", 1], ["trace", 2], ["trace", 3], ["end", 4]]);
    for (const item of sent) {
      const envelope = item.envelope as { session_id: string; session_segment: number; sequence: number; snapshot_type: "start" | "trace" | "end" };
      expect(item.key).toBe(uploadIdempotencyKey(envelope.session_id, envelope.session_segment, envelope.sequence, envelope.snapshot_type));
    }
  });

  test("a chat the local ledger does not know continues after the server's segment and sequence", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-position-"));
    const stateDir = await mkdtemp(join(tmpdir(), "omnirush-upload-position-state-"));
    roots.push(root, stateDir);
    const envelopes: Array<Record<string, unknown>> = [];
    const asked: string[] = [];
    const sessionUploader = new SessionUploader({
      capabilities: async () => ({ schema_versions: [1, 2], canonical_trace: false, idempotency_key: true, integrity: true, integrity_summary: true }),
      stateDir,
      upload: async (_sessionId, compressed) => {
        envelopes.push(withTraceEvents(JSON.parse(zstdDecompressSync(compressed).toString("utf8"))) as Record<string, unknown>);
        return Response.json({ ok: true }, { status: 201 });
      },
      sessionIntegrity: async (sessionId, options) => {
        asked.push(`${sessionId}:${options?.summary === true}`);
        return Response.json({ session_id: sessionId, segments: [
          { segment: 1, sequences: [1, 2, 3], gaps: [], max_sequence: 3 },
          { segment: 3, sequences: [9, 10], gaps: [], max_sequence: 10 },
        ] });
      },
      fallbackScanMs: 60_000,
    });
    const sessionId = "session-position-1234";
    sessionUploader.startSession(sessionId, "workspace-position", root);
    await sessionUploader.stop();
    expect(asked).toEqual([`${sessionId}:true`]);
    expect(envelopes[0]).toMatchObject({ snapshot_type: "start", trigger: "resume", session_segment: 4, sequence: 11, session_resumed: true });
  });

  test("a new chat the server has never seen starts at segment 1; the lookup is skipped once the ledger knows it", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-newchat-"));
    const stateDir = await mkdtemp(join(tmpdir(), "omnirush-upload-newchat-state-"));
    roots.push(root, stateDir);
    const envelopes: Array<Record<string, unknown>> = [];
    let asked = 0;
    const make = () => new SessionUploader({
      capabilities: async () => ({ schema_versions: [1, 2], canonical_trace: false, idempotency_key: true, integrity: true, integrity_summary: true }),
      stateDir,
      upload: async (_sessionId, compressed) => {
        envelopes.push(withTraceEvents(JSON.parse(zstdDecompressSync(compressed).toString("utf8"))) as Record<string, unknown>);
        return Response.json({ ok: true }, { status: 201 });
      },
      sessionIntegrity: async () => {
        asked += 1;
        return Response.json({ detail: "session_not_found" }, { status: 404 });
      },
      fallbackScanMs: 60_000,
    });
    const first = make();
    first.startSession("session-newchat-1234", "workspace-newchat", root);
    await first.stop();
    const second = make();
    second.startSession("session-newchat-1234", "workspace-newchat", root);
    await second.stop();
    expect(asked).toBe(1);
    expect(envelopes.filter((item) => item.snapshot_type === "start").map((item) => [item.session_segment, item.sequence])).toEqual([[1, 1], [2, 3]]);
  });

  test("an Idempotency-Key the server holds with other bytes moves the chat past the server's numbering and sends the trace again once", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-reused-"));
    const stateDir = await mkdtemp(join(tmpdir(), "omnirush-upload-reused-state-"));
    roots.push(root, stateDir);
    const accepted: Array<Record<string, unknown>> = [];
    let lookups = 0;
    const sessionUploader = new SessionUploader({
      capabilities: async () => ({ schema_versions: [1, 2], canonical_trace: false, idempotency_key: true, integrity: true, integrity_summary: true }),
      stateDir,
      upload: async (_sessionId, compressed) => {
        const envelope = withTraceEvents(JSON.parse(zstdDecompressSync(compressed).toString("utf8"))) as Record<string, unknown>;
        // The server already holds segment 1 up to sequence 5 (this device's ledger was lost).
        if (envelope.session_segment === 1 && Number(envelope.sequence) <= 5 && envelope.snapshot_type === "trace") {
          return Response.json({ detail: "idempotency_key_reused" }, { status: 409 });
        }
        accepted.push(envelope);
        return Response.json({ ok: true }, { status: 201 });
      },
      sessionIntegrity: async () => {
        lookups += 1;
        // Offline for the first lookup at start; known by the time of the 409.
        return lookups === 1
          ? Response.json({ detail: "unavailable" }, { status: 503 })
          : Response.json({ segments: [{ segment: 1, sequences: [1, 2, 3, 4, 5], gaps: [], max_sequence: 5 }] });
      },
      fallbackScanMs: 60_000,
    });
    const sessionId = "session-reused-1234";
    sessionUploader.startSession(sessionId, "workspace-reused", root);
    sessionUploader.recordTrace(sessionId, "tool.call", { n: 1 });
    sessionUploader.flushTrace(sessionId);
    await sessionUploader.stop();
    const trace = accepted.find((item) => item.snapshot_type === "trace");
    expect(trace).toMatchObject({ session_segment: 2, sequence: 6 });
    expect(JSON.stringify(accepted)).toContain("collector.resegmented");
    expect(accepted.map((item) => [item.snapshot_type, item.session_segment, item.sequence])).toEqual([["start", 1, 1], ["trace", 2, 6], ["trace", 2, 7], ["end", 2, 8]]);
  });

  test("client-raw: a chat keeps the rules pinned at its start; text goes up as written with a credential count", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-raw-"));
    const stateDir = await mkdtemp(join(tmpdir(), "omnirush-upload-raw-state-"));
    roots.push(root, stateDir);
    const token = "sk-1234567890abcdefghijklmnop";
    await writeFile(join(root, "app.txt"), `hello ${token} jane.doe@gmail.com\n`);
    const uploads: Array<{ sessionId: string; envelope: Record<string, unknown> }> = [];
    const make = () => new SessionUploader({
      stateDir,
      upload: async (sessionId, compressed) => {
        uploads.push({ sessionId, envelope: withTraceEvents(JSON.parse(zstdDecompressSync(compressed).toString("utf8"))) });
        return Response.json({ ok: true }, { status: 201 });
      },
      changeDebounceMs: 10,
      fallbackScanMs: 60_000,
    });
    const raw = "session-raw-12345678";
    const later = "session-later-12345678";
    try {
      setRedactionPolicy("client-raw");
      const first = make();
      first.startSession(raw, "workspace-raw", root);
      // The process switch moves mid-chat (a failed policy fetch falls back to the old rules): this chat keeps its pin.
      setRedactionPolicy("legacy");
      first.recordTrace(raw, "tool.call", { token, mail: "jane.doe@gmail.com" });
      first.flushTrace(raw);
      first.startSession(later, "workspace-raw", root);
      await first.stop();
      // Another process under v3: the reopened chat keeps the rules its ledger record was pinned to.
      setRedactionPolicy("client-v3");
      const second = make();
      second.startSession(raw, "workspace-raw", root);
      second.recordTrace(raw, "tool.call", { token });
      second.flushTrace(raw);
      await second.stop();
    } finally {
      setRedactionPolicy("legacy");
    }
    const mine = uploads.filter((upload) => upload.sessionId === raw).map((upload) => upload.envelope);
    expect(mine.some((envelope) => envelope.session_segment === 2)).toBe(true);
    for (const envelope of mine) {
      const privacy = envelope.privacy as Record<string, unknown>;
      expect(privacy.redaction_policy).toBe("client-raw");
      expect(typeof privacy.credential_count).toBe("number");
      expect(JSON.stringify(envelope)).not.toContain("[REDACTED");
    }
    expect(JSON.stringify(mine)).toContain(token);
    expect(mine.some((envelope) => ((envelope.privacy as { credential_count: number }).credential_count) > 0)).toBe(true);
    const other = uploads.filter((upload) => upload.sessionId === later).map((upload) => upload.envelope);
    expect(other.length).toBeGreaterThan(0);
    for (const envelope of other) expect((envelope.privacy as Record<string, unknown>).redaction_policy).toBe("legacy");
    expect(JSON.stringify(other)).not.toContain(token);
  });

  test("reads the server's position from an integrity answer", () => {
    expect(serverSessionPosition({ segments: [{ segment: null, sequences: [1, 4], max_sequence: 4 }, { segment: 2, sequences: [7], max_sequence: 7 }] })).toEqual({ segment: 2, sequence: 7 });
    expect(serverSessionPosition({ segments: [] })).toBeNull();
    expect(serverSessionPosition({ detail: "session_not_found" })).toBeNull();
    expect(serverSessionPosition({ summary: true, max_segment: 3, max_sequence: 12, segments: [] })).toEqual({ segment: 3, sequence: 12 });
    expect(serverSessionPosition({ summary: true, max_segment: null, max_sequence: null, segments: [] })).toBeNull();
  });

  test("the ledger keeps far more than 512 chats, so an older one resumed continues its numbering; only the newest keep sub-agent detail", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-ledger-"));
    const stateDir = await mkdtemp(join(tmpdir(), "omnirush-upload-ledger-state-"));
    roots.push(root, stateDir);
    const sessions: Record<string, unknown> = {};
    for (let index = 0; index < 1_200; index += 1) {
      sessions[`session-ledger-${String(index).padStart(5, "0")}`] = {
        segment: 2,
        nextSequence: 40,
        lastSeenAt: new Date(Date.UTC(2026, 0, 1) + index * 60_000).toISOString(),
        childSessionIds: ["child-a"],
      };
    }
    await writeFile(join(stateDir, "omnirush-upload-sessions.json"), JSON.stringify({ version: 1, sessions }));
    const envelopes: Array<Record<string, unknown>> = [];
    const sessionUploader = new SessionUploader({
      stateDir,
      upload: async (_sessionId, compressed) => {
        envelopes.push(withTraceEvents(JSON.parse(zstdDecompressSync(compressed).toString("utf8"))) as Record<string, unknown>);
        return Response.json({ ok: true }, { status: 201 });
      },
      fallbackScanMs: 60_000,
    });
    // The oldest chat of the 1,200 (it fell out of the old 512 cap).
    sessionUploader.startSession("session-ledger-00000", "workspace-ledger", root);
    await sessionUploader.stop();
    expect(envelopes[0]).toMatchObject({ snapshot_type: "start", session_segment: 3, sequence: 41, session_resumed: true });
    const ledger = JSON.parse(await readFile(join(stateDir, "omnirush-upload-sessions.json"), "utf8")) as { sessions: Record<string, { childSessionIds?: string[] }> };
    expect(Object.keys(ledger.sessions)).toHaveLength(1_200);
    expect(Object.values(ledger.sessions).filter((record) => record.childSessionIds)).toHaveLength(512);
  });

  test("a crash mid-turn loses no trace event: the next start uploads the journal in its own segment, marked recovered, and settles the open turn", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-journal-"));
    const stateDir = await mkdtemp(join(tmpdir(), "omnirush-upload-journal-state-"));
    roots.push(root, stateDir);
    await writeFile(join(root, "app.txt"), "hello\n");
    const envelopes: Array<Record<string, unknown>> = [];
    const upload = async (_sessionId: string, compressed: Uint8Array) => {
      envelopes.push(withTraceEvents(JSON.parse(zstdDecompressSync(compressed).toString("utf8"))) as Record<string, unknown>);
      return Response.json({ ok: true }, { status: 201 });
    };
    const crashed = new SessionUploader({ stateDir, upload, fallbackScanMs: 60_000 });
    const sessionId = "session-journal-1234";
    crashed.startSession(sessionId, "workspace-journal", root);
    await crashed.idle(sessionId);
    crashed.captureSnapshot(sessionId, "prompt");
    crashed.recordTrace(sessionId, "engine.request", { body: "do the task" });
    crashed.recordTrace(sessionId, "tool.call", { name: "edit" });
    await new Promise((resolve) => setTimeout(resolve, 600));
    // The process dies here: no stop(), nothing flushed.
    expect(envelopes.map((item) => item.snapshot_type)).toEqual(["start"]);
    const journals = await readdir(join(stateDir, "omnirush-upload-journal"));
    expect(journals).toHaveLength(1);

    const recoveredTurns: Array<{ sessionId: string; workspaceId: string; root: string }> = [];
    const next = new SessionUploader({ stateDir, upload, fallbackScanMs: 60_000, onRecoveredTurn: (turn) => recoveredTurns.push(turn) });
    for (let waited = 0; waited < 5_000 && recoveredTurns.length === 0; waited += 50) await new Promise((resolve) => setTimeout(resolve, 50));
    const recovered = envelopes[1]!;
    expect(recovered).toMatchObject({ snapshot_type: "trace", session_segment: 1, sequence: 2 });
    const types = (recovered.trace as Array<{ type: string }>).map((event) => event.type);
    expect(types[0]).toBe("collector.recovered");
    expect(types).toContain("engine.request");
    expect(types).toContain("tool.call");
    // The killed run's segment gets its end (marked recovered, turn open); the turn is settled in the next one.
    expect(types.at(-1)).toBe("session.end_recovered");
    expect(envelopes[2]).toMatchObject({ snapshot_type: "end", session_segment: 1, sequence: 3, trigger: "session_end" });
    expect(recoveredTurns).toEqual([{ sessionId, workspaceId: "workspace-journal", root }]);
    expect(await readdir(join(stateDir, "omnirush-upload-journal"))).toEqual([]);
    // The chat's next segment starts after the recovered uploads.
    next.startSession(sessionId, "workspace-journal", root);
    await next.stop();
    expect(envelopes.slice(3).map((item) => [item.snapshot_type, item.session_segment, item.sequence])).toEqual([["start", 2, 4], ["trace", 2, 5], ["end", 2, 6]]);
  }, 20_000);

  test("a recovered journal keeps the chat's pinned rules when the process switch changed between runs", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-journal-pin-"));
    const stateDir = await mkdtemp(join(tmpdir(), "omnirush-upload-journal-pin-state-"));
    roots.push(root, stateDir);
    await writeFile(join(root, "app.txt"), "hello\n");
    const token = "sk-1234567890abcdefghijklmnop";
    const envelopes: Array<Record<string, unknown>> = [];
    const upload = async (_sessionId: string, compressed: Uint8Array) => {
      envelopes.push(withTraceEvents(JSON.parse(zstdDecompressSync(compressed).toString("utf8"))) as Record<string, unknown>);
      return Response.json({ ok: true }, { status: 201 });
    };
    const sessionId = "session-journal-pin-1234";
    try {
      setRedactionPolicy("client-raw");
      const crashed = new SessionUploader({ stateDir, upload, fallbackScanMs: 60_000 });
      crashed.startSession(sessionId, "workspace-journal", root);
      await crashed.idle(sessionId);
      crashed.captureSnapshot(sessionId, "prompt");
      crashed.recordTrace(sessionId, "tool.call", { name: "edit", token });
      await new Promise((resolve) => setTimeout(resolve, 600));
      // The process dies here; the next one starts under other rules.
      setRedactionPolicy("legacy");
      const recoveredTurns: unknown[] = [];
      const next = new SessionUploader({ stateDir, upload, fallbackScanMs: 60_000, onRecoveredTurn: (turn) => recoveredTurns.push(turn) });
      for (let waited = 0; waited < 5_000 && recoveredTurns.length === 0; waited += 50) await new Promise((resolve) => setTimeout(resolve, 50));
      await next.stop();
    } finally {
      setRedactionPolicy("legacy");
    }
    const recovered = envelopes.slice(1);
    expect(recovered.length).toBeGreaterThan(0);
    for (const envelope of recovered) expect((envelope.privacy as Record<string, unknown>).redaction_policy).toBe("client-raw");
    expect(JSON.stringify(recovered)).toContain(token);
  }, 20_000);

  test("a crash after a turn settled, while its trace is on its way, still sends the turn's end and every event at the next start", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-turnend-"));
    const stateDir = await mkdtemp(join(tmpdir(), "omnirush-upload-turnend-state-"));
    roots.push(root, stateDir);
    await writeFile(join(root, "app.txt"), "hello\n");
    const envelopes: Array<Record<string, unknown>> = [];
    const parse = (compressed: Uint8Array) => withTraceEvents(JSON.parse(zstdDecompressSync(compressed).toString("utf8"))) as Record<string, unknown>;
    let traces = 0;
    const hangs: Array<() => void> = [];
    let released = false;
    // An upload that never gets through while the run lives; once it "died", any upload fails at once.
    const stall = () => released ? Promise.resolve(new Response(null, { status: 503 })) : new Promise<Response>((resolve) => hangs.push(() => resolve(new Response(null, { status: 503 }))));
    const crashed = new SessionUploader({
      stateDir,
      upload: async (_sessionId, compressed) => {
        const envelope = parse(compressed);
        if (envelope.snapshot_type === "trace") {
          traces += 1;
          // The turn's own trace never gets through before the app dies (a slow link, a big transcript).
          if (traces > 1) return stall();
          // The flush before it is slow: the turn's end is taken while it is on its way.
          await new Promise((resolve) => setTimeout(resolve, 300));
        }
        envelopes.push(envelope);
        return Response.json({ ok: true }, { status: 201 });
      },
      fallbackScanMs: 60_000,
    });
    const sessionId = "session-turnend-1234";
    crashed.startSession(sessionId, "workspace-turnend", root);
    await crashed.idle(sessionId);
    crashed.captureSnapshot(sessionId, "prompt");
    crashed.recordTrace(sessionId, "tool.call", { n: 1 });
    crashed.flushTrace(sessionId);
    crashed.recordTrace(sessionId, "tool.call", { n: 2 });
    crashed.recordTrace(sessionId, "session.idle", { status: "idle", outcome: "completed" });
    crashed.captureSnapshot(sessionId, "turn_completed");
    crashed.flushTrace(sessionId, { messages: [{ info: { id: "msg_user", role: "user" } }, { info: { id: "msg_answer", role: "assistant", parentID: "msg_user" } }] });
    for (let waited = 0; waited < 5_000 && !envelopes.some((item) => item.snapshot_type === "trace"); waited += 50) await new Promise((resolve) => setTimeout(resolve, 50));
    await new Promise((resolve) => setTimeout(resolve, 600));
    // The process dies here: the turn's trace (its end, its messages) is still on its way.
    const sent = envelopes.length;
    const sentEvents = envelopes.filter((item) => item.snapshot_type === "trace").flatMap((item) => (item.trace as Array<{ type: string; data?: Record<string, unknown> }>) ?? []);
    expect(sentEvents.filter((event) => event.type === "tool.call").map((event) => event.data?.n)).toEqual([1]);
    expect(sentEvents.map((event) => event.type)).not.toContain("turn.completed");

    const next = new SessionUploader({
      stateDir,
      upload: async (_sessionId, compressed) => {
        envelopes.push(parse(compressed));
        return Response.json({ ok: true }, { status: 201 });
      },
      fallbackScanMs: 60_000,
    });
    for (let waited = 0; waited < 5_000 && envelopes.length <= sent; waited += 50) await new Promise((resolve) => setTimeout(resolve, 50));
    const recovered = envelopes[sent]!;
    expect(recovered).toMatchObject({ snapshot_type: "trace", session_segment: 1 });
    const events = recovered.trace as Array<{ type: string; data?: Record<string, unknown> }>;
    expect(events[0]?.type).toBe("collector.recovered");
    expect(events[0]?.data).toMatchObject({ turn_open: false });
    expect(events.filter((event) => event.type === "tool.call").map((event) => event.data?.n)).toEqual([2]);
    const end = events.find((event) => event.type === "turn.completed");
    expect((end?.data?.messages as unknown[] | undefined)?.length).toBe(2);
    await next.stop();
    // The stalled uploads of the run that "died" end, so they hold no upload slot.
    released = true;
    for (const release of hangs) release();
    await crashed.stop().catch(() => undefined);
  }, 20_000);

  test("an upload on its way when the app died leaves no gap: the journal that holds its events goes out under its sequence", async () => {
    for (const serverKnows of [true, false]) {
      const root = await mkdtemp(join(tmpdir(), "omnirush-upload-unsent-"));
      const stateDir = await mkdtemp(join(tmpdir(), "omnirush-upload-unsent-state-"));
      roots.push(root, stateDir);
      await writeFile(join(root, "app.txt"), "hello\n");
      const stored: Array<Record<string, unknown>> = [];
      const hangs: Array<() => void> = [];
      let released = false;
      // An upload that never gets through while the run lives; once it "died", any upload fails at once.
      const stall = () => released ? Promise.resolve(new Response(null, { status: 503 })) : new Promise<Response>((resolve) => hangs.push(() => resolve(new Response(null, { status: 503 }))));
      const options = {
        stateDir,
        fallbackScanMs: 60_000,
        capabilities: async () => ({ schema_versions: [1, 2], canonical_trace: false, idempotency_key: true, integrity: true, integrity_summary: true }),
        sessionIntegrity: async () => serverKnows
          ? Response.json(stored.length === 0
            ? { summary: true, max_segment: null, max_sequence: null, segments: [] }
            : { summary: true, max_segment: 1, max_sequence: Math.max(...stored.map((item) => Number(item.sequence))), segments: [] })
          : Response.json({ detail: "unavailable" }, { status: 503 }),
      };
      const crashed = new SessionUploader({
        ...options,
        upload: async (_sessionId, compressed) => {
          const envelope = withTraceEvents(JSON.parse(zstdDecompressSync(compressed).toString("utf8"))) as Record<string, unknown>;
          // The trace flush is on its way when the app dies: the server never stores it.
          if (envelope.snapshot_type === "trace") return stall();
          stored.push(envelope);
          return Response.json({ ok: true }, { status: 201 });
        },
      });
      const sessionId = "session-unsent-1234";
      crashed.startSession(sessionId, "workspace-unsent", root);
      await crashed.idle(sessionId);
      crashed.recordTrace(sessionId, "tool.call", { n: 1 });
      crashed.flushTrace(sessionId);
      await new Promise((resolve) => setTimeout(resolve, 600));
      expect(stored.map((item) => [item.snapshot_type, item.sequence])).toEqual([["start", 1]]);

      const next = new SessionUploader({
        ...options,
        upload: async (_sessionId, compressed) => {
          stored.push(withTraceEvents(JSON.parse(zstdDecompressSync(compressed).toString("utf8"))) as Record<string, unknown>);
          return Response.json({ ok: true }, { status: 201 });
        },
      });
      for (let waited = 0; waited < 5_000 && !stored.some((item) => item.snapshot_type === "trace"); waited += 50) await new Promise((resolve) => setTimeout(resolve, 50));
      const recovered = stored.find((item) => item.snapshot_type === "trace")!;
      const marker = (recovered.trace as Array<{ type: string; data: Record<string, unknown> }>)[0]!;
      expect(marker.type).toBe("collector.recovered");
      expect((recovered.trace as Array<{ type: string; data: Record<string, unknown> }>).filter((event) => event.type === "tool.call")).toHaveLength(1);
      if (serverKnows) {
        // Sequence 2 never reached the server: the recovered trace takes it.
        expect(recovered).toMatchObject({ session_segment: 1, sequence: 2 });
        expect(marker.data.unsent_sequences).toEqual({ from: 2, to: 2 });
      } else {
        // The server cannot say: the numbering goes on past it, as before.
        expect(recovered).toMatchObject({ session_segment: 1, sequence: 3 });
        expect(marker.data.unsent_sequences).toBeUndefined();
      }
      await next.stop();
      released = true;
      for (const release of hangs) release();
      await crashed.stop().catch(() => undefined);
    }
  }, 30_000);

  test("a recovered journal is a recovered segment when the server takes one, so a run killed before its start snapshot reads as such", async () => {
    for (const recoveredSegments of [true, false]) {
      const root = await mkdtemp(join(tmpdir(), "omnirush-upload-recseg-"));
      const stateDir = await mkdtemp(join(tmpdir(), "omnirush-upload-recseg-state-"));
      roots.push(root, stateDir);
      await writeFile(join(root, "app.txt"), "hello\n");
      const envelopes: Array<Record<string, unknown>> = [];
      const hangs: Array<() => void> = [];
      let released = false;
      // An upload that never gets through while the run lives; once it "died", any upload fails at once.
      const stall = () => released ? Promise.resolve(new Response(null, { status: 503 })) : new Promise<Response>((resolve) => hangs.push(() => resolve(new Response(null, { status: 503 }))));
      const options = {
        stateDir,
        fallbackScanMs: 60_000,
        capabilities: async () => ({ schema_versions: [1, 2], canonical_trace: false, idempotency_key: true, recovered_segments: recoveredSegments }),
      };
      const crashed = new SessionUploader({
        ...options,
        // The start snapshot never goes out: the app dies while it uploads.
        upload: async () => stall(),
      });
      const sessionId = "session-recseg-1234";
      crashed.startSession(sessionId, "workspace-recseg", root);
      crashed.recordTrace(sessionId, "tool.call", { n: 1 });
      await new Promise((resolve) => setTimeout(resolve, 600));
      const next = new SessionUploader({
        ...options,
        upload: async (_sessionId, compressed) => {
          envelopes.push(withTraceEvents(JSON.parse(zstdDecompressSync(compressed).toString("utf8"))) as Record<string, unknown>);
          return Response.json({ ok: true }, { status: 201 });
        },
      });
      for (let waited = 0; waited < 5_000 && !envelopes.some((item) => item.snapshot_type === "trace"); waited += 50) await new Promise((resolve) => setTimeout(resolve, 50));
      const recovered = envelopes.find((item) => item.snapshot_type === "trace");
      expect(recovered).toMatchObject({ trigger: recoveredSegments ? "session_recovered" : "trace_flush" });
      expect((recovered?.trace as Array<{ type: string }>)[0]?.type).toBe("collector.recovered");
      await next.stop();
      released = true;
      for (const release of hangs) release();
      await crashed.stop().catch(() => undefined);
    }
  }, 30_000);

  test("an app that went away after a finished turn: the next launch sends the chat's end (marked recovered), once", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-endrec-"));
    const stateDir = await mkdtemp(join(tmpdir(), "omnirush-upload-endrec-state-"));
    roots.push(root, stateDir);
    await writeFile(join(root, "app.txt"), "hello\n");
    const envelopes: Array<Record<string, unknown>> = [];
    const upload = async (_sessionId: string, compressed: Uint8Array) => {
      envelopes.push(withTraceEvents(JSON.parse(zstdDecompressSync(compressed).toString("utf8"))) as Record<string, unknown>);
      return Response.json({ ok: true }, { status: 201 });
    };
    const crashed = new SessionUploader({ stateDir, upload, fallbackScanMs: 60_000 });
    const sessionId = "session-endrec-1234";
    crashed.startSession(sessionId, "workspace-endrec", root);
    crashed.captureSnapshot(sessionId, "prompt");
    crashed.recordTrace(sessionId, "tool.call", { n: 1 });
    crashed.captureSnapshot(sessionId, "turn_completed");
    crashed.flushTrace(sessionId, { messages: [] });
    await crashed.idle(sessionId);
    await new Promise((resolve) => setTimeout(resolve, 400));
    // The app dies here (a crash, a kill, a power cut): no stop(), so no end.
    expect(envelopes.map((item) => item.snapshot_type)).not.toContain("end");

    const next = new SessionUploader({ stateDir, upload, fallbackScanMs: 60_000 });
    for (let waited = 0; waited < 5_000 && !envelopes.some((item) => item.snapshot_type === "end"); waited += 50) await new Promise((resolve) => setTimeout(resolve, 50));
    const end = envelopes.find((item) => item.snapshot_type === "end");
    expect(end).toMatchObject({ session_id: sessionId, trigger: "session_end" });
    const marked = envelopes.filter((item) => item.snapshot_type === "trace").flatMap((item) => (item.trace as Array<{ type: string }>) ?? []).map((event) => event.type);
    expect(marked).toContain("session.end_recovered");
    for (let waited = 0; waited < 3_000 && (await readdir(join(stateDir, "omnirush-upload-journal"))).length > 0; waited += 50) await new Promise((resolve) => setTimeout(resolve, 50));
    expect(await readdir(join(stateDir, "omnirush-upload-journal"))).toEqual([]);
    await next.stop();
    // A third launch finds nothing to send.
    const count = envelopes.length;
    const third = new SessionUploader({ stateDir, upload, fallbackScanMs: 60_000 });
    await new Promise((resolve) => setTimeout(resolve, 500));
    await third.stop();
    expect(envelopes.length).toBe(count);
  }, 20_000);

  test("a chat left open after a finished turn sends its end once quiet; its next prompt reopens it and its close sends the next end", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-idleend-"));
    const stateDir = await mkdtemp(join(tmpdir(), "omnirush-upload-idleend-state-"));
    roots.push(root, stateDir);
    await writeFile(join(root, "app.txt"), "hello\n");
    const envelopes: Array<Record<string, unknown>> = [];
    const upload = async (_sessionId: string, compressed: Uint8Array) => {
      envelopes.push(withTraceEvents(JSON.parse(zstdDecompressSync(compressed).toString("utf8"))) as Record<string, unknown>);
      return Response.json({ ok: true }, { status: 201 });
    };
    const ledger = async () => (JSON.parse(await readFile(join(stateDir, "omnirush-upload-sessions.json"), "utf8")) as { sessions: Record<string, { endedAt?: string; segment: number }> }).sessions;
    const waitFor = async (check: () => boolean | Promise<boolean>) => {
      for (let waited = 0; waited < 5_000 && !(await check()); waited += 25) await new Promise((resolve) => setTimeout(resolve, 25));
    };
    const uploader = new SessionUploader({ stateDir, upload, fallbackScanMs: 60_000, idleEndMs: 300 });
    const sessionId = "session-idleend-1234";
    uploader.startSession(sessionId, "workspace-idleend", root);
    uploader.captureSnapshot(sessionId, "prompt");
    await writeFile(join(root, "app.txt"), "hello, turn one\n");
    uploader.captureSnapshot(sessionId, "turn_completed");
    uploader.flushTrace(sessionId, { messages: [] });
    await waitFor(() => envelopes.some((item) => item.snapshot_type === "end"));
    // The app stays open: the chat's end is out, with the turn's state.
    const first = envelopes.findIndex((item) => item.snapshot_type === "end");
    expect(envelopes[first]).toMatchObject({ session_id: sessionId, session_segment: 1, trigger: "session_end" });
    const before = envelopes.slice(0, first).filter((item) => item.snapshot_type === "trace").flatMap((item) => (item.trace as Array<{ type: string }>) ?? []).map((event) => event.type);
    expect(before).toContain("turn.completed");
    expect(before.at(-1)).toBe("session.idle_end");
    await waitFor(async () => Boolean((await ledger())[sessionId]?.endedAt));
    expect((await ledger())[sessionId]?.endedAt).toBeString();
    // A next prompt reopens the chat: the ledger no longer says it ended.
    uploader.captureSnapshot(sessionId, "prompt");
    await waitFor(async () => !(await ledger())[sessionId]?.endedAt);
    expect((await ledger())[sessionId]?.endedAt).toBeUndefined();
    await writeFile(join(root, "app.txt"), "hello, turn two\n");
    uploader.captureSnapshot(sessionId, "turn_completed");
    uploader.flushTrace(sessionId, { messages: [] });
    // Closed before it went quiet: the close sends the chat's end, after the first one.
    await uploader.stop();
    const ends = envelopes.filter((item) => item.snapshot_type === "end");
    expect(ends.map((item) => [item.session_segment, item.trigger])).toEqual([[1, "session_end"], [1, "session_end"]]);
    expect((ends[1]!.sequence as number) > (ends[0]!.sequence as number)).toBe(true);
    const sequences = envelopes.map((item) => item.sequence as number);
    expect(new Set(sequences).size).toBe(sequences.length);
  }, 20_000);

  test("a chat whose quiet end is its last state sends no second end at close; one with edits since does", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-idleend2-"));
    roots.push(root);
    await writeFile(join(root, "app.txt"), "hello\n");
    const envelopes: Array<Record<string, unknown>> = [];
    const upload = async (_sessionId: string, compressed: Uint8Array) => {
      envelopes.push(withTraceEvents(JSON.parse(zstdDecompressSync(compressed).toString("utf8"))) as Record<string, unknown>);
      return Response.json({ ok: true }, { status: 201 });
    };
    const uploader = new SessionUploader({ upload, fallbackScanMs: 60_000, idleEndMs: 200, changeDebounceMs: 10_000 });
    const quiet = "session-idleend-quiet";
    const edited = "session-idleend-edited";
    const other = await mkdtemp(join(tmpdir(), "omnirush-upload-idleend3-"));
    roots.push(other);
    await writeFile(join(other, "b.txt"), "b\n");
    uploader.startSession(quiet, "ws", root);
    uploader.startSession(edited, "ws2", other);
    for (const id of [quiet, edited]) {
      uploader.captureSnapshot(id, "prompt");
      uploader.captureSnapshot(id, "turn_completed");
      uploader.flushTrace(id, { messages: [] });
    }
    for (let waited = 0; waited < 5_000 && envelopes.filter((item) => item.snapshot_type === "end").length < 2; waited += 25) await new Promise((resolve) => setTimeout(resolve, 25));
    await Promise.all([uploader.idle(quiet), uploader.idle(edited)]);
    // An edit after the quiet end, still waiting for its change snapshot as the app quits.
    await writeFile(join(other, "b.txt"), "b, edited after\n");
    for (let waited = 0; waited < 2_000; waited += 25) await new Promise((resolve) => setTimeout(resolve, 25));
    await uploader.stop();
    const endsOf = (id: string) => envelopes.filter((item) => item.session_id === id && item.snapshot_type === "end").length;
    expect(endsOf(quiet)).toBe(1);
    expect(endsOf(edited)).toBe(2);
  }, 20_000);

  test("a journal whose chat the ledger lost: the next launch sends its end, numbered after the server's copy", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-lostledger-"));
    const stateDir = await mkdtemp(join(tmpdir(), "omnirush-upload-lostledger-state-"));
    roots.push(root, stateDir);
    await writeFile(join(root, "app.txt"), "hello\n");
    const envelopes: Array<Record<string, unknown>> = [];
    const upload = async (_sessionId: string, compressed: Uint8Array) => {
      envelopes.push(withTraceEvents(JSON.parse(zstdDecompressSync(compressed).toString("utf8"))) as Record<string, unknown>);
      return Response.json({ ok: true }, { status: 201 });
    };
    const crashed = new SessionUploader({ stateDir, upload, fallbackScanMs: 60_000, idleEndMs: 0 });
    const sessionId = "session-lostledger-1234";
    crashed.startSession(sessionId, "workspace-lostledger", root);
    crashed.captureSnapshot(sessionId, "prompt");
    crashed.captureSnapshot(sessionId, "turn_completed");
    crashed.flushTrace(sessionId, { messages: [] });
    await crashed.idle(sessionId);
    crashed.recordTrace(sessionId, "tool.call", { n: 2 });
    await new Promise((resolve) => setTimeout(resolve, 400));
    // Killed; and the ledger lost the chat.
    await rm(join(stateDir, "omnirush-upload-sessions.json"), { force: true });
    const top = Math.max(...envelopes.map((item) => item.sequence as number));
    const next = new SessionUploader({
      stateDir,
      upload,
      fallbackScanMs: 60_000,
      capabilities: async () => ({ schema_versions: [1, 2], canonical_trace: false, idempotency_key: true, integrity: true, integrity_summary: true }),
      sessionIntegrity: async (id) => Response.json({ session_id: id, max_segment: 1, max_sequence: top, segments: [{ segment: 1, sequences: [], gaps: [], max_sequence: top }] }),
      confirm: false,
    });
    for (let waited = 0; waited < 5_000 && !envelopes.some((item) => item.snapshot_type === "end"); waited += 50) await new Promise((resolve) => setTimeout(resolve, 50));
    await next.stop();
    const recovered = envelopes.filter((item) => (item.sequence as number) > top);
    expect(recovered.map((item) => [item.snapshot_type, item.session_segment, item.sequence])).toEqual([["trace", 1, top + 1], ["end", 1, top + 2]]);
    const marker = (recovered[0]!.trace as Array<{ type: string; data?: Record<string, unknown> }>).find((event) => event.type === "session.end_recovered");
    expect(marker?.data).toMatchObject({ reason: "run_ended_without_end", ledger: "missing" });
  }, 20_000);

  test("a ledger record with no end and no journal (an older launch read it): the next launch sends the end the server lacks, once", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-ledgerend-"));
    const stateDir = await mkdtemp(join(tmpdir(), "omnirush-upload-ledgerend-state-"));
    roots.push(root, stateDir);
    await writeFile(join(root, "app.txt"), "hello\n");
    const envelopes: Array<Record<string, unknown>> = [];
    const upload = async (_sessionId: string, compressed: Uint8Array) => {
      envelopes.push(withTraceEvents(JSON.parse(zstdDecompressSync(compressed).toString("utf8"))) as Record<string, unknown>);
      return Response.json({ ok: true }, { status: 201 });
    };
    const crashed = new SessionUploader({ stateDir, upload, fallbackScanMs: 60_000, idleEndMs: 0 });
    const missing = "session-ledgerend-missing";
    const held = "session-ledgerend-held";
    for (const id of [missing, held]) {
      crashed.startSession(id, "workspace-ledgerend", root);
      crashed.captureSnapshot(id, "prompt");
      crashed.captureSnapshot(id, "turn_completed");
      crashed.flushTrace(id, { messages: [] });
      await crashed.idle(id);
    }
    await new Promise((resolve) => setTimeout(resolve, 400));
    // Killed, then a launch of an older version read (and deleted) the journals.
    await rm(join(stateDir, "omnirush-upload-journal"), { recursive: true, force: true });
    const asked: string[] = [];
    const make = () => new SessionUploader({
      stateDir,
      upload,
      fallbackScanMs: 60_000,
      capabilities: async () => ({ schema_versions: [1, 2], canonical_trace: false, idempotency_key: true, integrity: true, integrity_summary: true }),
      sessionIntegrity: async (id, options) => {
        asked.push(`${id}:${options?.summary === true}`);
        // The server holds `held`'s end already (sent, the ledger never heard).
        const uploads = [{ snapshot_type: "start", sequence: 1 }, { snapshot_type: "trace", sequence: 2 }, ...(id === held ? [{ snapshot_type: "end", sequence: 3 }] : [])];
        return Response.json({ session_id: id, segments: [{ segment: 1, sequences: uploads.map((item) => item.sequence), gaps: [], max_sequence: uploads.length, uploads }] });
      },
      confirm: false,
    });
    const next = make();
    for (let waited = 0; waited < 5_000 && !envelopes.some((item) => item.snapshot_type === "end"); waited += 50) await new Promise((resolve) => setTimeout(resolve, 50));
    await next.stop();
    const ends = envelopes.filter((item) => item.snapshot_type === "end");
    expect(ends.map((item) => [item.session_id, item.session_segment, item.trigger])).toEqual([[missing, 1, "session_end"]]);
    const marker = envelopes.filter((item) => item.session_id === missing && item.snapshot_type === "trace").flatMap((item) => (item.trace as Array<{ type: string; data?: Record<string, unknown> }>) ?? []).find((event) => event.type === "session.end_recovered");
    expect(marker?.data).toMatchObject({ reason: "ledger_without_end" });
    expect(asked.sort()).toEqual([`${held}:false`, `${missing}:false`]);
    // A third launch finds nothing left to send or ask: `missing` ended, and the ledger now knows `held` did.
    const count = envelopes.length;
    const third = make();
    await new Promise((resolve) => setTimeout(resolve, 500));
    await third.stop();
    expect(envelopes.length).toBe(count);
    expect(asked).toHaveLength(2);
  }, 20_000);

  test("the base's outcome rides along (collector.project_archive, workspace.project_archive); two chats on one folder mark turn.overlap", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-gaps-"));
    const stateDir = await mkdtemp(join(tmpdir(), "omnirush-upload-gaps-state-"));
    roots.push(root, stateDir);
    await writeFile(join(root, "app.txt"), "hello\n");
    const envelopes: Array<Record<string, unknown>> = [];
    const upload = async (_sessionId: string, compressed: Uint8Array) => {
      envelopes.push(withTraceEvents(JSON.parse(zstdDecompressSync(compressed).toString("utf8"))) as Record<string, unknown>);
      return Response.json({ ok: true }, { status: 201 });
    };
    const uploader = new SessionUploader({ stateDir, upload, fallbackScanMs: 60_000 });
    const a = "session-gaps-a-1234";
    const b = "session-gaps-b-1234";
    uploader.startSession(a, "ws", root);
    uploader.startSession(b, "ws", root);
    await Promise.all([uploader.idle(a), uploader.idle(b)]);
    uploader.recordProjectArchive(a, { status: "skipped", reason: "not_archivable", detail: "no_git_folder_policy_off" });
    uploader.captureSnapshot(a, "prompt");
    uploader.captureSnapshot(b, "prompt");
    await Promise.all([uploader.idle(a), uploader.idle(b)]);
    await writeFile(join(root, "from-b.txt"), "b wrote this\n");
    uploader.captureSnapshot(a, "turn_completed");
    await uploader.idle(a);
    await uploader.stop();
    const traceOf = (id: string) => envelopes.filter((item) => item.session_id === id && item.snapshot_type === "trace").flatMap((item) => (item.trace as Array<{ type: string; data: Record<string, unknown> }>) ?? []);
    expect(traceOf(a).find((event) => event.type === "collector.project_archive")?.data).toEqual({ status: "skipped", reason: "not_archivable", detail: "no_git_folder_policy_off" });
    const end = envelopes.find((item) => item.session_id === a && item.snapshot_type === "end") as { workspace: Record<string, unknown> };
    expect(end.workspace.project_archive).toEqual({ status: "skipped", reason: "not_archivable", detail: "no_git_folder_policy_off" });
    const overlap = traceOf(a).find((event) => event.type === "turn.overlap");
    expect(overlap?.data.other_session_ids).toEqual([b]);
    expect(overlap?.data.not_written_here).toEqual(["from-b.txt"]);
  }, 20_000);

  test("the journal holds only what is not yet handed to an upload, and is gone once the chat ends", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-journal2-"));
    const stateDir = await mkdtemp(join(tmpdir(), "omnirush-upload-journal2-state-"));
    roots.push(root, stateDir);
    const sessionUploader = new SessionUploader({
      stateDir,
      upload: async () => Response.json({ ok: true }, { status: 201 }),
      fallbackScanMs: 60_000,
    });
    const sessionId = "session-journal2-1234";
    sessionUploader.startSession(sessionId, "workspace-journal2", root);
    sessionUploader.captureSnapshot(sessionId, "prompt");
    sessionUploader.recordTrace(sessionId, "tool.call", { n: 1 });
    sessionUploader.captureSnapshot(sessionId, "turn_completed");
    sessionUploader.flushTrace(sessionId, { messages: [] });
    await sessionUploader.idle(sessionId);
    await new Promise((resolve) => setTimeout(resolve, 400));
    const dir = join(stateDir, "omnirush-upload-journal");
    const [name] = await readdir(dir);
    const journal = parseJournal(await readFile(join(dir, name!), "utf8"));
    expect(journal?.meta).toMatchObject({ session_id: sessionId, turn_open: false, segment: 1 });
    expect(journal?.events.map((event) => event.type) ?? []).not.toContain("tool.call");
    await sessionUploader.stop();
    expect(await readdir(dir)).toEqual([]);
  }, 20_000);

  test("reads a journal cut off mid-line by a crash", () => {
    const meta = { v: 1 as const, session_id: "session-cut-1234", workspace_id: "ws", root: "/w", segment: 3, turn_open: true, at: "2026-10-10T00:00:00.000Z" };
    const text = `${JSON.stringify({ m: meta })}\n${JSON.stringify({ e: { at: "t", type: "tool.call", data: { a: 1 } } })}\n{"e":{"at":"t","ty`;
    expect(parseJournal(text)).toEqual({ meta, events: [{ at: "t", type: "tool.call", data: { a: 1 } }] });
    expect(parseJournal(`${JSON.stringify({ e: { at: "t", type: "x" } })}\n`)).toBeNull();
  });

  test("a schema 2 trace upload carries its events in trace.json only; schema 3 in the top-level trace only", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-forms-"));
    roots.push(root);
    for (const canonical of [false, true]) {
      const raw: Array<Record<string, unknown>> = [];
      const sessionUploader = new SessionUploader({
        upload: async (_sessionId, compressed) => {
          raw.push(JSON.parse(zstdDecompressSync(compressed).toString("utf8")) as Record<string, unknown>);
          return Response.json({ ok: true }, { status: 201 });
        },
        capabilities: async () => ({ schema_versions: canonical ? [1, 2, 3] : [1, 2], canonical_trace: canonical }),
        fallbackScanMs: 60_000,
      });
      sessionUploader.startSession("session-forms-1234", "workspace-forms", root);
      sessionUploader.recordTrace("session-forms-1234", "tool.call", {});
      sessionUploader.flushTrace("session-forms-1234");
      await sessionUploader.stop();
      const trace = raw.find((item) => item.snapshot_type === "trace")!;
      const files = trace.files as Array<{ path: string }>;
      if (canonical) {
        expect(Array.isArray(trace.trace)).toBe(true);
        expect(files).toEqual([]);
      } else {
        expect("trace" in trace).toBe(false);
        expect(files.map((file) => file.path)).toEqual(["__omnirush__/trace.json"]);
      }
    }
  });

  test("persists session segments and message checkpoints across a resume", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-resume-"));
    const stateDir = await mkdtemp(join(tmpdir(), "omnirush-upload-state-"));
    roots.push(root, stateDir);
    const uploads: Array<Record<string, unknown>> = [];
    const makeUploader = () => new SessionUploader({
      stateDir,
      upload: async (_sessionId, compressed) => {
        uploads.push(withTraceEvents(JSON.parse(zstdDecompressSync(compressed).toString("utf8"))) as Record<string, unknown>);
        return Response.json({ ok: true }, { status: 201 });
      },
      fallbackScanMs: 60_000,
    });
    const sessionId = "session-resume-1234";
    const first = makeUploader();
    first.startSession(sessionId, "workspace-resume", root);
    await new Promise((resolve) => setTimeout(resolve, 30));
    await first.setSessionCheckpoint(sessionId, "message-1");
    await first.stop();

    const second = makeUploader();
    second.startSession(sessionId, "workspace-resume", root);
    await new Promise((resolve) => setTimeout(resolve, 30));
    expect(await second.sessionCheckpoint(sessionId)).toMatchObject({ resumed: true, segment: 2, lastMessageId: "message-1" });
    await second.stop();

    const starts = uploads.filter((item) => item.snapshot_type === "start");
    expect(starts).toHaveLength(2);
    expect(starts[1]).toMatchObject({ session_segment: 2, session_resumed: true });
    const traceTypes = uploads
      .filter((item) => item.snapshot_type === "trace")
      .flatMap((item) => JSON.parse((item.files as Array<{ content: string }>)[0].content).events.map((event: { type: string }) => event.type));
    expect(traceTypes).toContain("session.resumed");
  });

  test("captures changed files in a bounded journal before the next snapshot", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-changes-"));
    roots.push(root);
    const uploads: Array<Record<string, unknown>> = [];
    const sessionUploader = new SessionUploader({
      upload: async (_sessionId, compressed) => {
        uploads.push(withTraceEvents(JSON.parse(zstdDecompressSync(compressed).toString("utf8"))) as Record<string, unknown>);
        return Response.json({ ok: true }, { status: 201 });
      },
      changeDebounceMs: 10,
      fallbackScanMs: 60_000,
    });
    const sessionId = "session-changes-1234";
    sessionUploader.startSession(sessionId, "workspace-changes", root);
    await sessionUploader.idle(sessionId);
    await writeFile(join(root, "created.txt"), "contact jane@acme-mail.io");
    sessionUploader.recordTrace(sessionId, "file.read", { path: "created.txt" });
    sessionUploader.flushTrace(sessionId);
    await new Promise((resolve) => setTimeout(resolve, 40));
    await sessionUploader.stop();

    const change = uploads.find((item) => item.snapshot_type === "change");
    expect(change).toBeDefined();
    const changeFile = (change?.files as Array<{ path: string; content: string }>).find((file) => file.path === "__omnirush__/changes.json");
    expect(changeFile).toBeDefined();
    expect(changeFile?.content).toContain('"path":"created.txt"');
    expect(changeFile?.content).not.toContain("jane@acme-mail.io");
  });

  test("records a privacy manifest and touched paths without uploading denied files", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-manifest-"));
    roots.push(root);
    await writeFile(join(root, "touched.ts"), "export const ok = true;");
    await writeFile(join(root, ".env.local"), "SECRET=do-not-upload");
    const uploads: Array<Record<string, unknown>> = [];
    const sessionUploader = new SessionUploader({
      upload: async (_sessionId, compressed) => {
        uploads.push(withTraceEvents(JSON.parse(zstdDecompressSync(compressed).toString("utf8"))) as Record<string, unknown>);
        return Response.json({ ok: true }, { status: 201 });
      },
      fallbackScanMs: 60_000,
    });
    const sessionId = "session-manifest-1234";
    sessionUploader.startSession(sessionId, "workspace-manifest", root);
    sessionUploader.recordTrace(sessionId, "file.read", { path: "touched.ts" });
    sessionUploader.flushTrace(sessionId);
    await sessionUploader.stop();
    const start = uploads.find((item) => item.snapshot_type === "start");
    const workspaceFile = (start?.files as Array<{ path: string; content: string }>).find((file) => file.path === "__omnirush__/workspace.json");
    expect(workspaceFile?.content).toContain('"capture_policy":"consented_workspace_session"');
    expect(workspaceFile?.content).toContain('"touched_paths":["touched.ts"]');
    expect(JSON.stringify(uploads)).not.toContain("do-not-upload");
  });

  test("keeps paths outside the workspace root out of capture: parents, other Windows drives and UNC shares", async () => {
    // Windows: path.relative returns a path on another drive as it is, which a `../` check let through.
    const windowsRoot = "C:\\Users\\dev\\omnirush.ai";
    for (const outside of [
      "D:\\data\\file.csv",
      "D:/data/file.csv",
      "d:\\data\\file.csv",
      "D:file.csv",
      "\\\\server\\share\\file.csv",
      "C:\\Users\\dev\\other\\file.csv",
      "C:\\Users\\dev\\omnirush.ai-other\\file.csv",
      "..\\file.csv",
      "src\\..\\..\\file.csv",
      windowsRoot,
    ]) {
      expect([outside, workspaceRelativePath(windowsRoot, outside, win32)]).toEqual([outside, null]);
    }
    expect(workspaceRelativePath(windowsRoot, "C:\\Users\\dev\\omnirush.ai\\src\\app.ts", win32)).toBe("src/app.ts");
    expect(workspaceRelativePath(windowsRoot, "c:\\users\\dev\\omnirush.ai\\src\\app.ts", win32)).toBe("src/app.ts");
    expect(workspaceRelativePath(windowsRoot, "src/app.ts", win32)).toBe("src/app.ts");
    // POSIX.
    for (const outside of ["/etc/hosts", "../ws-other/file.csv", "..", "/home/dev/ws"]) {
      expect([outside, workspaceRelativePath("/home/dev/ws", outside, posix)]).toEqual([outside, null]);
    }
    expect(workspaceRelativePath("/home/dev/ws", "/home/dev/ws/..notes.md", posix)).toBe("..notes.md");
    expect(workspaceRelativePath("/home/dev/ws", "src/app.ts", posix)).toBe("src/app.ts");

    // Through the session uploader: a tool naming a file outside the root reads nothing of it.
    const base = await mkdtemp(join(tmpdir(), "omnirush-upload-outside-"));
    roots.push(base);
    const root = join(base, "workspace");
    await mkdir(root);
    await writeFile(join(base, "outside.csv"), "OUTSIDE_FILE_MARKER");
    await writeFile(join(root, "inside.txt"), "inside");
    const { uploads, upload } = makeUploads();
    const sessionUploader = new SessionUploader({ upload, changeDebounceMs: 10, fallbackScanMs: 60_000 });
    const sessionId = "session-outside-1234";
    sessionUploader.startSession(sessionId, "workspace-outside", root);
    await sessionUploader.idle(sessionId);
    sessionUploader.recordTrace(sessionId, "file.read", { path: join(base, "outside.csv") });
    sessionUploader.recordTrace(sessionId, "file.read", { path: "../outside.csv" });
    sessionUploader.recordTrace(sessionId, "file.read", { path: "inside.txt" });
    sessionUploader.flushTrace(sessionId);
    await new Promise((resolve) => setTimeout(resolve, 40));
    await sessionUploader.stop();
    expect(uploads.at(-1)?.touched_paths).toEqual(["inside.txt"]);
    const files = uploads.flatMap((envelope) => envelope.files);
    expect(files.some((file) => file.content.includes("OUTSIDE_FILE_MARKER"))).toBe(false);
    expect(files.filter((file) => file.path === "__omnirush__/changes.json").map((file) => file.content).join()).not.toContain("outside.csv");
  });

  test("reports every path the session touches inside the root to the project archive, denied names too, and none outside", async () => {
    const base = await mkdtemp(join(tmpdir(), "omnirush-upload-touched-"));
    roots.push(base);
    const root = join(base, "workspace");
    await mkdir(join(root, "docs"), { recursive: true });
    await writeFile(join(base, "outside.csv"), "OUTSIDE");
    await writeFile(join(root, "docs/brief.pdf"), Buffer.from([0x25, 0x50, 0x44, 0x46, 0, 1, 2]));
    const touched: Array<[string, string]> = [];
    const { upload } = makeUploads();
    const sessionUploader = new SessionUploader({ upload, changeDebounceMs: 10, fallbackScanMs: 60_000, onPathTouched: (sessionId, path) => touched.push([sessionId, path]) });
    const sessionId = "session-touched-1234";
    sessionUploader.startSession(sessionId, "workspace-touched", root);
    await sessionUploader.idle(sessionId);
    // The agent reads a PDF (absolute path, in a tool input), names a file outside, and a credential file.
    sessionUploader.recordTrace(sessionId, "tool.read", { input: { filePath: join(root, "docs/brief.pdf") } });
    sessionUploader.recordTrace(sessionId, "tool.read", { path: join(base, "outside.csv") });
    sessionUploader.recordTrace(sessionId, "tool.read", { path: "../outside.csv" });
    sessionUploader.recordTrace(sessionId, "tool.read", { path: ".env" });
    // A command writes a binary: the watcher sees it land.
    await writeFile(join(root, "render.png"), Buffer.from([0x89, 0x50, 0x4e, 0x47, 0, 0, 1]));
    const deadline = Date.now() + 10_000;
    while (!touched.some(([, path]) => path === "render.png") && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 20));
    await sessionUploader.stop();
    const paths = new Set(touched.map(([, path]) => path));
    expect(touched.every(([id]) => id === sessionId)).toBe(true);
    for (const path of ["docs/brief.pdf", ".env", "render.png"]) expect(paths.has(path)).toBe(true);
    expect([...paths].filter((path) => path.includes("outside") || path.startsWith("..") || path.startsWith("/"))).toEqual([]);
  });

  test("reports only what the session touches when its start snapshot was refused", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-touched-refused-"));
    roots.push(root);
    await mkdir(join(root, "private"));
    await writeFile(join(root, "private/ledger.csv"), "untouched\n");
    await writeFile(join(root, "private/scan.pdf"), Buffer.from([0x25, 0x50, 0x44, 0x46, 0, 1, 2]));
    await writeFile(join(root, "notes.md"), "untouched\n");
    // macOS delivers writes made just before a watch starts to the new watcher: these files predate the session.
    await new Promise((resolve) => setTimeout(resolve, 500));
    const touched: string[] = [];
    const types: string[] = [];
    // The backend refuses the start snapshot (a 400 is never spooled), so no manifest is accepted.
    const upload = async (_sessionId: string, compressed: Uint8Array) => {
      const type = (withTraceEvents(JSON.parse(zstdDecompressSync(compressed).toString("utf8"))) as { snapshot_type: string }).snapshot_type;
      types.push(type);
      return type === "start" ? Response.json({ error: "bad_request" }, { status: 400 }) : Response.json({ ok: true }, { status: 201 });
    };
    const sessionUploader = new SessionUploader({ upload, changeDebounceMs: 10, fallbackScanMs: 60_000, onPathTouched: (_sessionId, path) => touched.push(path) });
    const sessionId = "session-touched-refused-1";
    sessionUploader.startSession(sessionId, "workspace-touched-refused", root);
    await sessionUploader.idle(sessionId);
    sessionUploader.captureSnapshot(sessionId, "prompt");
    await writeFile(join(root, "result.txt"), "the agent's output\n");
    const deadline = Date.now() + 10_000;
    while (!touched.includes("result.txt") && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 20));
    sessionUploader.captureSnapshot(sessionId, "turn_completed");
    await sessionUploader.idle(sessionId);
    await sessionUploader.stop();
    expect(types[0]).toBe("start");
    // Later captures scanned the whole tree with no accepted baseline.
    expect(types).toContain("end");
    expect(touched).toContain("result.txt");
    expect([...new Set(touched)].filter((path) => path !== "result.txt")).toEqual([]);
  });
});

// --- session uploader envelope v2 ---------------------------------------------------

type Envelope = Record<string, unknown> & {
  files: Array<{ path: string; content: string; sha256: string }>;
  manifest: Array<{ path: string; sha256: string; size: number; mode?: number; type?: "symlink"; target?: string; broken?: boolean; binary?: boolean; archived?: string }>;
  workspace: { root_name: string; git: Record<string, unknown> | null };
  environment: Record<string, unknown>;
  privacy: Record<string, unknown>;
  touched_paths: string[];
  trace?: Array<{ type: string; data?: Record<string, unknown> }>;
};

const sha256 = (text: string) => createHash("sha256").update(text).digest("hex");

function makeUploads() {
  const uploads: Envelope[] = [];
  const upload = async (_sessionId: string, compressed: Uint8Array) => {
    uploads.push(withTraceEvents(JSON.parse(zstdDecompressSync(compressed).toString("utf8"))) as Envelope);
    return Response.json({ ok: true }, { status: 201 });
  };
  return { uploads, upload };
}

async function git(root: string, ...args: string[]): Promise<string> {
  const { stdout } = await execFileAsync("git", ["-C", root, "-c", "commit.gpgsign=false", "-c", "user.name=Dev", "-c", "user.email=dev@acme-mail.io", ...args]);
  return String(stdout).trim();
}

describe("session uploader envelope v2", () => {
  test("uploads a v2 envelope with trigger, environment, manifest, hashed files and privacy fields", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-v2-"));
    roots.push(root);
    await writeFile(join(root, "app.ts"), "export const answer = 42;\n");
    await mkdir(join(root, "nested"));
    await writeFile(join(root, "nested", "note.md"), "call me at +1 (415) 555-0132\n");
    await writeFile(join(root, ".env"), "TOKEN=nope\n");
    const { uploads, upload } = makeUploads();
    const sessionUploader = new SessionUploader({ upload, fallbackScanMs: 60_000, appVersion: "1.2.3", engineVersion: "9.9.9" });
    const sessionId = "session-v2-envelope-1";
    sessionUploader.startSession(sessionId, "workspace-v2", root);
    sessionUploader.recordTrace(sessionId, "file.read", { path: "app.ts" });
    sessionUploader.flushTrace(sessionId);
    await sessionUploader.stop();

    expect(uploads.map((item) => [item.snapshot_type, item.trigger])).toEqual([
      ["start", "session_start"],
      ["trace", "trace_flush"],
      ["end", "session_end"],
    ]);
    for (const envelope of uploads) {
      expect(envelope.schema_version).toBe(UPLOAD_SCHEMA_VERSION);
      expect(typeof envelope.captured_at).toBe("string");
      expect(Number.isNaN(Date.parse(envelope.captured_at as string))).toBe(false);
      expect(envelope.workspace.root_name).toBe(basename(root));
      expect(envelope.environment).toMatchObject({
        os: process.platform,
        arch: process.arch,
        app_version: "1.2.3",
        engine_version: "9.9.9",
      });
      for (const key of ["os_version", "node_version", "shell", "locale", "timezone", "git_version"]) {
        expect(key in envelope.environment).toBe(true);
      }
      expect(envelope.privacy).toMatchObject({ capture_policy: "consented_workspace_session", git_internals_excluded: true, environment_variables_excluded: true });
      expect(envelope.touched_paths).toEqual(["app.ts"]);
      for (const file of envelope.files) expect(file.sha256).toBe(sha256(file.content));
    }
    const start = uploads[0]!;
    expect(start.workspace.git).toBeNull();
    expect(start.manifest.map((entry) => entry.path).sort()).toEqual(["app.ts", "nested/note.md"]);
    for (const entry of start.manifest) {
      const file = start.files.find((candidate) => candidate.path === entry.path);
      expect(file).toBeDefined();
      expect(file?.sha256).toBe(entry.sha256);
      expect(entry.size).toBe(Buffer.byteLength(file!.content));
    }
    // Hashes and timestamps can legitimately contain "415"; the number itself must be gone.
    expect(JSON.stringify(uploads)).not.toContain("(415)");
    expect(JSON.stringify(uploads)).not.toContain("555-0132");
    expect(JSON.stringify(uploads)).not.toContain("TOKEN=nope");
    const trace = uploads[1]!;
    expect(Array.isArray(trace.trace)).toBe(true);
    expect(trace.trace?.map((event) => event.type)).toContain("file.read");
    expect(trace.manifest).toEqual([]);
  });

  test("uses canonical trace schema 3, then retries the same batch as schema 2 on an explicit 422", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-trace-schema-"));
    roots.push(root);
    const attempts: Envelope[] = [];
    let capabilityCalls = 0;
    let rejectSchema3 = true;
    const sessionUploader = new SessionUploader({
      capabilities: async () => {
        capabilityCalls += 1;
        return { schema_versions: [1, 2, 3], canonical_trace: true };
      },
      upload: async (_sessionId, compressed) => {
        const envelope = withTraceEvents(JSON.parse(zstdDecompressSync(compressed).toString("utf8"))) as Envelope;
        attempts.push(envelope);
        if (envelope.schema_version === 3 && rejectSchema3) {
          rejectSchema3 = false;
          return Response.json({ error: "unsupported_schema", schema_version: 3 }, { status: 422 });
        }
        return Response.json({ ok: true }, { status: 201 });
      },
      fallbackScanMs: 60_000,
    });
    const sessionId = "session-trace-schema-1";
    sessionUploader.startSession(sessionId, "workspace-trace-schema", root);
    await sessionUploader.idle(sessionId);
    sessionUploader.recordTrace(sessionId, "engine.request", { path: "src/app.ts" });
    sessionUploader.flushTrace(sessionId);
    await sessionUploader.idle(sessionId);
    await sessionUploader.stop();

    expect(capabilityCalls).toBe(1);
    expect(attempts.map((envelope) => [envelope.snapshot_type, envelope.schema_version])).toEqual([
      ["start", 2],
      ["trace", 3],
      ["trace", 2],
      ["end", 2],
    ]);
    const rejected = attempts[1]!;
    const fallback = attempts[2]!;
    expect(rejected.files).toEqual([]);
    expect(rejected.trace?.map((event) => event.type)).toEqual(["client.launch", "engine.request"]);
    expect(fallback.files.map((file) => file.path)).toEqual(["__omnirush__/trace.json"]);
    expect(fallback.trace?.map((event) => event.type)).toEqual(rejected.trace?.map((event) => event.type));
    expect(JSON.parse(fallback.files[0]!.content).events.map((event: { type: string }) => event.type)).toEqual(["client.launch", "engine.request"]);
  });

  test("summarises a git repository without shipping internals or remote credentials", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-git-"));
    roots.push(root);
    await git(root, "init", "-q");
    await git(root, "remote", "add", "origin", "https://oauth2:ghp_secrettoken123456@github.com/acme/widgets.git");
    await git(root, "remote", "add", "mirror", "git@github.com:acme/widgets-mirror.git");
    await writeFile(join(root, "app.txt"), "line one\n");
    await writeFile(join(root, "credentials.json"), '{"password":"hunter2-committed"}\n');
    await writeFile(join(root, "blob.bin"), Buffer.from([0, 1, 2, 3, 4]));
    await git(root, "add", "-A");
    await git(root, "commit", "-q", "-m", "initial commit by jane@acme-mail.io");
    await writeFile(join(root, "app.txt"), "line one\nline two added\n");
    await writeFile(join(root, "credentials.json"), '{"password":"hunter2-modified"}\n');
    await writeFile(join(root, "blob.bin"), Buffer.from([0, 9, 9, 9, 9, 9]));
    await writeFile(join(root, ".env.local"), "TOKEN=abcdef123456\n");
    await writeFile(join(root, "staged.txt"), "staged content\n");
    await git(root, "add", "staged.txt");
    const head = await git(root, "rev-parse", "HEAD");
    const branch = await git(root, "branch", "--show-current");

    const { uploads, upload } = makeUploads();
    const sessionUploader = new SessionUploader({ upload, fallbackScanMs: 60_000 });
    const sessionId = "session-v2-git-1";
    sessionUploader.startSession(sessionId, "workspace-git", root);
    await sessionUploader.stop();

    const start = uploads.find((item) => item.snapshot_type === "start")!;
    const gitBlock = start.workspace.git as {
      commit: string; branch: string; dirty: boolean; upstream: string | null; ahead: number | null; behind: number | null;
      remotes: Array<{ name: string; url: string }>; recent_commits: Array<{ sha: string; at: string; subject: string }>;
      status: Array<{ code: string; path: string }>; diff: string; diff_truncated: boolean;
    };
    expect(gitBlock.commit).toBe(head);
    expect(gitBlock.branch).toBe(branch);
    expect(gitBlock.dirty).toBe(true);
    expect(gitBlock.upstream).toBeNull();
    expect(gitBlock.ahead).toBeNull();
    expect(gitBlock.behind).toBeNull();
    expect([...gitBlock.remotes].sort((left, right) => left.name.localeCompare(right.name))).toEqual([
      { name: "mirror", url: "github.com:acme/widgets-mirror.git" },
      { name: "origin", url: "https://github.com/acme/widgets.git" },
    ]);
    expect(gitBlock.recent_commits).toHaveLength(1);
    expect(gitBlock.recent_commits[0]).toMatchObject({ sha: head, subject: "initial commit by [REDACTED_PII]" });
    expect(Number.isNaN(Date.parse(gitBlock.recent_commits[0]!.at))).toBe(false);
    const statusPaths = gitBlock.status.map((entry) => entry.path);
    expect(gitBlock.status).toContainEqual({ code: " M", path: "app.txt" });
    expect(gitBlock.status).toContainEqual({ code: "A ", path: "staged.txt" });
    expect(statusPaths).not.toContain("credentials.json");
    expect(statusPaths).not.toContain(".env.local");
    expect(gitBlock.diff).toContain("+line two added");
    expect(gitBlock.diff).toContain("+staged content");
    expect(gitBlock.diff).not.toContain("credentials.json");
    expect(gitBlock.diff).not.toContain("blob.bin");
    expect(gitBlock.diff).not.toContain("Binary files");
    expect(gitBlock.diff_truncated).toBe(false);
    // Capture v2: the binary is listed with its raw digest (its bytes go to the byte-exact archive), never as text.
    expect(start.manifest.filter((entry) => entry.binary !== true).map((entry) => entry.path).sort()).toEqual(["app.txt", "staged.txt"]);
    expect(start.manifest.find((entry) => entry.path === "blob.bin")).toMatchObject({ binary: true, archived: "byte_exact", size: 6 });
    expect(start.files.some((file) => file.path === "blob.bin")).toBe(false);
    const serialized = JSON.stringify(uploads);
    for (const forbidden of ["ghp_secrettoken123456", "oauth2:", "hunter2", "abcdef123456", "jane@acme-mail.io", ".git/"]) {
      expect(serialized).not.toContain(forbidden);
    }
  });

  test("caps the git diff and flags truncation", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-bigdiff-"));
    roots.push(root);
    await git(root, "init", "-q");
    await writeFile(join(root, "big.txt"), "seed\n");
    await git(root, "add", "-A");
    await git(root, "commit", "-q", "-m", "seed");
    const lines: string[] = [];
    for (let index = 0; index < 40_000; index += 1) lines.push(`line ${index} ${"x".repeat(60)}`);
    await writeFile(join(root, "big.txt"), `${lines.join("\n")}\n`);

    const { uploads, upload } = makeUploads();
    const sessionUploader = new SessionUploader({ upload, fallbackScanMs: 60_000 });
    sessionUploader.startSession("session-v2-bigdiff-1", "workspace-bigdiff", root);
    await sessionUploader.stop();

    const gitBlock = uploads[0]!.workspace.git as { diff: string; diff_truncated: boolean };
    expect(gitBlock.diff_truncated).toBe(true);
    expect(Buffer.byteLength(gitBlock.diff)).toBeLessThanOrEqual(MAX_UPLOAD_DIFF_BYTES);
    expect(gitBlock.diff).toContain("+line 0 ");
  });

  test("scopes the git block to a workspace nested inside a larger repository", async () => {
    const repo = await mkdtemp(join(tmpdir(), "omnirush-upload-nested-"));
    roots.push(repo);
    await git(repo, "init", "-q");
    await mkdir(join(repo, "pkg-a"));
    await mkdir(join(repo, "pkg-b"));
    await writeFile(join(repo, "pkg-a", "a.txt"), "a1\n");
    await writeFile(join(repo, "pkg-b", "b.txt"), "b1\n");
    await writeFile(join(repo, ".netrc"), "machine example.com login jane password hunter2-netrc\n");
    await git(repo, "add", "-A");
    await git(repo, "commit", "-q", "-m", "initial");
    await writeFile(join(repo, "pkg-b", "b.txt"), "b1\nOUTSIDE-COMMIT\n");
    await git(repo, "add", "-A");
    await git(repo, "commit", "-q", "-m", "OUTSIDE-COMMIT touches pkg-b only");
    await writeFile(join(repo, "pkg-a", "a.txt"), "a1\na2 INSIDE-CHANGE\n");
    await writeFile(join(repo, "pkg-a", "new.txt"), "untracked\n");
    await writeFile(join(repo, "pkg-b", "b.txt"), "b2 OUTSIDE-CHANGE\n");
    await writeFile(join(repo, ".netrc"), "machine example.com login jane password hunter2-CHANGED\n");
    const head = await git(repo, "rev-parse", "HEAD");

    // A monorepo package: only its own subtree, with workspace-relative paths
    // that line up with the manifest.
    const block = (await collectGitBlock(join(repo, "pkg-a")))!;
    expect(block).not.toBeNull();
    expect(block.commit).toBe(head);
    expect(block.dirty).toBe(true);
    expect([...block.status].sort((left, right) => left.path.localeCompare(right.path))).toEqual([
      { code: " M", path: "a.txt" },
      { code: "??", path: "new.txt" },
    ]);
    expect(block.diff).toContain("diff --git a/a.txt b/a.txt");
    expect(block.diff).toContain("+a2 INSIDE-CHANGE");
    expect(block.recent_commits.map((commit) => commit.subject)).toEqual(["initial"]);
    const serialized = JSON.stringify(block);
    for (const forbidden of ["OUTSIDE", "pkg-a/", "pkg-b", ".netrc", "hunter2"]) {
      expect(serialized).not.toContain(forbidden);
    }

    // A plain project folder under a repository root (a home directory kept
    // in a dotfiles repo): nothing beyond the folder itself is described.
    await mkdir(join(repo, "projects", "foo"), { recursive: true });
    await writeFile(join(repo, "projects", "foo", "notes.txt"), "hello\n");
    const nested = (await collectGitBlock(join(repo, "projects", "foo")))!;
    expect(nested).not.toBeNull();
    expect(nested.diff).toBeNull();
    expect(nested.diff_truncated).toBe(false);
    expect(nested.dirty).toBe(false);
    expect(nested.recent_commits).toEqual([]);
    for (const entry of nested.status) {
      expect(entry.code).toBe("??");
      expect(entry.path.startsWith("notes.txt") || entry.path === "./").toBe(true);
    }
    const nestedSerialized = JSON.stringify(nested);
    for (const forbidden of ["OUTSIDE", "projects", "pkg-", ".netrc", "hunter2"]) {
      expect(nestedSerialized).not.toContain(forbidden);
    }
  });

  test("clamps git metadata to the session uploader's field limits after redaction", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-limits-"));
    roots.push(root);
    await git(root, "init", "-q");
    await git(root, "checkout", "-q", "-b", `feature/${Array.from({ length: 6 }, () => "x".repeat(100)).join("/")}`);
    await git(root, "remote", "add", "origin", `https://example.com/${"r".repeat(2_100)}.git`);
    await writeFile(join(root, "a.txt"), "a\n");
    await git(root, "add", "-A");
    // 980 characters before redaction; every short address becomes the longer
    // [REDACTED_PII] marker, so only the post-redaction length breaks the cap.
    await git(root, "commit", "-q", "-m", "a@b.io ".repeat(140).trim());

    const block = (await collectGitBlock(root))!;
    expect(block).not.toBeNull();
    expect(block.recent_commits).toHaveLength(1);
    const subject = block.recent_commits[0]!.subject;
    expect(subject).not.toContain("a@b.io");
    expect(subject.startsWith("[REDACTED_PII]")).toBe(true);
    expect(Array.from(subject)).toHaveLength(1_024);
    expect(Array.from(block.branch!)).toHaveLength(512);
    expect(block.branch!.startsWith("feature/")).toBe(true);
    expect(block.remotes).toHaveLength(1);
    expect(Array.from(block.remotes[0]!.url)).toHaveLength(2_048);
    expect(block.remotes[0]!.url.startsWith("https://example.com/")).toBe(true);
  });

  test("a turn the user stopped carries outcome aborted on its collector.trigger and turn.completed events", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-aborted-"));
    roots.push(root);
    await writeFile(join(root, "a.txt"), "alpha\n");
    const { uploads, upload } = makeUploads();
    const sessionUploader = new SessionUploader({ upload, changeDebounceMs: 60_000, fallbackScanMs: 60_000 });
    const sessionId = "session-v2-aborted-1";
    sessionUploader.startSession(sessionId, "workspace-aborted", root);
    sessionUploader.captureSnapshot(sessionId, "prompt");
    await sessionUploader.idle(sessionId);
    await writeFile(join(root, "a.txt"), "alpha, half written\n");
    sessionUploader.captureSnapshot(sessionId, "turn_completed", "aborted");
    sessionUploader.flushTrace(sessionId, { messages: [], outcome: "aborted" });
    await sessionUploader.idle(sessionId);
    sessionUploader.captureSnapshot(sessionId, "prompt");
    sessionUploader.captureSnapshot(sessionId, "turn_completed");
    await sessionUploader.idle(sessionId);
    sessionUploader.flushTrace(sessionId);
    await sessionUploader.stop();
    const events = uploads.filter((item) => item.snapshot_type === "trace").flatMap((item) => item.trace ?? []);
    expect(events.filter((event) => event.type === "collector.trigger").map((event) => event.data)).toEqual([
      { trigger: "prompt", captured: false },
      { trigger: "turn_completed", captured: true, outcome: "aborted" },
      { trigger: "prompt", captured: false },
      { trigger: "turn_completed", captured: false },
    ]);
    expect(events.filter((event) => event.type === "turn.completed").map((event) => event.data)).toEqual([{ messages: [], outcome: "aborted" }]);
    // The snapshot itself keeps the trigger every backend takes.
    expect(uploads.filter((item) => item.snapshot_type === "change").map((item) => item.trigger)).toEqual(["turn_completed"]);
  });

  test("captures prompt and turn_completed snapshots only when the workspace changed", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-triggers-"));
    roots.push(root);
    await writeFile(join(root, "a.txt"), "alpha\n");
    await writeFile(join(root, "b.txt"), "beta\n");
    const { uploads, upload } = makeUploads();
    const sessionUploader = new SessionUploader({ upload, changeDebounceMs: 60_000, fallbackScanMs: 60_000 });
    const sessionId = "session-v2-triggers-1";
    sessionUploader.startSession(sessionId, "workspace-triggers", root);
    sessionUploader.captureSnapshot(sessionId, "prompt");
    await sessionUploader.idle(sessionId);
    expect(uploads.map((item) => item.snapshot_type)).toEqual(["start"]);

    await writeFile(join(root, "a.txt"), "alpha changed\n");
    sessionUploader.captureSnapshot(sessionId, "turn_completed");
    await sessionUploader.idle(sessionId);
    expect(uploads.map((item) => [item.snapshot_type, item.trigger])).toEqual([["start", "session_start"], ["change", "turn_completed"]]);
    const change = uploads[1]!;
    const changedPaths = change.files.map((file) => file.path).filter((path) => !path.startsWith("__omnirush__/"));
    expect(changedPaths).toEqual(["a.txt"]);
    expect(change.files.find((file) => file.path === "a.txt")?.sha256).toBe(sha256("alpha changed\n"));
    expect(change.manifest.map((entry) => entry.path).sort()).toEqual(["a.txt", "b.txt"]);
    expect(change.manifest.find((entry) => entry.path === "a.txt")?.sha256).toBe(sha256("alpha changed\n"));
    expect(change.manifest.find((entry) => entry.path === "b.txt")?.sha256).toBe(sha256("beta\n"));

    sessionUploader.captureSnapshot(sessionId, "prompt");
    await sessionUploader.idle(sessionId);
    sessionUploader.flushTrace(sessionId);
    await sessionUploader.stop();
    const triggers = uploads
      .filter((item) => item.snapshot_type === "trace")
      .flatMap((item) => item.trace ?? [])
      .filter((event) => event.type === "collector.trigger")
      .map((event) => event.data);
    expect(triggers).toEqual([
      { trigger: "prompt", captured: false },
      { trigger: "turn_completed", captured: true },
      { trigger: "prompt", captured: false },
    ]);
    const end = uploads.find((item) => item.snapshot_type === "end")!;
    expect(end.files.map((file) => file.path).filter((path) => !path.startsWith("__omnirush__/"))).toEqual([]);
  });
});

describe("session uploader durable retry", () => {
  test("spools failed uploads to disk with a failure ledger and delivers them once the gateway recovers", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-spool-"));
    const stateDir = await mkdtemp(join(tmpdir(), "omnirush-upload-spool-state-"));
    roots.push(root, stateDir);
    await writeFile(join(root, "app.txt"), "hello\n");
    const uploads: Envelope[] = [];
    let healthy = false;
    const warnings: string[] = [];
    const sessionUploader = new SessionUploader({
      stateDir,
      upload: async (_sessionId, compressed) => {
        if (!healthy) return Response.json({ error: "unavailable" }, { status: 503 });
        uploads.push(withTraceEvents(JSON.parse(zstdDecompressSync(compressed).toString("utf8"))) as Envelope);
        return Response.json({ ok: true }, { status: 201 });
      },
      log: (level, message) => { if (level === "warn") warnings.push(message); },
      fallbackScanMs: 60_000,
      uploadRetryDelayMs: 1,
      retryBaseMs: 60_000,
    });
    const sessionId = "session-spool-1234";
    sessionUploader.startSession(sessionId, "workspace-spool", root);
    await sessionUploader.idle(sessionId);

    expect(uploads).toHaveLength(0);
    expect(await sessionUploader.spoolStatus()).toMatchObject({ entries: 1 });
    expect(warnings).toContain("OmniRush session upload artifact spooled for retry");
    const spoolDir = join(stateDir, "omnirush-upload-spool");
    const names = (await readdir(spoolDir)).sort();
    expect(names.some((name) => name.endsWith(".json"))).toBe(true);
    expect(names.some((name) => name.endsWith(".zst"))).toBe(true);
    if (process.platform !== "win32") {
      for (const name of names) expect((await stat(join(spoolDir, name))).mode & 0o777).toBe(0o600);
      expect((await stat(spoolDir)).mode & 0o777).toBe(0o700);
    }
    const ledger = JSON.parse(await readFile(join(stateDir, "omnirush-upload-sessions.json"), "utf8")) as { sessions: Record<string, Record<string, unknown>> };
    expect(ledger.sessions[sessionId]).toMatchObject({ failureCount: 1, nextSequence: 1 });
    expect(typeof ledger.sessions[sessionId]?.lastFailureAt).toBe("string");
    expect(await sessionUploader.sessionDeliveryStatus(sessionId)).toMatchObject({ failureCount: 1, lastSuccessAt: null });

    healthy = true;
    expect(await sessionUploader.drainSpool()).toEqual({ delivered: 1, pending: 0 });
    expect(uploads.map((item) => [item.snapshot_type, item.trigger, item.sequence])).toEqual([["start", "session_start", 1]]);
    expect(await sessionUploader.spoolStatus()).toEqual({ entries: 0, bytes: 0 });
    await sessionUploader.stop();
    expect(uploads.map((item) => [item.snapshot_type, item.sequence])).toEqual([["start", 1], ["end", 2]]);
    expect(await sessionUploader.spoolStatus()).toEqual({ entries: 0, bytes: 0 });
    const settled = JSON.parse(await readFile(join(stateDir, "omnirush-upload-sessions.json"), "utf8")) as { sessions: Record<string, Record<string, unknown>> };
    expect(typeof settled.sessions[sessionId]?.lastSuccessAt).toBe("string");
    expect(settled.sessions[sessionId]).toMatchObject({ failureCount: 1 });
  });

  test("retries spooled uploads with backoff on the next session uploader start", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-respool-"));
    const stateDir = await mkdtemp(join(tmpdir(), "omnirush-upload-respool-state-"));
    roots.push(root, stateDir);
    await writeFile(join(root, "app.txt"), "hello\n");
    const sessionId = "session-respool-1234";
    const first = new SessionUploader({
      stateDir,
      upload: async () => { throw new Error("network down"); },
      fallbackScanMs: 60_000,
      uploadRetryDelayMs: 1,
      retryBaseMs: 60_000,
    });
    first.startSession(sessionId, "workspace-respool", root);
    await first.stop();
    expect(await first.spoolStatus()).toMatchObject({ entries: 2 });

    const { uploads, upload } = makeUploads();
    const second = new SessionUploader({ stateDir, upload, fallbackScanMs: 60_000, retryBaseMs: 10, retryMaxMs: 20 });
    for (let attempt = 0; attempt < 100 && uploads.length < 2; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    expect(uploads.map((item) => [item.snapshot_type, item.trigger, item.sequence])).toEqual([["start", "session_start", 1], ["end", "session_end", 2]]);
    expect(await second.spoolStatus()).toEqual({ entries: 0, bytes: 0 });
    await second.stop();
  });

  test("a 507 on the end upload is spooled after one attempt, and the next start sends it", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-507-"));
    const stateDir = await mkdtemp(join(tmpdir(), "omnirush-upload-507-state-"));
    roots.push(root, stateDir);
    await writeFile(join(root, "app.txt"), "hello\n");
    const sessionId = "session-507-1234";
    const sent: string[] = [];
    const first = new SessionUploader({
      stateDir,
      upload: async (_sessionId, compressed) => {
        const envelope = withTraceEvents(JSON.parse(zstdDecompressSync(compressed).toString("utf8"))) as Envelope;
        sent.push(String(envelope.snapshot_type));
        // The server's disk filled up before the session ended.
        return envelope.snapshot_type === "end" ? Response.json({ detail: "insufficient storage" }, { status: 507 }) : Response.json({ ok: true }, { status: 201 });
      },
      fallbackScanMs: 60_000,
      uploadRetryDelayMs: 1,
      retryBaseMs: 60_000,
    });
    first.startSession(sessionId, "workspace-507", root);
    await first.idle(sessionId);
    await first.stop();
    expect(sent.filter((type) => type === "end")).toHaveLength(1);
    const spoolDir = join(stateDir, "omnirush-upload-spool");
    const metas = await Promise.all((await readdir(spoolDir)).filter((name) => name.endsWith(".json"))
      .map(async (name) => JSON.parse(await readFile(join(spoolDir, name), "utf8")) as { snapshot_type: string }));
    expect(metas.map((meta) => meta.snapshot_type)).toEqual(["end"]);

    const { uploads, upload } = makeUploads();
    const second = new SessionUploader({ stateDir, upload, fallbackScanMs: 60_000, retryBaseMs: 10, retryMaxMs: 20 });
    for (let attempt = 0; attempt < 200 && uploads.length < 1; attempt += 1) await new Promise((resolve) => setTimeout(resolve, 10));
    expect(uploads.map((item) => [item.snapshot_type, item.trigger])).toEqual([["end", "session_end"]]);
    expect(await second.spoolStatus()).toEqual({ entries: 0, bytes: 0 });
    await second.stop();
  });

  test("a 413 or 429 with Retry-After is spooled and not sent before it; a plain 413 or a 501 is final", async () => {
    expect(retryAfterMs("30", 0)).toBe(30_000);
    expect(retryAfterMs("Thu, 01 Jan 1970 00:01:00 GMT", 0)).toBe(60_000);
    expect(retryAfterMs("later", 0)).toBeNull();
    expect([507, 599, 501, 505].map((status) => isRetryableUploadStatus(status))).toEqual([true, true, false, false]);
    expect([isRetryableUploadStatus(413), isRetryableUploadStatus(413, 1_000)]).toEqual([false, true]);
    for (const [status, headers, spooled] of [[413, { "Retry-After": "3600" }, true], [429, { "Retry-After": "3600" }, true], [413, {}, false], [501, {}, false]] as const) {
      const root = await mkdtemp(join(tmpdir(), "omnirush-upload-ra-"));
      const stateDir = await mkdtemp(join(tmpdir(), "omnirush-upload-ra-state-"));
      roots.push(root, stateDir);
      await writeFile(join(root, "app.txt"), "hello\n");
      let calls = 0;
      let healthy = false;
      const uploader = new SessionUploader({
        stateDir,
        upload: async () => {
          calls += 1;
          return healthy ? Response.json({ ok: true }, { status: 201 }) : Response.json({ detail: "busy" }, { status, headers });
        },
        fallbackScanMs: 60_000,
        uploadRetryDelayMs: 1,
        retryBaseMs: 60_000,
      });
      uploader.startSession("session-ra-1234", "workspace-ra", root);
      await uploader.idle("session-ra-1234");
      expect({ status, calls }).toEqual({ status, calls: 1 });
      expect({ status, entries: (await uploader.spoolStatus()).entries }).toEqual({ status, entries: spooled ? 1 : 0 });
      healthy = true;
      // Not before the Retry-After: the drain leaves it.
      if (spooled) expect(await uploader.drainSpool()).toEqual({ delivered: 0, pending: 1 });
      expect(calls).toBe(1);
      await uploader.clearSpool();
      await uploader.stop();
    }
  }, 20_000);

  test("bounds the spool, drops permanently rejected uploads and clears on request", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-spoolcap-"));
    const stateDir = await mkdtemp(join(tmpdir(), "omnirush-upload-spoolcap-state-"));
    roots.push(root, stateDir);
    await writeFile(join(root, "app.txt"), "v0\n");
    let status = 503;
    const sessionUploader = new SessionUploader({
      stateDir,
      upload: async () => Response.json({ error: "nope" }, { status }),
      fallbackScanMs: 60_000,
      changeDebounceMs: 60_000,
      uploadRetryDelayMs: 1,
      retryBaseMs: 60_000,
      spoolMaxEntries: 2,
    });
    const sessionId = "session-spoolcap-1234";
    sessionUploader.startSession(sessionId, "workspace-spoolcap", root);
    await sessionUploader.idle(sessionId);
    for (let version = 1; version <= 3; version += 1) {
      await writeFile(join(root, "app.txt"), `v${version}\n`);
      sessionUploader.captureSnapshot(sessionId, "turn_completed");
      await sessionUploader.idle(sessionId);
    }
    expect(await sessionUploader.spoolStatus()).toMatchObject({ entries: 2 });
    const spoolDir = join(stateDir, "omnirush-upload-spool");
    const sequences = (await Promise.all((await readdir(spoolDir)).filter((name) => name.endsWith(".json"))
      .map(async (name) => (JSON.parse(await readFile(join(spoolDir, name), "utf8")) as { sequence: number }).sequence))).sort();
    expect(sequences).toEqual([3, 4]);

    status = 400;
    await writeFile(join(root, "app.txt"), "v4\n");
    sessionUploader.captureSnapshot(sessionId, "turn_completed");
    await sessionUploader.idle(sessionId);
    expect(await sessionUploader.spoolStatus()).toMatchObject({ entries: 2 });
    expect(await sessionUploader.sessionDeliveryStatus(sessionId)).toMatchObject({ failureCount: 5 });

    await sessionUploader.clearSpool();
    expect(await sessionUploader.spoolStatus()).toEqual({ entries: 0, bytes: 0 });
    await sessionUploader.stop();
  });
});

describe("session upload deadline and spool drain", () => {
  // Upload deadlines at 1/100 of real time: one simulated second is 10 ms.
  const hundredth: SessionUploadBudget = {
    baseMs: SESSION_UPLOAD_BUDGET.baseMs / 100,
    bytesPerSecond: SESSION_UPLOAD_BUDGET.bytesPerSecond * 100,
    maxSendMs: SESSION_UPLOAD_BUDGET.maxSendMs / 100,
    responseMs: SESSION_UPLOAD_BUDGET.responseMs / 100,
  };
  const simulatedSeconds = (seconds: number) => seconds * 10;
  const sleep = (ms: number, signal?: AbortSignal) => new Promise<void>((resolvePromise, reject) => {
    const timer = setTimeout(resolvePromise, ms);
    signal?.addEventListener("abort", () => {
      clearTimeout(timer);
      reject(signal.reason);
    }, { once: true });
  });

  /** Writes one spool entry as a failed upload leaves it; ids sort in `index` order. */
  async function spoolEntry(stateDir: string, index: number, bytes: number, extra: Record<string, unknown> = {}): Promise<string> {
    const spoolDir = join(stateDir, "omnirush-upload-spool");
    await mkdir(spoolDir, { recursive: true, mode: 0o700 });
    const id = `${index.toString(16).padStart(12, "0")}-${index.toString(16).padStart(6, "0")}-0000000${index}`;
    const body = Buffer.alloc(bytes, index);
    await writeFile(join(spoolDir, `${id}.zst`), body, { mode: 0o600 });
    await writeFile(join(spoolDir, `${id}.json`), JSON.stringify({
      id,
      session_id: `session-drain-${index}`,
      snapshot_type: index === 1 ? "start" : "change",
      trigger: index === 1 ? "session_start" : "turn_completed",
      sequence: index,
      bytes,
      created_at: new Date().toISOString(),
      attempts: 1,
      ...extra,
    }), { mode: 0o600 });
    return id;
  }

  async function spoolMeta(stateDir: string, id: string): Promise<{ attempts: number; last_attempt_at?: string }> {
    return JSON.parse(await readFile(join(stateDir, "omnirush-upload-spool", `${id}.json`), "utf8")) as { attempts: number; last_attempt_at?: string };
  }

  async function drainState(): Promise<string> {
    const stateDir = await mkdtemp(join(tmpdir(), "omnirush-upload-drain-state-"));
    roots.push(stateDir);
    return stateDir;
  }

  test("scales the deadline with the envelope and adds the wait for the gateway's answer", () => {
    expect(sessionUploadTimeoutMs(0)).toBe(150_000);
    // A 10 MiB start snapshot: 30 s, 80 s of body at 128 KiB/s, 120 s for the answer.
    expect(sessionUploadTimeoutMs(10 * 1024 * 1024)).toBe(230_000);
    expect(sessionUploadTimeoutMs(10 * 1024 * 1024)).toBeGreaterThan(60_000 + 90_000);
    expect(sessionUploadTimeoutMs(1024 * 1024 * 1024)).toBe(15 * 60_000 + 120_000);
    expect(sessionUploadTimeoutMs(10 * 1024 * 1024, hundredth)).toBe(2_300);
  });

  test("delivers a 10 MB envelope over an uplink that needs 60 s for it on the first attempt", async () => {
    const stateDir = await drainState();
    await spoolEntry(stateDir, 1, 10 * 1024 * 1024);
    const calls: { bytes: number; aborted: boolean }[] = [];
    const sessionUploader = new SessionUploader({
      stateDir,
      upload: async (_sessionId, compressed, signal) => {
        // Throttled: the body trickles out over 60 s (about 170 KiB/s).
        await sleep(simulatedSeconds(60), signal);
        calls.push({ bytes: compressed.byteLength, aborted: signal?.aborted ?? true });
        return Response.json({ ok: true }, { status: 201 });
      },
      uploadBudget: hundredth,
      retryBaseMs: 60_000,
    });
    expect(await sessionUploader.drainSpool()).toEqual({ delivered: 1, pending: 0 });
    expect(calls).toEqual([{ bytes: 10 * 1024 * 1024, aborted: false }]);
    expect(await sessionUploader.spoolStatus()).toEqual({ entries: 0, bytes: 0 });
    await sessionUploader.stop();
  });

  test("waits for an answer that comes 90 s after the body is sent", async () => {
    const stateDir = await drainState();
    await spoolEntry(stateDir, 1, 6 * 1024 * 1024);
    const answered: boolean[] = [];
    const sessionUploader = new SessionUploader({
      stateDir,
      gatewayUrl: "https://gateway.example.test/v1",
      accessToken: "device-token",
      fetch: async (_input: string, init?: RequestInit) => {
        const signal = init?.signal ?? undefined;
        await sleep(simulatedSeconds(20), signal);
        // Body sent; the gateway scrubs the envelope before it answers.
        await sleep(simulatedSeconds(90), signal);
        answered.push(signal?.aborted ?? true);
        return Response.json({ ok: true }, { status: 201 });
      },
      uploadBudget: hundredth,
      retryBaseMs: 60_000,
    });
    expect(await sessionUploader.drainSpool()).toEqual({ delivered: 1, pending: 0 });
    expect(answered).toEqual([false]);
    await sessionUploader.stop();
  });

  test("delivers the entries behind a spooled upload that keeps failing, and backs that one off", async () => {
    const stateDir = await drainState();
    const stuck = await spoolEntry(stateDir, 1, 4_096);
    await spoolEntry(stateDir, 2, 1_024);
    await spoolEntry(stateDir, 3, 1_024);
    const attempts: number[] = [];
    const delivered: number[] = [];
    const sessionUploader = new SessionUploader({
      stateDir,
      upload: async (sessionId) => {
        const index = Number(sessionId.split("-").at(-1));
        attempts.push(index);
        // The first entry never gets an answer, even past its deadline.
        if (index === 1) return new Promise<Response>(() => undefined);
        delivered.push(index);
        return Response.json({ ok: true }, { status: 201 });
      },
      uploadBudget: { baseMs: 50, bytesPerSecond: 128 * 1024 * 1000, maxSendMs: 900, responseMs: 100 },
      retryBaseMs: 60_000,
    });

    expect(await sessionUploader.drainSpool()).toEqual({ delivered: 2, pending: 1 });
    expect(attempts).toEqual([1, 2, 3]);
    expect(delivered).toEqual([2, 3]);
    const failed = await spoolMeta(stateDir, stuck);
    expect(failed.attempts).toBe(2);
    expect(typeof failed.last_attempt_at).toBe("string");

    // Within its backoff the failed entry is left alone.
    expect(await sessionUploader.drainSpool()).toEqual({ delivered: 0, pending: 1 });
    expect(attempts).toEqual([1, 2, 3]);

    // Once the backoff (the retry base after one failed drain) has passed, it is tried again...
    const spoolDir = join(stateDir, "omnirush-upload-spool");
    await writeFile(join(spoolDir, `${stuck}.json`), JSON.stringify({ ...failed, last_attempt_at: new Date(Date.now() - 61_000).toISOString() }));
    expect(await sessionUploader.drainSpool()).toEqual({ delivered: 0, pending: 1 });
    expect(attempts).toEqual([1, 2, 3, 1]);
    const again = await spoolMeta(stateDir, stuck);
    expect(again.attempts).toBe(3);

    // ...and the next backoff is twice as long.
    await writeFile(join(spoolDir, `${stuck}.json`), JSON.stringify({ ...again, last_attempt_at: new Date(Date.now() - 90_000).toISOString() }));
    expect(await sessionUploader.drainSpool()).toEqual({ delivered: 0, pending: 1 });
    expect(attempts).toEqual([1, 2, 3, 1]);
    await sessionUploader.stop();
  });

  test("stops a drain after three failures and leaves the rest to the next one", async () => {
    const stateDir = await drainState();
    for (let index = 1; index <= 5; index += 1) await spoolEntry(stateDir, index, 512);
    const attempts: string[] = [];
    const sessionUploader = new SessionUploader({
      stateDir,
      upload: async (sessionId) => {
        attempts.push(sessionId);
        return Response.json({ error: "unavailable" }, { status: 503 });
      },
      retryBaseMs: 60_000,
    });
    expect(await sessionUploader.drainSpool()).toEqual({ delivered: 0, pending: 5 });
    expect(attempts).toEqual(["session-drain-1", "session-drain-2", "session-drain-3"]);
    await sessionUploader.stop();
  });

  test("a long outage keeps every entry however many attempts fail; only age drops one", async () => {
    const stateDir = await drainState();
    // 85 min of 503s used to drop an entry at its 24th attempt; it is kept now.
    await spoolEntry(stateDir, 1, 512, { attempts: 400 });
    await spoolEntry(stateDir, 2, 512, { created_at: new Date(Date.now() - 2 * 60 * 60_000).toISOString() });
    const warnings: string[] = [];
    const sessionUploader = new SessionUploader({
      stateDir,
      upload: async () => Response.json({ error: "unavailable" }, { status: 503 }),
      log: (level, message, attributes) => { if (level === "warn") warnings.push(`${message}:${String(attributes?.reason ?? "")}`); },
      retryBaseMs: 60_000,
      // A short age limit stands in for the 7 days.
      spoolMaxAgeMs: 60 * 60_000,
    });
    expect(await sessionUploader.drainSpool()).toEqual({ delivered: 0, pending: 1 });
    expect(warnings).toEqual(["OmniRush session upload artifact dropped from spool:expired"]);
    expect(await sessionUploader.spoolStatus()).toEqual({ entries: 1, bytes: 512 });
    await sessionUploader.stop();
  });

  test("the default age limit is fourteen days (an account that signed out gets them after its next sign-in)", () => {
    expect(MAX_SPOOL_AGE_MS).toBe(14 * 24 * 60 * 60_000);
  });

  test("a non-retryable answer still drops the entry", async () => {
    const stateDir = await drainState();
    await spoolEntry(stateDir, 1, 512);
    const sessionUploader = new SessionUploader({
      stateDir,
      upload: async () => Response.json({ detail: "idempotency_key_reused" }, { status: 409 }),
      retryBaseMs: 60_000,
    });
    expect(await sessionUploader.drainSpool()).toEqual({ delivered: 0, pending: 0 });
    expect(await sessionUploader.spoolStatus()).toEqual({ entries: 0, bytes: 0 });
    await sessionUploader.stop();
  });

  test("traces have their own spool budget: a large snapshot never pushes one out", async () => {
    const stateDir = await drainState();
    await spoolEntry(stateDir, 1, 600, { snapshot_type: "trace", trigger: "trace_flush" });
    await spoolEntry(stateDir, 2, 600, { snapshot_type: "trace", trigger: "trace_flush" });
    await spoolEntry(stateDir, 3, 600);
    const sessionUploader = new SessionUploader({
      stateDir,
      upload: async () => Response.json({ error: "unavailable" }, { status: 503 }),
      retryBaseMs: 60_000,
      spoolMaxBytes: 1_000,
      spoolMaxTraceBytes: 1_000,
    });
    const uploads = sessionUploader as unknown as { enforceSpoolBounds(): Promise<void> };
    await uploads.enforceSpoolBounds();
    // The oldest trace went for the trace budget; the snapshot did not touch either trace.
    const left = (await readdir(join(stateDir, "omnirush-upload-spool"))).filter((name) => name.endsWith(".json")).sort();
    expect(left.map((name) => name.slice(-6, -5))).toEqual(["2", "3"]);
    await sessionUploader.stop();
  });

  test("the spool is kept at start without an account and drained for that account once it is back", async () => {
    const stateDir = await drainState();
    await spoolEntry(stateDir, 1, 512, { account_id: "acct-a" });
    await spoolEntry(stateDir, 2, 512, { account_id: "acct-b" });
    await spoolEntry(stateDir, 3, 512);
    // Signed out by a refused refresh: nothing uploads, and nothing is deleted.
    const signedOut = new SessionUploader({ stateDir, retryBaseMs: 60_000 });
    expect(signedOut.enabled).toBe(false);
    await signedOut.stop();
    expect(await signedOut.spoolStatus()).toEqual({ entries: 3, bytes: 1_536 });
    const sent: string[] = [];
    const sessionUploader = new SessionUploader({
      stateDir,
      upload: async (sessionId) => {
        sent.push(sessionId);
        return Response.json({}, { status: 201 });
      },
      accountId: async () => "acct-a",
      retryBaseMs: 60_000,
    });
    // Account A's own entry and the unstamped one go out; account B's stays for B.
    expect(await sessionUploader.drainSpool()).toEqual({ delivered: 2, pending: 0 });
    expect(sent.sort()).toEqual(["session-drain-1", "session-drain-3"]);
    expect(await sessionUploader.spoolStatus()).toEqual({ entries: 1, bytes: 512 });
    await sessionUploader.stop();
  });

  test("a sign-out keeps the spool: unstamped entries take the signed-out account, another account never sends them, the same account does", async () => {
    const stateDir = await drainState();
    await spoolEntry(stateDir, 1, 512);
    await spoolEntry(stateDir, 2, 512, { account_id: "acct-b" });
    const leaving = new SessionUploader({ stateDir, retryBaseMs: 60_000, accountId: async () => "acct-a" });
    await leaving.keepSpoolFor("acct-a");
    expect(await leaving.spoolStatus()).toEqual({ entries: 2, bytes: 1_024 });
    await leaving.stop();
    const sentBy = (account: string) => {
      const sent: string[] = [];
      const uploader = new SessionUploader({
        stateDir,
        upload: async (sessionId) => {
          sent.push(sessionId);
          return Response.json({}, { status: 201 });
        },
        accountId: async () => account,
        retryBaseMs: 60_000,
      });
      return { uploader, sent };
    };
    const other = sentBy("acct-c");
    expect(await other.uploader.drainSpool()).toEqual({ delivered: 0, pending: 0 });
    expect(other.sent).toEqual([]);
    await other.uploader.stop();
    const same = sentBy("acct-a");
    expect(await same.uploader.drainSpool()).toEqual({ delivered: 1, pending: 0 });
    expect(same.sent).toEqual(["session-drain-1"]);
    await same.uploader.stop();
    // Never learned whose they were: stamped with an account nobody has.
    const unknown = await drainState();
    await spoolEntry(unknown, 3, 512);
    const signedOut = new SessionUploader({ stateDir: unknown, retryBaseMs: 60_000 });
    await signedOut.keepSpoolFor(null);
    await signedOut.stop();
    const anyone = new SessionUploader({ stateDir: unknown, upload: async () => Response.json({}, { status: 201 }), accountId: async () => "acct-a", retryBaseMs: 60_000 });
    expect(await anyone.drainSpool()).toEqual({ delivered: 0, pending: 0 });
    await anyone.stop();
  });

  test("while the account cannot be learned only this process's own entries go out", async () => {
    const stateDir = await drainState();
    await spoolEntry(stateDir, 1, 512);
    const sent: string[] = [];
    const sessionUploader = new SessionUploader({
      stateDir,
      upload: async (sessionId) => {
        sent.push(sessionId);
        return Response.json({}, { status: 201 });
      },
      accountId: async () => null,
      retryBaseMs: 60_000,
    });
    expect(await sessionUploader.drainSpool()).toEqual({ delivered: 0, pending: 1 });
    expect(sent).toEqual([]);
    await sessionUploader.stop();
  });

  test("a spooled entry is re-sent with its Idempotency-Key and checked against the stored body hash", async () => {
    const stateDir = await drainState();
    const body = Buffer.alloc(512, 1);
    const digest = createHash("sha256").update(body).digest("hex");
    const key = uploadIdempotencyKey("session-drain-1", 2, 1, "start");
    await spoolEntry(stateDir, 1, 512, { idempotency_key: key, body_sha256: digest });
    const keys: Array<string | undefined> = [];
    let answers = 0;
    const sessionUploader = new SessionUploader({
      capabilities: async () => ({ schema_versions: [1, 2], canonical_trace: false, idempotency_key: true, integrity: true, integrity_summary: true }),
      stateDir,
      upload: async (_sessionId, _compressed, _signal, request) => {
        keys.push(request?.idempotencyKey);
        answers += 1;
        // The first answer names other bytes: the envelope is sent again.
        return Response.json({ body_sha256: answers === 1 ? "0".repeat(64) : digest }, { status: 201 });
      },
      retryBaseMs: 60_000,
    });
    expect(await sessionUploader.drainSpool()).toEqual({ delivered: 1, pending: 0 });
    expect(keys).toEqual([key, key]);
    await sessionUploader.stop();
  });

  test("the Idempotency-Key is the sha256 of session, segment, sequence and type joined by newlines", () => {
    expect(uploadIdempotencyKey("ses_abc12345", 2, 7, "trace")).toBe(createHash("sha256").update("ses_abc12345\n2\n7\ntrace").digest("hex"));
    expect(uploadIdempotencyKey("ses_abc12345", 2, 7, "trace")).toMatch(/^[0-9a-f]{64}$/);
  });

  test("a sign-out aborts the spooled upload in flight and empties the spool", async () => {
    const stateDir = await drainState();
    await spoolEntry(stateDir, 1, 1_024);
    let started!: () => void;
    const inFlight = new Promise<void>((resolvePromise) => { started = resolvePromise; });
    let aborted = false;
    const sessionUploader = new SessionUploader({
      stateDir,
      upload: (_sessionId, _compressed, signal) => new Promise<Response>((_resolvePromise, reject) => {
        signal?.addEventListener("abort", () => {
          aborted = true;
          reject(signal.reason);
        }, { once: true });
        started();
      }),
      retryBaseMs: 60_000,
    });
    const drain = sessionUploader.drainSpool();
    await inFlight;
    await sessionUploader.clearSpool();
    expect(aborted).toBe(true);
    expect(await drain).toEqual({ delivered: 0, pending: 1 });
    expect(await sessionUploader.spoolStatus()).toEqual({ entries: 0, bytes: 0 });
    await sessionUploader.stop();
  });

  test("a sign-out aborts the live upload in flight and spools nothing it carried", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-signout-"));
    roots.push(root);
    const stateDir = await drainState();
    await writeFile(join(root, "app.txt"), "hello\n");
    let started!: () => void;
    const inFlight = new Promise<void>((resolvePromise) => { started = resolvePromise; });
    const signals: AbortSignal[] = [];
    const infos: string[] = [];
    const sessionUploader = new SessionUploader({
      stateDir,
      upload: async (_sessionId, _compressed, signal) => {
        signals.push(signal!);
        started();
        // Fails 200 ms in, cancelled or not: a slow uplink that drops.
        await new Promise((resolvePromise) => setTimeout(resolvePromise, 200));
        throw new Error("network down");
      },
      log: (level, message) => { if (level === "info") infos.push(message); },
      fallbackScanMs: 60_000,
      uploadRetryDelayMs: 1,
      retryBaseMs: 60_000,
    });
    const sessionId = "session-signout-1234";
    sessionUploader.startSession(sessionId, "workspace-signout", root);
    await inFlight;
    await sessionUploader.clearSpool();
    await sessionUploader.idle(sessionId);

    expect(signals).toHaveLength(1);
    expect(signals[0]!.aborted).toBe(true);
    expect(infos).toContain("OmniRush session upload artifact discarded at sign-out");
    expect(await sessionUploader.spoolStatus()).toEqual({ entries: 0, bytes: 0 });
    expect(await readdir(join(stateDir, "omnirush-upload-spool")).catch(() => [])).toEqual([]);

    // The next account's uploads are not cancelled by the earlier sign-out.
    const next = "session-signout-5678";
    sessionUploader.startSession(next, "workspace-signout-next", root);
    await sessionUploader.idle(next);
    expect(signals.length).toBeGreaterThan(1);
    expect(signals.slice(1).every((signal) => !signal.aborted)).toBe(true);
    expect(await sessionUploader.spoolStatus()).toMatchObject({ entries: 1 });
    await sessionUploader.clearSpool();
    await sessionUploader.stop();
  });

  test("spools a live upload once an attempt runs out its deadline, and still retries quick failures in band", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-deadline-live-"));
    roots.push(root);
    const stateDir = await drainState();
    await writeFile(join(root, "app.txt"), "v0\n");
    // What the gateway does with each call, in order; "drop" once the plan runs out.
    const plan: Array<"hang" | "drop" | "timeout"> = [];
    const calls: string[] = [];
    const spooled: unknown[] = [];
    const sessionUploader = new SessionUploader({
      stateDir,
      upload: async () => {
        const step = plan.shift() ?? "drop";
        calls.push(step);
        // No answer ever, and the hook ignores its signal: only the deadline ends the attempt.
        if (step === "hang") return new Promise<Response>(() => undefined);
        // The gateway broker's own deadline, reported by name across the worker boundary.
        if (step === "timeout") throw new DOMException("The operation timed out.", "TimeoutError");
        throw new Error("network down");
      },
      log: (level, message, attributes) => {
        if (level === "warn" && message === "OmniRush session upload artifact spooled for retry") spooled.push(attributes?.reason);
      },
      uploadBudget: { baseMs: 50, bytesPerSecond: 128 * 1024 * 1000, maxSendMs: 900, responseMs: 100 },
      fallbackScanMs: 60_000,
      changeDebounceMs: 60_000,
      uploadRetryDelayMs: 1,
      retryBaseMs: 60_000,
    });
    const sessionId = "session-deadline-live-1";

    // The start snapshot's first attempt runs out its deadline: spooled, not tried twice more in band.
    plan.push("hang");
    sessionUploader.startSession(sessionId, "workspace-deadline-live", root);
    await sessionUploader.idle(sessionId);
    expect(calls).toEqual(["hang"]);
    expect(spooled).toHaveLength(1);
    expect(await sessionUploader.spoolStatus()).toMatchObject({ entries: 1 });

    // The session's queue moved on to its next snapshot, whose quick failures keep their in-band retries.
    plan.push("drop", "drop", "drop");
    await writeFile(join(root, "app.txt"), "v1\n");
    sessionUploader.captureSnapshot(sessionId, "turn_completed");
    await sessionUploader.idle(sessionId);
    expect(calls).toEqual(["hang", "drop", "drop", "drop"]);
    expect(await sessionUploader.spoolStatus()).toMatchObject({ entries: 2 });

    // A quick failure, then an attempt out of time: no third attempt.
    plan.push("drop", "timeout");
    await writeFile(join(root, "app.txt"), "v2\n");
    sessionUploader.captureSnapshot(sessionId, "turn_completed");
    await sessionUploader.idle(sessionId);
    expect(calls).toEqual(["hang", "drop", "drop", "drop", "drop", "timeout"]);
    expect(spooled.slice(1)).toEqual(["network down", "The operation timed out."]);
    expect(await sessionUploader.spoolStatus()).toMatchObject({ entries: 3 });
    await sessionUploader.clearSpool();
    await sessionUploader.stop();
  });

  test("a stop mid-drain leaves the spooled entry in flight as it was", async () => {
    const stateDir = await drainState();
    const id = await spoolEntry(stateDir, 1, 1_024, { attempts: 3, last_attempt_at: new Date(Date.now() - 60 * 60_000).toISOString() });
    const before = await spoolMeta(stateDir, id);
    let started!: () => void;
    const inFlight = new Promise<void>((resolvePromise) => { started = resolvePromise; });
    const sessionUploader = new SessionUploader({
      stateDir,
      // Never answers and ignores its signal: the stop ends it all the same.
      upload: () => {
        started();
        return new Promise<Response>(() => undefined);
      },
      retryBaseMs: 60_000,
    });
    const drain = sessionUploader.drainSpool();
    await inFlight;
    await sessionUploader.stop();
    expect(await drain).toEqual({ delivered: 0, pending: 1 });
    expect(await spoolMeta(stateDir, id)).toEqual(before);
    expect(before).toMatchObject({ attempts: 3, last_attempt_at: expect.any(String) });
    expect(await sessionUploader.spoolStatus()).toEqual({ entries: 1, bytes: 1_024 });
  });

  test("an entry dated in the future (the clock went back) waits one backoff, not until then", async () => {
    const stateDir = await drainState();
    await spoolEntry(stateDir, 1, 256, { attempts: 2, last_attempt_at: new Date(Date.now() + 30 * 24 * 60 * 60_000).toISOString() });
    let calls = 0;
    const sessionUploader = new SessionUploader({
      stateDir,
      upload: async () => {
        calls += 1;
        return new Response(null, { status: calls === 1 ? 503 : 201 });
      },
      retryBaseMs: 20,
      retryMaxMs: 80,
    });
    // Due at once: the first try fails and records a sane last attempt.
    expect(await sessionUploader.drainSpool()).toEqual({ delivered: 0, pending: 1 });
    const deadline = Date.now() + 2_000;
    while ((await sessionUploader.spoolStatus()).entries > 0 && Date.now() < deadline) {
      await new Promise((resolvePromise) => setTimeout(resolvePromise, 20));
    }
    expect(await sessionUploader.spoolStatus()).toEqual({ entries: 0, bytes: 0 });
    // Retried on the capped schedule: a handful of calls, no 1 ms loop.
    expect(calls).toBeGreaterThanOrEqual(1);
    expect(calls).toBeLessThanOrEqual(4);
    await sessionUploader.stop();
  });

  test("a drain asked for while one runs picks up the entries spooled meanwhile", async () => {
    const stateDir = await drainState();
    await spoolEntry(stateDir, 1, 512);
    let release!: () => void;
    const held = new Promise<void>((resolvePromise) => { release = resolvePromise; });
    let started!: () => void;
    const inFlight = new Promise<void>((resolvePromise) => { started = resolvePromise; });
    const delivered: string[] = [];
    const sessionUploader = new SessionUploader({
      stateDir,
      upload: async (sessionId) => {
        if (sessionId === "session-drain-1") {
          started();
          await held;
        }
        delivered.push(sessionId);
        return Response.json({ ok: true }, { status: 201 });
      },
      retryBaseMs: 60_000,
    });
    const running = sessionUploader.drainSpool();
    await inFlight;
    // Spooled after the running drain listed the spool.
    await spoolEntry(stateDir, 2, 512);
    const next = sessionUploader.drainSpool();
    // Every call during the run shares the one drain after it.
    expect(sessionUploader.drainSpool()).toBe(next);
    release();
    expect(await running).toEqual({ delivered: 1, pending: 0 });
    expect(await next).toEqual({ delivered: 1, pending: 0 });
    expect(delivered).toEqual(["session-drain-1", "session-drain-2"]);
    expect(await sessionUploader.spoolStatus()).toEqual({ entries: 0, bytes: 0 });
    await sessionUploader.stop();
  });
});

describe("session uploader git helpers", () => {
  test("clamps text by code points without splitting surrogate pairs", () => {
    expect(clampUploadText("abc", 5)).toBe("abc");
    expect(clampUploadText("abcdef", 3)).toBe("abc");
    const faces = "\u{1F600}".repeat(4);
    expect(clampUploadText(faces, 4)).toBe(faces);
    expect(clampUploadText(faces, 3)).toBe("\u{1F600}".repeat(3));
    expect(Array.from(clampUploadText("y".repeat(2_000), 1_024))).toHaveLength(1_024);
  });

  test("strips userinfo from scheme and scp-like remotes", () => {
    expect(stripRemoteUserinfo("https://user:pass@example.com/org/repo.git")).toBe("https://example.com/org/repo.git");
    expect(stripRemoteUserinfo("ssh://git@example.com:2222/org/repo.git")).toBe("ssh://example.com:2222/org/repo.git");
    expect(stripRemoteUserinfo("git@example.com:org/repo.git")).toBe("example.com:org/repo.git");
    expect(stripRemoteUserinfo("https://example.com/org/repo.git")).toBe("https://example.com/org/repo.git");
    expect(stripRemoteUserinfo("/srv/git/repo.git")).toBe("/srv/git/repo.git");
  });

  test("parses plain and quoted diff headers", () => {
    expect(diffHeaderPath("diff --git a/src/app.ts b/src/app.ts")).toBe("src/app.ts");
    expect(diffHeaderPath("diff --git a/with space.txt b/with space.txt")).toBe("with space.txt");
    expect(diffHeaderPath('diff --git "a/caf\\303\\251 \\"x\\".txt" "b/caf\\303\\251 \\"x\\".txt"')).toBe('café "x".txt');
    expect(diffHeaderPath("diff --git a/one.txt b/two.txt")).toBeNull();
    expect(diffHeaderPath("not a header")).toBeNull();
  });

  test("filters denied and binary diff sections and redacts the rest", () => {
    const raw = [
      "diff --git a/app.ts b/app.ts",
      "--- a/app.ts",
      "+++ b/app.ts",
      "@@ -1 +1 @@",
      "-const key = 'old';",
      "+const key = 'sk-1234567890abcdefghijklmnop';",
      "diff --git a/.env b/.env",
      "--- a/.env",
      "+++ b/.env",
      "@@ -1 +1 @@",
      "+PASSWORD=super-secret-value",
      "diff --git a/blob.bin b/blob.bin",
      "Binary files a/blob.bin and b/blob.bin differ",
      "diff --git a/keys/service.json b/keys/service.json",
      "+{\"private\":true}",
      "",
    ].join("\n");
    const result = filterUploadDiff(raw);
    expect(result.truncated).toBe(false);
    expect(result.diff).toContain("diff --git a/app.ts b/app.ts");
    expect(result.diff).toContain("[REDACTED]");
    expect(result.diff).not.toContain("sk-1234567890abcdefghijklmnop");
    expect(result.diff).not.toContain(".env");
    expect(result.diff).not.toContain("super-secret-value");
    expect(result.diff).not.toContain("blob.bin");
    expect(result.diff).not.toContain("keys/service.json");
    expect(filterUploadDiff("")).toEqual({ diff: null, truncated: false });
    expect(filterUploadDiff("diff --git a/x b/x\n+ok\n", true).truncated).toBe(true);
  });
});

// --- session uploader trace additions (contract v2) --------------------------------

function traceEvents(uploads: Envelope[]): Array<{ type: string; data?: Record<string, unknown> }> {
  return uploads.filter((item) => item.snapshot_type === "trace").flatMap((item) => item.trace ?? []);
}

describe("session uploader trace additions", () => {
  test("raises the caps to the contract values", () => {
    expect(MAX_UPLOAD_FILE_BYTES).toBe(4 * 1024 * 1024);
    expect(MAX_UPLOAD_DIFF_BYTES).toBe(2 * 1024 * 1024);
    expect(MAX_UPLOAD_FILES).toBe(50_000);
    expect(MAX_UPLOAD_WEB_VISIT_TEXT_BYTES).toBe(64 * 1024);
    expect(MAX_UPLOAD_ATTACHMENT_TEXT_BYTES).toBe(256 * 1024);
  });

  test("keeps uploading every snapshot of a session that has already sent more than 512 MiB", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-nocap-"));
    const stateDir = await mkdtemp(join(tmpdir(), "omnirush-upload-nocap-state-"));
    roots.push(root, stateDir);
    await writeFile(join(root, "app.txt"), "v0\n");
    const sessionId = "session-nocap-1234";
    // The session ledger stands in for the running total of a long session:
    // it says 600 MiB were already accepted (past the 512 MiB per-session cap
    // the session uploader used to stop at) without any of that data being written.
    const sentBefore = 600 * 1024 * 1024;
    await writeFile(join(stateDir, "omnirush-upload-sessions.json"), JSON.stringify({
      version: 1,
      sessions: { [sessionId]: { segment: 1, nextSequence: 40, sentBytes: sentBefore, lastSeenAt: new Date().toISOString() } },
    }));
    const { uploads, upload } = makeUploads();
    const sessionUploader = new SessionUploader({ stateDir, upload, changeDebounceMs: 60_000, fallbackScanMs: 60_000 });
    sessionUploader.startSession(sessionId, "workspace-nocap", root);
    await sessionUploader.idle(sessionId);
    await writeFile(join(root, "app.txt"), "v1\n");
    sessionUploader.captureSnapshot(sessionId, "turn_completed");
    await sessionUploader.idle(sessionId);
    sessionUploader.recordTrace(sessionId, "file.read", { path: "app.txt" });
    sessionUploader.flushTrace(sessionId);
    await sessionUploader.stop();

    // Sequence 41 onwards: the seeded total was loaded, and nothing was held back.
    expect(uploads.map((item) => [item.snapshot_type, item.trigger, item.sequence])).toEqual([
      ["start", "resume", 41],
      ["change", "turn_completed", 42],
      ["trace", "trace_flush", 43],
      ["end", "session_end", 44],
    ]);
    expect(uploads[0]!.files.find((file) => file.path === "app.txt")?.content).toBe("v0\n");
    expect(uploads[1]!.files.find((file) => file.path === "app.txt")?.content).toBe("v1\n");
    expect(traceEvents(uploads).some((event) => event.type === "file.read")).toBe(true);
    for (const envelope of uploads) expect(envelope.privacy).not.toHaveProperty("max_session_bytes");
    const metadata = JSON.parse(uploads[0]!.files.find((file) => file.path === "__omnirush__/workspace.json")!.content) as Record<string, unknown>;
    expect(metadata).not.toHaveProperty("max_session_bytes");
    // The running total is still counted, for diagnostics only.
    const ledger = JSON.parse(await readFile(join(stateDir, "omnirush-upload-sessions.json"), "utf8")) as { sessions: Record<string, { sentBytes: number }> };
    expect(ledger.sessions[sessionId]!.sentBytes).toBeGreaterThan(sentBefore);
  });

  test("records the turn model and child sessions with checkpoints that survive a resume", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-children-"));
    const stateDir = await mkdtemp(join(tmpdir(), "omnirush-upload-children-state-"));
    roots.push(root, stateDir);
    await writeFile(join(root, "app.txt"), "hello\n");
    const { uploads, upload } = makeUploads();
    const makeUploader = () => new SessionUploader({ stateDir, upload, fallbackScanMs: 60_000 });
    const sessionId = "session-children-1234";

    const first = makeUploader();
    first.startSession(sessionId, "workspace-children", root);
    await first.idle(sessionId);
    expect(uploads.map((item) => item.snapshot_type)).toEqual(["start"]);
    expect(uploads[0]!.session).toEqual({ provider_id: null, model_id: null, variant: null, child_session_ids: [] });
    first.recordSessionModel(sessionId, { provider_id: "anthropic", model_id: "claude-sonnet-4-5", variant: "high", agent: "build" });
    first.recordChildSession(sessionId, {
      childSessionId: "ses_child_1",
      parentSessionId: sessionId,
      title: "Subtask",
      agent: "explore",
      messages: [{ info: { id: "cmsg_1", role: "user", sessionID: "ses_child_1" }, parts: [{ type: "text", text: "find jane@acme-mail.io" }] }],
      lastMessageId: "cmsg_1",
    });
    first.recordChildSession(sessionId, {
      childSessionId: "ses_grandchild_1",
      parentSessionId: "ses_child_1",
      title: null,
      agent: null,
      messages: [],
      lastMessageId: null,
    });
    first.flushTrace(sessionId);
    await first.idle(sessionId);
    expect(await first.childCheckpoints(sessionId)).toEqual({ ses_child_1: "cmsg_1" });
    expect(await first.childSessionIds(sessionId)).toEqual(["ses_child_1", "ses_grandchild_1"]);
    await first.stop();

    expect(uploads.map((item) => item.snapshot_type)).toEqual(["start", "trace", "end"]);
    const events = traceEvents(uploads);
    expect(events.find((event) => event.type === "session.model")?.data).toEqual({
      provider_id: "anthropic", model_id: "claude-sonnet-4-5", variant: "high", agent: "build",
    });
    const children = events.filter((event) => event.type === "session.child");
    expect(children.map((event) => [event.data?.child_session_id, event.data?.parent_session_id, event.data?.title, event.data?.agent])).toEqual([
      ["ses_child_1", sessionId, "Subtask", "explore"],
      ["ses_grandchild_1", "ses_child_1", null, null],
    ]);
    expect(JSON.stringify(children[0]?.data?.messages)).toContain("cmsg_1");
    expect(JSON.stringify(children)).not.toContain("jane@acme-mail.io");
    const end = uploads.at(-1)!;
    expect(end.session).toEqual({
      provider_id: "anthropic", model_id: "claude-sonnet-4-5", variant: "high", child_session_ids: ["ses_child_1", "ses_grandchild_1"],
    });

    // A resumed session starts from the persisted checkpoints and reports the
    // last known model and children on its very first upload.
    const second = makeUploader();
    second.startSession(sessionId, "workspace-children", root);
    await second.idle(sessionId);
    expect(await second.childCheckpoints(sessionId)).toEqual({ ses_child_1: "cmsg_1" });
    expect(await second.childSessionIds(sessionId)).toEqual(["ses_child_1", "ses_grandchild_1"]);
    const resumedStart = uploads.find((item) => item.snapshot_type === "start" && item.session_segment === 2)!;
    expect(resumedStart.session).toEqual({
      provider_id: "anthropic", model_id: "claude-sonnet-4-5", variant: "high", child_session_ids: ["ses_child_1", "ses_grandchild_1"],
    });
    await second.stop();
  });

  test("child ids noted while the turn runs are listed at once, deduped, and kept across a restart without a transcript event", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-child-ids-"));
    const stateDir = await mkdtemp(join(tmpdir(), "omnirush-upload-child-ids-state-"));
    roots.push(root, stateDir);
    await writeFile(join(root, "app.txt"), "hello\n");
    const { uploads, upload } = makeUploads();
    const makeUploader = () => new SessionUploader({ stateDir, upload, fallbackScanMs: 60_000 });
    const sessionId = "session-child-ids-1234";

    const first = makeUploader();
    first.startSession(sessionId, "workspace-child-ids", root);
    await first.idle(sessionId);
    expect(first.noteChildSessionIds(sessionId, ["ses_child_1", "ses_grandchild_1"])).toBe(2);
    expect(first.noteChildSessionIds(sessionId, ["ses_child_1", sessionId, "bad id!", "ses_child_2"])).toBe(1);
    expect(first.noteChildSessionIds("session-unknown", ["ses_child_9"])).toBe(0);
    expect(await first.childSessionIds(sessionId)).toEqual(["ses_child_1", "ses_grandchild_1", "ses_child_2"]);
    // The next envelope (here a trace flush) lists them.
    first.recordTrace(sessionId, "session.idle", { status: "busy" });
    first.flushTrace(sessionId);
    await first.idle(sessionId);
    expect(uploads.at(-1)!.session).toMatchObject({ child_session_ids: ["ses_child_1", "ses_grandchild_1", "ses_child_2"] });
    // Ids only: the transcripts still come when the turn settles.
    expect(traceEvents(uploads).filter((event) => event.type === "session.child")).toEqual([]);
    // The app quits before the turn settles: the next start still lists them.
    await first.stop();
    const second = makeUploader();
    second.startSession(sessionId, "workspace-child-ids", root);
    await second.idle(sessionId);
    const resumedStart = uploads.find((item) => item.snapshot_type === "start" && item.session_segment === 2)!;
    expect(resumedStart.session).toMatchObject({ child_session_ids: ["ses_child_1", "ses_grandchild_1", "ses_child_2"] });
    await second.stop();
  });

  test("sub-agents on their own models keep them; a gateway fallback records the model that really answered", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-subagent-model-"));
    roots.push(root);
    await writeFile(join(root, "app.txt"), "hello\n");
    const { uploads, upload } = makeUploads();
    const sessionUploader = new SessionUploader({ upload, fallbackScanMs: 60_000 });
    const sessionId = "session-subagent-model-1";
    sessionUploader.startSession(sessionId, "workspace-subagent-model", root);
    await sessionUploader.idle(sessionId);
    sessionUploader.recordSessionModel(sessionId, { provider_id: "omnirush", model_id: "gpt-6-astra", variant: "max", agent: "omnirush" });
    const assistant = (id: string, session: string, modelID: string, variant: string, completed: number) => ({
      info: { id, role: "assistant", sessionID: session, providerID: "omnirush", modelID, variant, agent: "general", time: { created: completed - 10, completed } },
      parts: [{ type: "text", text: `answer ${id}` }],
    });
    // The gateway refused GPT 6 Sol for ses_sol at t=2000; ses_muse ran on Muse all along.
    sessionUploader.recordTrace(sessionId, "subagent.model_fallback", {
      kind: "gateway", child_session_id: "ses_sol", requested_model: "gpt-6-sol", used_model: "gpt-6-astra", used_effort: "high", reason: "model_unavailable", ok: true, at: 2_000,
    });
    sessionUploader.recordTrace(sessionId, "subagent.model_fallback", {
      kind: "selection", child_session_id: "ses_other", requested_model: "meta-muse-spark", used_model: "gpt-6-astra", reason: "not_in_catalog", at: 2_000,
    });
    sessionUploader.recordChildSession(sessionId, {
      childSessionId: "ses_muse", parentSessionId: sessionId, depth: 1, title: "Muse task", agent: "general",
      messages: [assistant("m1", "ses_muse", "meta-muse-spark", "xhigh", 5_000)], lastMessageId: "m1",
    });
    sessionUploader.recordChildSession(sessionId, {
      childSessionId: "ses_sol", parentSessionId: sessionId, depth: 1, title: "Sol task", agent: "general",
      messages: [assistant("s1", "ses_sol", "gpt-6-sol", "high", 1_000), assistant("s2", "ses_sol", "gpt-6-sol", "high", 3_000)], lastMessageId: "s2",
    });
    sessionUploader.flushTrace(sessionId);
    await sessionUploader.stop();

    const events = traceEvents(uploads);
    const child = (id: string) => events.find((event) => event.type === "session.child" && event.data?.child_session_id === id)?.data?.messages as Array<{ info: Record<string, unknown> }>;
    expect(child("ses_muse").map((message) => [message.info.modelID, message.info.variant])).toEqual([["meta-muse-spark", "xhigh"]]);
    expect(child("ses_sol").map((message) => [message.info.modelID, message.info.variant, message.info.omnirushModelFallback ?? null])).toEqual([
      ["gpt-6-sol", "high", null],
      ["gpt-6-astra", "high", { requested: "gpt-6-sol", requestedVariant: "high", reason: "gateway_refused" }],
    ]);
    expect(events.filter((event) => event.type === "subagent.model_fallback").map((event) => event.data?.kind)).toEqual(["gateway", "selection"]);
    // The main session's model is the main agent's own.
    expect(uploads.at(-1)!.session).toMatchObject({ provider_id: "omnirush", model_id: "gpt-6-astra", variant: "max" });
  });

  test("keeps only the newest 5,000 events across every push site", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-cap-"));
    roots.push(root);
    await writeFile(join(root, "app.txt"), "hello\n");
    const { uploads, upload } = makeUploads();
    const sessionUploader = new SessionUploader({ upload, fallbackScanMs: 60_000 });
    const sessionId = "session-cap-1234";
    sessionUploader.startSession(sessionId, "workspace-cap", root);
    await sessionUploader.idle(sessionId);
    expect(MAX_UPLOAD_TRACE_EVENTS).toBe(5_000);
    // Fill the trace, then push one event through each of the newer sites:
    // every one of them displaces the oldest event instead of growing the trace.
    for (let index = 0; index < MAX_UPLOAD_TRACE_EVENTS; index += 1) sessionUploader.recordTrace(sessionId, "filler", { index });
    sessionUploader.recordSessionModel(sessionId, { provider_id: "anthropic", model_id: "claude-sonnet-4-5", variant: null, agent: null });
    sessionUploader.recordChildSession(sessionId, { childSessionId: "ses_child_cap", parentSessionId: sessionId, title: null, agent: null, messages: [], lastMessageId: null });
    expect(sessionUploader.recordWebVisit(sessionId, { url: "https://example.com/page", title: "Page", text: "text" })).toBe(true);
    sessionUploader.recordAttachment(sessionId, { name: "note.txt", mime: "text/plain", bytes: 4, sha256: "0".repeat(64), text: "note", textTruncated: false });
    sessionUploader.flushTrace(sessionId);
    await sessionUploader.stop();

    const events = traceEvents(uploads);
    expect(events).toHaveLength(MAX_UPLOAD_TRACE_EVENTS);
    expect(events.slice(-4).map((event) => event.type)).toEqual(["session.model", "session.child", "web.visit", "attachment"]);
    // The four oldest filler events (indices 0-3) were dropped; the newest filler survives.
    expect(events[0]?.data).toEqual({ index: 4 });
    expect(events.filter((event) => event.type === "filler")).toHaveLength(MAX_UPLOAD_TRACE_EVENTS - 4);
  }, 20_000);

  test("traces browser visits with redacted, capped text and never local pages", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-web-"));
    roots.push(root);
    const { uploads, upload } = makeUploads();
    const sessionUploader = new SessionUploader({ upload, fallbackScanMs: 60_000 });
    const sessionId = "session-web-1234";
    sessionUploader.startSession(sessionId, "workspace-web", root);
    const text = `Contact jane@acme-mail.io about AKIA1234567890123456 ${"page text ".repeat(20_000)}`;
    expect(sessionUploader.recordWebVisit(sessionId, { url: "https://user:pw@example.com/docs?q=1#top", title: "Docs jane@acme-mail.io", text })).toBe(true);
    expect(sessionUploader.recordWebVisit(sessionId, { url: "https://example.org/short", title: null, text: "brief" })).toBe(true);
    for (const url of ["file:///etc/passwd", "data:text/html,<p>hi</p>", "chrome://settings", "http://localhost:3000/app", "http://127.0.0.1:8080/", "https://[::1]/", "ftp://example.com/x"]) {
      expect(sessionUploader.recordWebVisit(sessionId, { url, title: "local", text: "secret local page" })).toBe(false);
    }
    sessionUploader.flushTrace(sessionId);
    await sessionUploader.stop();

    const visits = traceEvents(uploads).filter((event) => event.type === "web.visit");
    expect(visits).toHaveLength(2);
    const [long, short] = visits;
    expect(long?.data?.url).toBe("https://example.com/docs?q=1#top");
    expect(long?.data?.title).toBe("Docs [REDACTED_PII]");
    expect(long?.data?.text_truncated).toBe(true);
    expect(Buffer.byteLength(String(long?.data?.text))).toBeLessThanOrEqual(MAX_UPLOAD_WEB_VISIT_TEXT_BYTES);
    expect(String(long?.data?.text)).not.toContain("jane@acme-mail.io");
    expect(String(long?.data?.text)).not.toContain("AKIA1234567890123456");
    expect(short?.data).toEqual({ url: "https://example.org/short", title: null, text: "brief", text_truncated: false });
    expect(JSON.stringify(uploads)).not.toContain("secret local page");
    expect(JSON.stringify(uploads)).not.toContain("user:pw@");
  });

  test("traces prompt attachments with redacted, capped text", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-attachments-"));
    roots.push(root);
    const { uploads, upload } = makeUploads();
    const sessionUploader = new SessionUploader({ upload, fallbackScanMs: 60_000 });
    const sessionId = "session-attachment-1234";
    sessionUploader.startSession(sessionId, "workspace-attachment", root);
    const text = `OPENAI_API_KEY=sk-1234567890abcdefghijklmnop\n${"notes ".repeat(60_000)}`;
    sessionUploader.recordAttachment(sessionId, { name: "../notes jane@acme-mail.io report.txt", mime: "text/plain", bytes: Buffer.byteLength(text), sha256: sha256(text), text });
    sessionUploader.recordAttachment(sessionId, { name: "photo.png", mime: "image/png", bytes: 12, sha256: sha256("png"), text: null });
    sessionUploader.flushTrace(sessionId);
    await sessionUploader.stop();

    const attachments = traceEvents(uploads).filter((event) => event.type === "attachment");
    expect(attachments).toHaveLength(2);
    const [note, photo] = attachments;
    expect(note?.data?.name).toBe("notes [REDACTED_PII] report.txt");
    expect(note?.data?.mime).toBe("text/plain");
    expect(note?.data?.bytes).toBe(Buffer.byteLength(text));
    expect(note?.data?.sha256).toBe(sha256(text));
    expect(note?.data?.text_truncated).toBe(true);
    expect(Buffer.byteLength(String(note?.data?.text))).toBeLessThanOrEqual(MAX_UPLOAD_ATTACHMENT_TEXT_BYTES);
    expect(String(note?.data?.text)).not.toContain("sk-1234567890abcdefghijklmnop");
    expect(String(note?.data?.text)).toContain("[REDACTED]");
    expect(photo?.data).toEqual({ name: "photo.png", mime: "image/png", bytes: 12, sha256: sha256("png"), text: null, text_truncated: false });
  });

  test("emits artifact events for untracked outputs a turn creates or modifies, gitignored ones outside the regenerable folders too", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-artifacts-"));
    roots.push(root);
    await git(root, "init", "-q");
    await writeFile(join(root, ".gitignore"), "ignored/\nnode_modules/\n");
    await writeFile(join(root, "tracked.txt"), "tracked\n");
    await writeFile(join(root, "stale.txt"), "already there\n");
    await git(root, "add", ".gitignore", "tracked.txt");
    await git(root, "commit", "-q", "-m", "init");
    const { uploads, upload } = makeUploads();
    const sessionUploader = new SessionUploader({ upload, changeDebounceMs: 60_000, fallbackScanMs: 60_000 });
    const sessionId = "session-artifacts-1234";
    sessionUploader.startSession(sessionId, "workspace-artifacts", root);
    sessionUploader.captureSnapshot(sessionId, "prompt");
    await sessionUploader.idle(sessionId);

    await new Promise((resolve) => setTimeout(resolve, 20));
    await writeFile(join(root, "tracked.txt"), "tracked, edited\n");
    await mkdir(join(root, "out"));
    await writeFile(join(root, "out", "report.bin"), Buffer.from([0, 1, 2, 3, 255]));
    await writeFile(join(root, "notes.md"), "generated notes\n");
    await mkdir(join(root, "ignored"));
    await writeFile(join(root, "ignored", "cache.txt"), "ignored output\n");
    await mkdir(join(root, "node_modules", "dep"), { recursive: true });
    await writeFile(join(root, "node_modules", "dep", "index.js"), "module.exports = 1;\n");
    sessionUploader.captureSnapshot(sessionId, "turn_completed");
    await sessionUploader.idle(sessionId);
    sessionUploader.flushTrace(sessionId);
    await sessionUploader.stop();

    const artifacts = traceEvents(uploads).filter((event) => event.type === "artifact").map((event) => event.data);
    expect(artifacts.map((artifact) => artifact?.path).sort()).toEqual(["ignored/cache.txt", "notes.md", "out/report.bin"]);
    expect(artifacts.find((artifact) => artifact?.path === "ignored/cache.txt")).toEqual({ path: "ignored/cache.txt", sha256: sha256("ignored output\n"), bytes: 15 });
    expect(artifacts.find((artifact) => artifact?.path === "out/report.bin")).toEqual({
      path: "out/report.bin",
      sha256: createHash("sha256").update(Buffer.from([0, 1, 2, 3, 255])).digest("hex"),
      bytes: 5,
    });
    expect(artifacts.find((artifact) => artifact?.path === "notes.md")).toEqual({ path: "notes.md", sha256: sha256("generated notes\n"), bytes: 16 });
    expect(JSON.stringify(uploads)).not.toContain("ignored output");
    const change = uploads.find((item) => item.snapshot_type === "change" && item.trigger === "turn_completed");
    expect(change?.files.map((file) => file.path)).toContain("tracked.txt");
    expect(change?.touched_paths).toEqual(expect.arrayContaining(["notes.md", "out/report.bin"]));
  });

  test("clamps by bytes without splitting code points and classifies web urls", () => {
    expect(clampUploadBytes("abc", 10)).toEqual({ text: "abc", truncated: false });
    expect(clampUploadBytes("a😀b", 4)).toEqual({ text: "a", truncated: true });
    expect(clampUploadBytes("a😀b", 5)).toEqual({ text: "a😀", truncated: true });
    expect(isUploadableWebUrl("https://example.com/")).toBe(true);
    expect(isUploadableWebUrl("http://example.com:8080/path")).toBe(true);
    for (const url of ["file:///tmp/a", "data:text/plain,a", "chrome://version", "about:blank", "http://localhost/", "http://app.localhost/", "http://127.0.0.1/", "http://[::1]/", "not a url"]) {
      expect(isUploadableWebUrl(url)).toBe(false);
    }
  });
});

// --- session uploader secret rails --------------------------------------------------

const AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
// Token samples are assembled at runtime so the source never contains a
// contiguous token shape (GitHub push protection scans committed blobs).
const sample = (prefix: string, ...rest: string[]) => prefix + rest.join("");
const GITHUB_TOKEN = sample("ghp_", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123");

describe("session uploader secret rails", () => {
  test("drops the incident file by name and counts it in the privacy manifest", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-incident-"));
    roots.push(root);
    await git(root, "init", "-q");
    await writeFile(join(root, "AWS master key"), `aws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = ${AWS_SECRET}\n`);
    await writeFile(join(root, "app.ts"), "export const ok = true;\n");
    const { uploads, upload } = makeUploads();
    const sessionUploader = new SessionUploader({ upload, fallbackScanMs: 60_000 });
    const sessionId = "session-incident-1";
    sessionUploader.startSession(sessionId, "workspace-incident", root);
    sessionUploader.recordTrace(sessionId, "file.read", { path: "AWS master key" });
    await sessionUploader.stop();

    const start = uploads.find((item) => item.snapshot_type === "start")!;
    expect(start.files.map((file) => file.path).sort()).toEqual(["__omnirush__/workspace.json", "app.ts"]);
    expect(start.manifest.map((entry) => entry.path)).toEqual(["app.ts"]);
    expect(start.privacy.denied_file_count).toBe(1);
    expect(start.files.find((file) => file.path === "__omnirush__/workspace.json")?.content).toContain('"denied_file_count":1');
    // The denied name never reaches the snapshot, manifest or touched paths
    // (the raw tool argument in the trace event is the agent's own input).
    for (const envelope of uploads) {
      expect(envelope.touched_paths).toEqual([]);
      expect(envelope.files.map((file) => file.path)).not.toContain("AWS master key");
      expect(envelope.manifest.map((entry) => entry.path)).not.toContain("AWS master key");
    }
    const serialized = JSON.stringify(uploads);
    expect(serialized).not.toContain(AWS_SECRET);
    expect(serialized).not.toContain("AKIAIOSFODNN7EXAMPLE");
  });

  test("denies credential-named paths unless they carry a source or docs extension", () => {
    for (const path of [
      "AWS master key", "tokens/prod.csv", "backup/wallet.dat", "my-wallet", "seed.csv", "kubeconfig", "id_rsa.pub", "notes/passwords",
      ".aws/config", ".gnupg/pubring.kbx", ".docker/config.json", "team/mnemonic", "prod secret", "api_key", ".netrc", "passwd",
    ]) {
      expect(isUploadPathDenied(path)).toBe(true);
    }
    for (const path of [
      "src/token/refresh.ts", "design-tokens/colors.ts", "prisma/seed/users.ts", "seed.sql", "password-reset.tsx", "keys.md",
      "AWS master key.txt", "kubeconfig.yaml", "keyboard.ts", "hotkey.json", ".docker/daemon.json", "src/app.ts",
    ]) {
      expect(isUploadPathDenied(path)).toBe(false);
    }
    // The pre-existing rules stay stricter than the extension carve-out.
    for (const path of ["credentials.json", "secrets.ts", "secrets/config.yml", "keys/service.json", "server.key", ".env.production", "private-key.md"]) {
      expect(isUploadPathDenied(path)).toBe(true);
    }
  });

  test("redacts every secret-named assignment form once and leaves obvious non-secrets alone", () => {
    const secrets: Array<[string, string]> = [
      [`aws_secret_access_key = ${AWS_SECRET}`, "aws_secret_access_key = [REDACTED]"],
      ["password: hunter2hunter2", "password: [REDACTED]"],
      ["client_secret: 'abcdefghijkl'", "client_secret: '[REDACTED]'"],
      ['"token": "abcdefghijkl"', '"token": "[REDACTED]"'],
      ['{"apiKey":"abcdefghijkl","x":1}', '{"apiKey":"[REDACTED]","x":1}'],
      ["DB_PASSWD=hunter2abc", "DB_PASSWD=[REDACTED]"],
      ['export API_KEY="abcdefghijkl"', 'export API_KEY="[REDACTED]"'],
      ["mysql --password=hunter2abc -u root", "mysql --password=[REDACTED] -u root"],
      ['const apiKey = "abcdefghijkl";', 'const apiKey = "[REDACTED]";'],
      ["PRIVATE_KEY = abcdefghijkl", "PRIVATE_KEY = [REDACTED]"],
      ["access_key: abcdefghijkl", "access_key: [REDACTED]"],
      ["pwd=abcdefghijkl", "pwd=[REDACTED]"],
      ["auth: abcdefghijkl", "auth: [REDACTED]"],
      ["credentials = abcdefghijkl", "credentials = [REDACTED]"],
      ["session_key: abcdefghijkl", "session_key: [REDACTED]"],
      ["signing_key = abcdefghijkl", "signing_key = [REDACTED]"],
      ["masterKey: abcdefghijkl", "masterKey: [REDACTED]"],
      ["encryption_key = abcdefghijkl", "encryption_key = [REDACTED]"],
      ["apikey: abcdefghijkl", "apikey: [REDACTED]"],
      ["githubToken = abcdefghijkl", "githubToken = [REDACTED]"],
      ["db.password: abcdefghijkl,", "db.password: [REDACTED],"],
      ["  - password=abc12345 # note", "  - password=[REDACTED] # note"],
      ["auth_token = abcdefgh1234", "auth_token = [REDACTED]"],
      ["basic-auth: abcdefghijkl", "basic-auth: [REDACTED]"],
      ["AUTH=abcdefghijkl", "AUTH=[REDACTED]"],
      ["authorization: abcdefghijkl", "authorization: [REDACTED]"],
      ["oauth_client_secret = abcdefghijkl", "oauth_client_secret = [REDACTED]"],
      ["HTTPSecret = abcdefghijkl", "HTTPSecret = [REDACTED]"],
      ["APIKey: abcdefghijkl", "APIKey: [REDACTED]"],
      ["accessKey: abcdefghijkl", "accessKey: [REDACTED]"],
      ["token2 = abcdefghijkl", "token2 = [REDACTED]"],
    ];
    for (const [input, expected] of secrets) {
      expect(redactUploadText(input)).toEqual({ text: expected, count: 1 });
    }
    const preserved = [
      "token_length = abcdefghij", "token_ttl = abcdefghij", "auth_seconds = abcdefghij", "token_count = abcdefghij",
      "secret_size = abcdefghij", "token_url = https://example.com/oauth/token", "secret_path = /var/run/secrets/x",
      "secret_name = github-token-secret", "session_id = abcdefghij12", "auth_header = X-Auth-Token", "api-key-name: primary-key",
      "token = getToken()", "password = process.env.PASSWORD", 'secret = os.environ["X"]', "token = env.TOKEN",
      "password: ${PASSWORD}", "token=$(cat token.txt)", "password = abc123", "token: short", "auth: 12345678",
      "const password = passwordInput.value.trim()", "token: true",
      // Keyword families match whole key segments, never a substring of an ordinary word.
      "author: Johnathan", "authors = Johnathan", "authored_by: Johnathan", "oauth_client_id = abcdefghijkl",
      "tokenizer_class = BertTokenizer", "tokenize: whitespace", "keyboard_layout = qwerty-intl", "keywords = abcdefghijkl",
      "pwdir = /home/user/project", "accessKeyId = abcdefghijkl", 'eos_token: "<|endoftext|>"',
    ];
    for (const input of preserved) expect(redactUploadText(input)).toEqual({ text: input, count: 0 });
  });

  test("leaves a real package.json and a tokenizer config byte-identical", () => {
    const packageJson = [
      "{",
      '  "name": "@acme/widgets",',
      '  "version": "1.2.3",',
      '  "description": "Token helpers for the Acme auth flow",',
      '  "author": "sindresorhus",',
      '  "keywords": ["token", "auth", "password", "keyboard"],',
      '  "scripts": { "test": "bun test", "tokenize": "node scripts/tokenize.js" },',
      '  "dependencies": { "jsonwebtoken": "^9.0.2", "keyboardjs": "2.7.0" },',
      '  "authorship": "community-maintained"',
      "}",
      "",
    ].join("\n");
    expect(redactUploadContent("package.json", packageJson)).toBe(packageJson);
    expect(redactUploadText(packageJson)).toEqual({ text: packageJson, count: 0 });
    const tokenizerConfig = '{"tokenizer_class": "LlamaTokenizer", "bos_token": "<s>", "eos_token": "<|endoftext|>", "add_bos_token": true, "model_max_length": 4096, "clean_up_tokenization_spaces": false}';
    expect(redactUploadContent("tokenizer_config.json", tokenizerConfig)).toBe(tokenizerConfig);
    expect(redactUploadText(tokenizerConfig)).toEqual({ text: tokenizerConfig, count: 0 });
    expect(redactUploadText("tokenizer_class = LlamaTokenizer\nauth_token = abcdefgh1234\n"))
      .toEqual({ text: "tokenizer_class = LlamaTokenizer\nauth_token = [REDACTED]\n", count: 1 });
  });

  test("redacts provider token shapes", () => {
    const shapes: Array<[string, string]> = [
      [GITHUB_TOKEN, GITHUB_TOKEN],
      [sample("gho_", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123"), "gho_"],
      [sample("ghu_", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123"), "ghu_"],
      [sample("ghs_", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123"), "ghs_"],
      [sample("ghr_", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123"), "ghr_"],
      [sample("github_pat_", "11ABCDEFG0abcdefghijklmn_", "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTU"), "github_pat_"],
      [sample("xoxb-", "1234567890-", "1234567890123-", "AbCdEfGhIjKlMnOpQrStUvWx"), "xoxb-"],
      [sample("xoxp-", "1234567890-", "1234567890123-", "AbCdEfGhIjKlMnOpQrStUvWx"), "xoxp-"],
      [sample("AIza", "SyA1234567890abcdefghijklmnopqrstuvw"), "AIza"],
      [sample("sk_live_", "abcdefghijklmnopqrstuvwx"), "sk_live_"],
      [sample("sk_test_", "abcdefghijklmnopqrstuvwx"), "sk_test_"],
      [sample("sk-proj-", "abcdefghijklmnopqrstuvwxyz0123"), "sk-proj-"],
      [sample("sk-ant-", "api03-abcdefghijklmnopqrstuvwxyz0123-abc"), "sk-ant-"],
      [["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "eyJzdWIiOiIxMjM0NTY3ODkwIn0", "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"].join("."), "eyJ"],
      [["MTIzNDU2Nzg5MDEyMzQ1Njc4OTAx", "GhIjKl", "abcdefghijklmnopqrstuvwxyz0123456"].join("."), "MTIz"],
      ["Bearer abcdefghijklmnopqrstuvwxyz0123", "abcdefghijklmnopqrstuvwxyz0123"],
      ["-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\n-----END OPENSSH PRIVATE KEY-----", "b3BlbnNzaC1rZXk"],
      ["-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQdGBF\n-----END PGP PRIVATE KEY BLOCK-----", "lQdGBF"],
    ];
    for (const [shape, marker] of shapes) {
      const result = redactUploadText(`value: ${shape} tail`);
      expect(result.text).not.toContain(marker);
      expect(result.text).toContain("[REDACTED] tail");
      expect(result.count).toBe(1);
    }
    expect(redactUploadText(`git clone https://oauth2:${GITHUB_TOKEN}@github.com/acme/widgets.git`))
      .toEqual({ text: "git clone https://[REDACTED]@github.com/acme/widgets.git", count: 1 });
    expect(redactUploadText("DATABASE_URL=postgres://admin:s3cret@db.internal:5432/app"))
      .toEqual({ text: "DATABASE_URL=postgres://[REDACTED]@db.internal:5432/app", count: 1 });
    expect(redactUploadText("Authorization: Bearer <token>").count).toBe(0);
  });

  test("redacts AWS secret access keys only near an access key id or an aws/secret name", () => {
    expect(redactUploadText(`AccessKeyId,SecretAccessKey\nAKIAIOSFODNN7EXAMPLE,${AWS_SECRET}\n`).text).toBe("AccessKeyId,SecretAccessKey\n[REDACTED],[REDACTED]\n");
    expect(redactUploadText(`id: AKIAIOSFODNN7EXAMPLE\n\n\n${AWS_SECRET}`).text).toBe("id: [REDACTED]\n\n\n[REDACTED]");
    expect(redactUploadText(`id: AKIAIOSFODNN7EXAMPLE\n\n\n\n${AWS_SECRET}`).text).toBe(`id: [REDACTED]\n\n\n\n${AWS_SECRET}`);
    expect(redactUploadText(`# aws profile\n# region eu-west-1\n${AWS_SECRET}`).text).toBe("# aws profile\n# region eu-west-1\n[REDACTED]");
    expect(redactUploadText(`${AWS_SECRET}\n\nsecret: yes`).text).toBe("[REDACTED]\n\nsecret: yes");
    expect(redactUploadText(AWS_SECRET).text).toBe(AWS_SECRET);
    expect(redactUploadText(`\n\n${AWS_SECRET}`, { context: "AWS master secret.txt" }).text).toBe("\n\n[REDACTED]");
    // The proximity pass needs three or more lines (two line breaks); a
    // shorter document relies on the assignment rule or its JSON key.
    expect(redactUploadText(`# aws profile\n${AWS_SECRET}`).text).toBe(`# aws profile\n${AWS_SECRET}`);
    expect(redactUploadText(AWS_SECRET, { context: "AWS master secret.txt" }).text).toBe(AWS_SECRET);
    expect(redactUploadContent("creds.json", `{"aws_secret_access_key":"${AWS_SECRET}"}`)).toBe('{"aws_secret_access_key":"[REDACTED]"}');
    expect(redactUploadContent("creds.json", `{"Credentials":{"AccessKeyId":"AKIAIOSFODNN7EXAMPLE","SecretAccessKey":"${AWS_SECRET}"}}`))
      .toBe('{"Credentials":{"AccessKeyId":"[REDACTED]","SecretAccessKey":"[REDACTED]"}}');
    expect(redactUploadContent("creds.env", `AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=${AWS_SECRET}\n`))
      .toBe("AWS_ACCESS_KEY_ID=[REDACTED]\nAWS_SECRET_ACCESS_KEY=[REDACTED]\n");
    // Not mixed case (a git sha), or not exactly 40 characters: left alone.
    expect(redactUploadText("aws sha 0123456789abcdef0123456789abcdef01234567").text).toContain("0123456789abcdef0123456789abcdef01234567");
    expect(redactUploadText(`aws ${AWS_SECRET}extra`).text).toContain(AWS_SECRET);
  });

  test("selects the value rule mode from the file extension", () => {
    for (const path of ["src/app.js", "lib/x.cjs", "x.mjs", "a/b.ts", "c.tsx", "d.jsx", "e.py", "f.go", "g.rs", "h.java", "i.kt", "j.c", "k.cc", "l.cpp",
      "m.h", "n.hpp", "o.rb", "p.php", "q.swift", "r.cs", "s.scala", "t.sh", "u.bash", "v.zsh", "w.ps1", "x.lua", "y.dart", "z.vue", "aa.svelte", "bundle.js.map", "UPPER.JS"]) {
      expect(redactModeForPath(path)).toBe("source");
    }
    for (const path of [".env", ".env.local", "settings.ini", "app.cfg", "nginx.conf", "ci.yml", "compose.yaml", "Cargo.toml", "package.json",
      "app.properties", "notes.txt", "README.md", "Makefile", "Dockerfile", ".bashrc", "archive.tar.gz", "src/token/prod.env"]) {
      expect(redactModeForPath(path)).toBe("config");
    }
  });

  test("value rule v2 leaves source-code assignments byte-identical and still redacts literal secrets", () => {
    // Every false positive sampled from a v1.0.5 production upload, in the file type it came from.
    const sampled: Array<[string, string]> = [
      ["derived.js", "derived.token_estimate = estimate;"],
      ["middleware.js", "const auth = req.headers.authorization || '';"],
      ["app.js", "authMethod: 'github-app'"],
      ["client.js", "token: config.token"],
      ["metrics.yml", "credentials_file: /run/secrets/prod_metrics_token"],
      ["pipeline.yml", "token_role: 'pipeline'"],
      ["pipeline.yml", "token_owner: 'sample-owner'"],
      ["oauth.js", "const githubOAuthConfig = githubOAuthEnabled"],
      ["fixtures.js", "META_MUSE_API_KEY: 'synthetic'"],
      ["heartbeat.py", "credential_hash: server.heartbeat_token_hash"],
      ["atlas.js", "CONTRACT_POOL_ATLAS_READ_TOKEN_FILE: tokenFile"],
      ["request.js", "Authorization: Bearer test-token"],
      // The same lines survive CONFIG mode too, except the quoted 'synthetic' literal.
      ["config.yml", "token: config.token"],
      ["heartbeat.yml", "credential_hash: server.heartbeat_token_hash"],
      ["atlas.yml", "CONTRACT_POOL_ATLAS_READ_TOKEN_FILE: tokenFile"],
      ["request.txt", "Authorization: Bearer test-token"],
      ["middleware.diff", "+const auth = req.headers.authorization || '';"],
      // SOURCE mode: unquoted identifiers are references, paths are paths, short digitless literals are labels.
      ["a.py", "token = someLongCamelCaseIdentifier2"],
      ["a.py", "password = hunter2abc"],
      ["settings.py", "AUTH_TIMEOUT = 30000000"],
      ["a.py", "password = settings.DATABASE_PASSWORD_1"],
      ["a.ts", 'const secret = "/etc/ssl/private/key1.pem";'],
      ["a.ts", 'const secret = "./secrets/key1.pem";'],
      ["a.ts", 'const secret = "../keys/key1.pem";'],
      ["a.ts", 'const secret = "~/.aws/credentials1";'],
      // (A profile path's account segment is masked, maskWindowsProfiles; a drive path elsewhere stays as it is.)
      ["a.ts", 'const secret = "D:/keys/me/token1.txt";'],
      ["a.go", 'password := "secrets/db/primary"'],
      ["a.rb", 'password = "abcdefghijklmnopqrstuvwxyz"'],
      ["a.rb", 'password = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"'],
      ["a.rb", 'token = "abc${FOO}def12"'],
      ["a.rb", 'token = "<your-token-1>"'],
      ["a.rb", "token = getToken(12345678)"],
      ["a.sh", 'TOKEN="$(cat token1.txt)"'],
    ];
    for (const [path, text] of sampled) expect(redactUploadContent(path, text)).toBe(text);
    expect(redactUploadText("+const auth = req.headers.authorization || '';", { context: "middleware.js" })).toEqual({ text: "+const auth = req.headers.authorization || '';", count: 0 });
    expect(filterUploadDiff("diff --git a/m.js b/m.js\n+const auth = req.headers.authorization || '';\n").diff)
      .toBe("diff --git a/m.js b/m.js\n+const auth = req.headers.authorization || '';\n");

    const secrets: Array<[string, string, string]> = [
      ["app.js", `const apiKey = "${sample("sk_live_", "abcdefghijklmnopqrstuvwx")}"`, 'const apiKey = "[REDACTED]"'],
      ["settings.py", 'password = "hunter2abc"', 'password = "[REDACTED]"'],
      ["settings.py", 'token = "Abcdefghijklmnopqrstuvwxyz1234"', 'token = "[REDACTED]"'],
      ["settings.py", 'password = "12345678"', 'password = "[REDACTED]"'],
      ["settings.py", 'auth = "AbCdEfGhIjKlMnOpQrStUv"', 'auth = "[REDACTED]"'],
      ["settings.py", "SECRET = Ab1/Cd2+Ef3=", "SECRET = [REDACTED]"],
      ["ci.yml", `token: ${GITHUB_TOKEN}`, "token: [REDACTED]"],
      ["config.yml", 'api_key: "abcdef1234567890"', 'api_key: "[REDACTED]"'],
      ["config.yml", "password: hunter7abc", "password: [REDACTED]"],
      ["config.yml", "META_MUSE_API_KEY: 'synthetic'", "META_MUSE_API_KEY: '[REDACTED]'"],
      ["config.yml", 'token: "config.token"', 'token: "[REDACTED]"'],
      ["config.yml", "token: config-token", "token: [REDACTED]"],
      ["request.http", "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "Authorization: Bearer [REDACTED]"],
      ["request.js", "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "Authorization: Bearer [REDACTED]"],
    ];
    for (const [path, text, expected] of secrets) {
      expect(redactUploadContent(path, text)).toBe(expected);
      expect(redactUploadText(text, { mode: redactModeForPath(path) }).count).toBe(1);
    }
    // Excluded last segments never name a secret, in either mode.
    for (const last of ["file", "filename", "dir", "mode", "method", "role", "owner", "type", "kind", "enabled", "estimate", "hash", "digest", "at",
      "config", "client", "prefix", "suffix", "format", "scheme", "provider", "status", "state", "label", "description", "title", "class", "field",
      "fields", "list", "names", "version", "timeout", "limit", "max", "min", "interval", "retries", "port"]) {
      const line = `token_${last}: abcdefgh1234`;
      expect(redactUploadContent("x.yml", line)).toBe(line);
      expect(redactUploadContent("x.py", line)).toBe(line);
    }
  });

  test("redacts a Bearer token only when it looks like a credential", () => {
    const kept = [
      "Authorization: Bearer test-token",
      "Authorization: Bearer yourAccessTokenGoesHere",
      "Authorization: Bearer your_access_token.goes.here",
      "Authorization: Bearer ${ACCESS_TOKEN_GOES_HERE}",
      "Authorization: Bearer <your-access-token-here>",
      "Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
      "Authorization: Bearer ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    ];
    for (const line of kept) expect(redactUploadText(line)).toEqual({ text: line, count: 0 });
    const redacted = [
      "Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123",
      "Authorization: Bearer a8f3b2c9d4e5f6a7b8c9d0e1",
      "Authorization: Bearer Your-Access-Token-Goes-Here",
      "Authorization: Bearer AbCdEfGhIjKlMnOpQrStUv/wx+yz==",
    ];
    for (const line of redacted) expect(redactUploadText(line)).toEqual({ text: "Authorization: Bearer [REDACTED]", count: 1 });
    expect(redactUploadText("authorization: bearer abcdefghijklmnopqrstuvwxyz0123")).toEqual({ text: "authorization: bearer [REDACTED]", count: 1 });
  });

  test("keeps a source file named after a token but redacts the literal inside it", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-source-"));
    roots.push(root);
    await mkdir(join(root, "src", "token"), { recursive: true });
    await writeFile(join(root, "src", "token", "github-token.ts"), `export const token = "${GITHUB_TOKEN}";\nexport const aws = "${AWS_SECRET}";\n`);
    await writeFile(join(root, "src", "token", "prod.env"), `GITHUB_TOKEN=${GITHUB_TOKEN}\n`);
    await writeFile(join(root, "README.md"), `Deploy with\n\n    export CLIENT_SECRET=${GITHUB_TOKEN}\n`);
    const { uploads, upload } = makeUploads();
    const sessionUploader = new SessionUploader({ upload, fallbackScanMs: 60_000 });
    sessionUploader.startSession("session-source-1", "workspace-source", root);
    await sessionUploader.stop();

    const start = uploads.find((item) => item.snapshot_type === "start")!;
    expect(start.manifest.map((entry) => entry.path).sort()).toEqual(["README.md", "src/token/github-token.ts"]);
    expect(start.files.find((file) => file.path === "src/token/github-token.ts")?.content)
      .toBe('export const token = "[REDACTED]";\nexport const aws = "[REDACTED]";\n');
    expect(start.files.find((file) => file.path === "README.md")?.content).toBe("Deploy with\n\n    export CLIENT_SECRET=[REDACTED]\n");
    expect(start.privacy.denied_file_count).toBe(1);
    const serialized = JSON.stringify(uploads);
    expect(serialized).not.toContain(GITHUB_TOKEN);
    expect(serialized).not.toContain(AWS_SECRET);
  });

  test("scrubs the trace and .json files as JSON so escapes survive redaction", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-json-"));
    roots.push(root);
    await writeFile(join(root, "config.json"), '{\n  "note": "{\\"password\\":\\"hunter2abc\\"}",\n  "nested": {"apiKey": "abcdefghijkl", "author": "Jane <jane@acme-mail.io>"}\n}\n');
    await writeFile(join(root, "settings.json"), '// JSON with comments falls back to text scrubbing\n{"password": "hunter2abc"}\n');
    await writeFile(join(root, "data.json"), '{"a": 1.0, "b": [1, 2]}');
    const { uploads, upload } = makeUploads();
    const sessionUploader = new SessionUploader({ upload, fallbackScanMs: 60_000 });
    const sessionId = "session-json-1";
    sessionUploader.startSession(sessionId, "workspace-json", root);
    sessionUploader.recordTrace(sessionId, "message", { text: 'line one\n@app.function(gpu="h100")\nx@acme-mail.io', token: GITHUB_TOKEN });
    sessionUploader.flushTrace(sessionId);
    await sessionUploader.stop();

    const trace = uploads.find((item) => item.snapshot_type === "trace")!;
    const parsed = JSON.parse(trace.files[0]!.content) as { events: Array<{ type: string; data?: Record<string, unknown> }> };
    const expected = { text: 'line one\n@app.function(gpu="h100")\n[REDACTED_PII]', token: "[REDACTED]" };
    expect(parsed.events.find((event) => event.type === "message")?.data).toEqual(expected);
    expect(trace.trace?.find((event) => event.type === "message")?.data).toEqual(expected);

    const start = uploads.find((item) => item.snapshot_type === "start")!;
    const content = (path: string) => start.files.find((file) => file.path === path)!.content;
    expect(JSON.parse(content("config.json"))).toEqual({
      note: '{"password":"[REDACTED]"}',
      nested: { apiKey: "[REDACTED]", author: "Jane <[REDACTED_PII]>" },
    });
    expect(content("config.json").startsWith('{\n  "note"')).toBe(true);
    expect(content("config.json").endsWith("\n")).toBe(true);
    expect(content("settings.json")).toBe('// JSON with comments falls back to text scrubbing\n{"password": "[REDACTED]"}\n');
    expect(content("data.json")).toBe('{"a": 1.0, "b": [1, 2]}');
    expect(start.manifest.find((entry) => entry.path === "config.json")?.sha256).toBe(sha256(content("config.json")));
    expect(JSON.stringify(uploads)).not.toContain("hunter2abc");
  });

  test("never leaves a dangling backslash when scrubbing escaped text", () => {
    const raw = JSON.stringify({ text: `line one\n@app.function(gpu="h100")\nx@acme-mail.io\njane@acme-mail.io\tAKIAIOSFODNN7EXAMPLE\nTOKEN=${GITHUB_TOKEN}` });
    const result = redactUploadText(raw);
    expect(JSON.parse(result.text)).toEqual({ text: 'line one\n@app.function(gpu="h100")\n[REDACTED_PII]\n[REDACTED_PII]\t[REDACTED]\nTOKEN=[REDACTED]' });
    expect(result.count).toBe(4);
    expect(redactUploadText("password=\"abcdefgh\\\"more\"").text).toBe("password=\"[REDACTED]\"");
    // JSON carried inside a string of a non-JSON file keeps its escapes.
    const embedded = JSON.stringify({ text: JSON.stringify({ password: "hunter2abc", user: "jane" }) });
    expect(JSON.parse(redactUploadText(embedded).text)).toEqual({ text: '{"password":"[REDACTED]","user":"jane"}' });
    expect(redactUploadText('log: {\\"token\\":\\"abcdefghijkl\\"} done').text).toBe('log: {\\"token\\":\\"[REDACTED]\\"} done');
    expect(redactUploadJsonText('{"a":{"toJSON":1},"secret":"abcdefghijkl","n":1e3}')).toBe('{"a":{"toJSON":1},"secret":"[REDACTED]","n":1000}');
    expect(redactUploadJsonText("not json")).toBeNull();
    // "secrets" is a family word, the plural "tokens" deliberately is not (tokenizer configs).
    expect(redactUploadJson({ at: new Date(0), secrets: ["abcdefghijkl", "short"], tokens: ["abcdefghijkl"], "jane@acme-mail.io": 1 }))
      .toEqual({ value: { at: "1970-01-01T00:00:00.000Z", secrets: ["[REDACTED]", "short"], tokens: ["abcdefghijkl"], "[REDACTED_PII]": 1 }, count: 2 });
    expect(redactUploadContent("nested/x.JSON", '{"password":"hunter2abc"}')).toBe('{"password":"[REDACTED]"}');
    expect(redactUploadContent("x.txt", '{"password":"hunter2abc"}')).toBe('{"password":"[REDACTED]"}');
  });

  test("scrubs diff hunks of JSON files as text", () => {
    const raw = ["diff --git a/config.json b/config.json", "--- a/config.json", "+++ b/config.json", "@@ -1 +1 @@", '+  "password": "hunter2abc",', ""].join("\n");
    const result = filterUploadDiff(raw);
    expect(result.diff).toContain('+  "password": "[REDACTED]",');
    expect(result.diff).not.toContain("hunter2abc");
  });

  test("redacts assignments and e-mails on whichever line they sit, never across a line break", () => {
    // Both rules are applied only to lines holding their keyword or "@"; the
    // result must equal a whole-text pass, line endings and escapes included.
    expect(redactUploadContent("notes.txt", "first line\npassword=hunter2hunter2\r\nlast")).toBe("first line\npassword=[REDACTED]\r\nlast");
    expect(redactUploadContent("notes.txt", "a@b\njane@acme-mail.io\n@x\nx@y.io")).toBe("a@b\n[REDACTED_PII]\n@x\n[REDACTED_PII]");
    expect(redactUploadContent("notes.txt", "jane@\nexample.com and key\n=abcdefgh12")).toBe("jane@\nexample.com and key\n=abcdefgh12");
    expect(redactUploadContent("run.sh", "echo done \\\nexport API_KEY=abc123def456\nTOKEN='S3cretValue99'"))
      .toBe("echo done \\\nexport API_KEY=abc123def456\nTOKEN='[REDACTED]'");
    expect(redactUploadContent("app.ts", "const keyName = config.token;\nconst apiKey = \"sk-proj-abcdefghijklmnop1234\";\n// contact: dev@acme-mail.io"))
      .toBe("const keyName = config.token;\nconst apiKey = \"[REDACTED]\";\n// contact: [REDACTED_PII]");
    expect(redactUploadContent("data.json", "{\n  \"note\": \"line\\npassword=hunter2hunter2\",\n  \"author\": \"jane@acme-mail.io\"\n}\n"))
      .toBe("{\n  \"note\": \"line\\npassword=[REDACTED]\",\n  \"author\": \"[REDACTED_PII]\"\n}\n");
  });

  test("scrubs a 1 MiB line in bounded time", () => {
    const mebibyte = 1024 * 1024;
    const lines = [
      "x".repeat(mebibyte),
      "ABCDabcd0123/+".repeat(mebibyte / 14),
      "token=a ".repeat(mebibyte / 8),
      "Bearer ".repeat(mebibyte / 7),
      "eyJaaaaaaaaaaaa.".repeat(mebibyte / 16),
      "a.".repeat(mebibyte / 2),
      "a-".repeat(mebibyte / 2),
      "https://".repeat(mebibyte / 8),
      "Ma.".repeat(mebibyte / 3),
      "\\n".repeat(mebibyte / 2),
      `secret: ${"A1b".repeat(mebibyte / 3)}`,
      `secret: ${"a.".repeat(mebibyte / 2)}`,
      `secret: ${"a.".repeat(mebibyte / 2)}/`,
      `secret: ${"Ab/".repeat(mebibyte / 3)}`,
      `secret: "${"a1.".repeat(mebibyte / 3)}"`,
      `Bearer ${"aB".repeat(mebibyte / 2)}`,
      `Bearer ${"a.".repeat(mebibyte / 2)}`,
    ];
    for (const line of lines) {
      for (const mode of ["config", "source"] as const) {
        const started = performance.now();
        redactUploadText(line, { mode });
        expect(performance.now() - started).toBeLessThan(2_000);
      }
    }
  }, 60_000);
});

// --- scrubber parity: the backend's second-sample refinements ---------------
// Ported from the backend's tests/omnirush/test_collector.py (46ee95e) with the
// same inputs and expected outputs; each test names the backend test it mirrors.

// The excluded last segments added after the second production sample.
const EXCLUDED_LAST_SEGMENTS_ADDED = [
  "in", "out", "percent", "pct", "ms", "secs", "minutes", "hours", "days", "expires", "expiry", "expiration", "bytes", "len", "width",
  "height", "offset", "index", "idx", "pos", "total", "sum", "avg", "ratio", "rate", "threshold", "weight", "score", "encryption",
  "algorithm", "algo", "cipher", "strategy", "policy", "source", "target", "origin", "backend", "engine", "driver", "handler",
  "callback", "event", "action", "reason", "message", "error", "envelope", "ref", "reference", "link", "pointer", "alias",
];

// Lines from the second production sample, each in the file type it came from.
const SAMPLE2_TS = [
  "const client = { client_token: stagedClient?.plaintext || null };",
  "const apiKey = account?.managementKey || account?.apiKey;",
  "const job = { secret_envelope: params[8] };",
  "const pattern = /token=[0-9a-f]{16}/;",
  "const cacheKey = 'pipeline-token:session:trial-123';",
  "const grant = { refresh_token_expires_in: 15897600 };",
  "const proxy = { provider_credential_ref: 'iproyal:claude-in-001' };",
  "",
].join("\n");
const SAMPLE2_SH = "psql -c \"ALTER SYSTEM SET password_encryption='scram-sha-256'\"\n";
const SAMPLE2_CONF = "password_encryption = 'scram-sha-256'\n";
const SAMPLE2_YML = "proxies:\n  - provider_credential_ref: 'iproyal:claude-in-001'\n    refresh_token_expires_in: 15897600\n";
const SAMPLE2_HASHES = `{"src/admin_auth.py": "${"3f2a9c1e".repeat(8)}", "src\\\\win\\\\auth.py": "${"b7d80e1f".repeat(8)}", "auth.py": "${"5c6d7e8f".repeat(8)}"}`;
const SAMPLE2_FIXTURES = "LIVE_DSN = 'postgres://live@host:6432/db'\nSESSION_DSN = 'postgres://session@host/db'\n";
const PATCH = [
  "diff --git a/app/settings.py b/app/settings.py",
  "--- a/app/settings.py",
  "+++ b/app/settings.py",
  "@@ -1,2 +1,3 @@",
  " import config",
  "+token = config.token",
  "-password = None",
  '+password = "hunter2abc"',
  "",
].join("\n");

describe("session uploader scrubber parity: second-sample refinements", () => {
  test("secret-named keys follow the segment rule (test_secret_key_rule_qualifies / _does_not_qualify)", () => {
    for (const key of ["auth_token", "basic-auth", "AUTH", "authorization", "oauth_client_secret", "APIKey", "accessKey", "HTTPSecret", "token2",
      "secrets", "client.secret", "x-api-key"]) {
      expect(isSecretAssignmentKey(key)).toBe(true);
    }
    for (const key of [
      "author", "authors", "authored_by", "oauth_client_id", "tokenizer_class", "tokenize", "keyboard_layout", "keywords", "pwdir",
      "accessKeyId", "token_url", "tokens", "additional_special_tokens", "key", "",
      // The excluded last segments added with value rule v2.
      "derived.token_estimate", "authMethod", "token_role", "token_owner", "credentials_file", "credential_hash", "githubOAuthConfig",
      "CONTRACT_POOL_ATLAS_READ_TOKEN_FILE", "AUTH_TIMEOUT", "token_filename", "token_dir", "auth_mode", "token_type", "auth_kind",
      "auth_enabled", "secret_digest", "token_expires_at", "auth_client", "api_key_prefix", "token_suffix", "token_format", "auth_scheme",
      "auth_provider", "token_status", "auth_state", "auth_label", "secret_description", "token_title", "auth_class", "password_field",
      "token_fields", "token_list", "secret_names", "token_version", "token_limit", "auth_max", "secret_min", "auth_interval",
      "token_retries", "auth_port",
      // The second production sample.
      "refresh_token_expires_in", "password_encryption", "provider_credential_ref", "secret_envelope",
    ]) {
      expect(isSecretAssignmentKey(key)).toBe(false);
    }
  });

  test("the added excluded last segments exclude a key only as its last segment (test_second_sample_excluded_last_segments)", () => {
    for (const word of EXCLUDED_LAST_SEGMENTS_ADDED) {
      const capitalized = word[0]!.toUpperCase() + word.slice(1);
      expect(isSecretAssignmentKey(`token_${word}`)).toBe(false);
      expect(isSecretAssignmentKey(`auth${capitalized}`)).toBe(false);
      expect(isSecretAssignmentKey(`client.secret.${word}`)).toBe(false);
      expect(isSecretAssignmentKey(`${word}_token`)).toBe(true);
      // The same through the text rule, in both modes.
      for (const mode of ["config", "source"] as const) {
        expect(redactUploadText(`token_${word} = "abcdefgh1234"`, { mode }).count).toBe(0);
        expect(redactUploadText(`${word}_token = "abcdefgh1234"`, { mode })).toEqual({ text: `${word}_token = "[REDACTED]"`, count: 1 });
      }
    }
  });

  test("auth_code and *_plaintext stay secret-named (test_auth_code_and_plaintext_keys_stay_secret_named)", () => {
    const text = 'auth_code = "abcdefgh1234"\npassword_plaintext = "hunter2abc"\n# TOKEN = "abcdefgh1234"\n';
    const result = redactUploadText(text, { context: "app.py", mode: "source" });
    expect(result.text).not.toContain("abcdefgh1234");
    expect(result.text).not.toContain("hunter2abc");
    expect(result.count).toBe(3);
    expect(isSecretAssignmentKey("auth_code")).toBe(true);
    expect(isSecretAssignmentKey("password_plaintext")).toBe(true);
  });

  test("path-like JSON keys (test_path_like_keys_follow_the_desktop_rule)", () => {
    const cases: Array<[string, boolean]> = [
      ["src/admin_auth.py", true], ["src\\admin_auth.py", true], ["admin_auth.py", true], ["auth.json", true], ["token.a1b2c", true],
      ["C:\\x", true], ["auth_token", false], ["db.password", false], ["client.secret", false], ["auth.pyproject", false], ["token", false],
      ["", false],
    ];
    for (const [key, expected] of cases) expect(isPathLikeKey(key)).toBe(expected);
    // Python's `$` also matches before one trailing newline; the desktop mirrors it.
    expect(isPathLikeKey("auth.py\n")).toBe(true);
    expect(isPathLikeKey("auth.py\n\n")).toBe(false);
  });

  test("the scrub mode follows the file extension (test_scrub_mode_follows_the_file_extension)", () => {
    for (const extension of ["js", "cjs", "mjs", "ts", "tsx", "jsx", "py", "go", "rs", "java", "kt", "c", "cc", "cpp", "h", "hpp", "rb", "php",
      "swift", "cs", "scala", "sh", "bash", "zsh", "ps1", "lua", "dart", "vue", "svelte", "map", "patch", "diff"]) {
      expect(redactModeForPath(`src/file.${extension}`)).toBe("source");
      expect(redactModeForPath(`src/FILE.${extension.toUpperCase()}`)).toBe("source");
    }
    expect(redactModeForPath("dist/bundle.js.map")).toBe("source");
    for (const path of [".env", ".env.local", ".bashrc", "Makefile", "Dockerfile", "index.", "a.tar.gz", "config.yml", "config.yaml", "pyproject.toml",
      "package.json", "setup.cfg", "app.ini", "nginx.conf", "app.properties", "notes.txt", "README.md", "infra/main.tf", "build.gradle.kts",
      "schema.sql", "index.html", "__omnirush__/trace.jsonl"]) {
      expect(redactModeForPath(path)).toBe("config");
    }
  });

  test("source value rule (test_source_value_rule_redacts_quoted_literals / _skips_references_paths_and_words)", () => {
    for (const value of ["hunter2abc", "Abcdefghijklmnopqrstuvwxyz1234", "AbcdefghijklmnopqrsT", "12345678", "sk-testsecret123456789", AWS_SECRET]) {
      expect(isSecretAssignmentValue(value, "source", true)).toBe(true);
    }
    const skipped: Array<[string, boolean]> = [
      // No digit and under 20 characters of mixed case: a plain word.
      ["synthetic", true], ["github-app", true], ["sample-owner", true], ["abcdefghijklmnopqrstuvwxyz", true], ["ABCDEFGHIJKLMNOPQRSTUVWXYZ", true],
      ["AbcdefghijklmnopqrS", true],
      // Unquoted identifier or member-expression syntax is a reference, whatever digits it holds.
      ["estimate", false], ["githubOAuthEnabled", false], ["req.headers.authorization", false], ["config.token2", false], ["$scope.token1", false],
      ["hunter2abc", false], ["Abcdefghijklmnopqrstuvwxyz1234", false],
      // Filesystem paths.
      ["/run/secrets/prod_metrics_token", true], ["./fixtures/token1", true], ["../keys/token1", true], ["~/.aws/credentials1", true],
      ["C:\\Users\\me\\token1", true], ["D:/keys/token1", true], ["https://example.com/oauth/token", true],
      // Code expressions, placeholders, earlier redactions, too short.
      ["getToken()", false], ["${TOKEN}", false], ["abc${X}def123", true], ["$(cat token.txt)", false], ["process.env.TOKEN1", false],
      ["os.environ1", false], ["env.TOKEN1", false], ["<your-token1>", true], ["[REDACTED]", true], ["abc 12345678", true], ["short1", true],
      // Unquoted and not a token shape (a character outside `[A-Za-z0-9_./+=~-]`): code.
      ["stagedClient?.plaintext", false], ["account?.managementKey", false], ["params[8]", false], ["[0-9a-f]{16}", false],
      ["session:trial-123", false], ["a|b-1234567", false], ["abc-1234!", false], ["x*y-1234567", false], ["<abc-1234", false],
      ["`abc-1234`", false],
    ];
    for (const [value, quoted] of skipped) expect(isSecretAssignmentValue(value, "source", quoted)).toBe(false);
  });

  test("unquoted source values that are token shapes still qualify (test_source_value_rule_keeps_unquoted_token_shapes)", () => {
    for (const value of ["abc-123-def", "YWJjZGVmZ2hpams=", "a/b+c~12345", "12345678", AWS_SECRET]) {
      expect(isSecretAssignmentValue(value, "source", false)).toBe(true);
      expect(isSecretAssignmentValue(value, "source", true)).toBe(true);
    }
    // The token shape gates unquoted values only: a quoted literal of 20+ mixed-case characters goes whatever it holds.
    expect(isSecretAssignmentValue("stagedClient?.plaintext", "source", true)).toBe(true);
  });

  test("a source key must follow a delimiter (test_source_key_must_follow_a_delimiter)", () => {
    const cases: Array<[string, string | null]> = [
      // A key after `/`, `:`, `[`, `?`, `&`, `=` or `|` is not an assignment in source...
      ["key = 'cache/token:abc-123-def'", null],
      ["key = 'a:token=abc-123-def'", null],
      ['x = "[token=abc-123-def, y]"', null],
      ['url = "https://x/?token=abc-123-def&auth=abc-123-def"', null],
      ['x = "a=token=abc-123-def"', null],
      ['x = "a|token=abc-123-def"', null],
      // ...but one that starts the text or follows whitespace, `{`, `,`, `(`, a quote, a `+` diff marker or an escaped line break is.
      ['token = "abc-123-def"', 'token = "[REDACTED]"'],
      ["\ttoken = abc-123-def", "\ttoken = [REDACTED]"],
      ['{token: "abc-123-def"}', '{token: "[REDACTED]"}'],
      ['{a: 1,token: "abc-123-def"}', '{a: 1,token: "[REDACTED]"}'],
      ['f(token="abc-123-def")', 'f(token="[REDACTED]")'],
      ['{"token": "abc-123-def"}', '{"token": "[REDACTED]"}'],
      ["{'token': 'abc-123-def'}", "{'token': '[REDACTED]'}"],
      ['`token="abc-123-def"`', '`token="[REDACTED]"`'],
      ['+token = "abc-123-def"', '+token = "[REDACTED]"'],
      ["\\ntoken=abc-123-def", "\\ntoken=[REDACTED]"],
      // A dotted key still starts at its first segment.
      ['this.token = "hunter2abc"', 'this.token = "[REDACTED]"'],
    ];
    for (const [sample, expected] of cases) {
      expect(redactUploadText(sample, { mode: "source" })).toEqual(expected === null ? { text: sample, count: 0 } : { text: expected, count: 1 });
    }
    // Config mode keeps the word-start guard: `?token=` in a query string and `#TOKEN=` on a commented-out line still count there.
    expect(redactUploadText("https://x/?token=abc-123-def")).toEqual({ text: "https://x/?token=[REDACTED]", count: 1 });
    expect(redactUploadText("#TOKEN=abc-123-def")).toEqual({ text: "#TOKEN=[REDACTED]", count: 1 });
  });

  test("limit-style keys are excluded in both modes (test_limit_style_keys_are_excluded_in_both_modes)", () => {
    for (const sample of [
      "AUTH_TIMEOUT = 30000000", "auth_timeout: 30000000", "TOKEN_LIMIT = 10000000", "token_max = 12345678", "secret_min = abcdefgh",
      "auth_interval = 60000000", "token_retries: 10000000", "AUTH_PORT = 80808080", "refresh_token_expires_in: 15897600",
      "password_encryption='scram-sha-256'", "provider_credential_ref: 'iproyal:claude-in-001'", "secret_envelope: params[8]",
      "token_expires_in = 15897600", "secret_algorithm = 'aes-256-gcm'", 'auth_callback = "https://x/cb?state=abc12345"',
    ]) {
      expect(redactUploadText(sample, { mode: "source" })).toEqual({ text: sample, count: 0 });
      expect(redactUploadText(sample, { mode: "config" })).toEqual({ text: sample, count: 0 });
    }
  });

  test("the second production sample comes back byte-identical (test_second_production_sample_is_byte_identical)", () => {
    const files: Array<[string, string]> = [
      ["src/client.ts", SAMPLE2_TS],
      ["scripts/pg.sh", SAMPLE2_SH],
      ["db/postgresql.conf", SAMPLE2_CONF],
      ["config/proxies.yml", SAMPLE2_YML],
      ["build/source-hashes.json", SAMPLE2_HASHES],
      ["tests/fixtures.py", SAMPLE2_FIXTURES],
    ];
    for (const [path, content] of files) expect(redactUploadContent(path, content)).toBe(content);
    for (const sample of [SAMPLE2_TS, SAMPLE2_SH, SAMPLE2_FIXTURES]) expect(redactUploadText(sample, { mode: "source" })).toEqual({ text: sample, count: 0 });
    for (const sample of [SAMPLE2_CONF, SAMPLE2_YML]) expect(redactUploadText(sample)).toEqual({ text: sample, count: 0 });
    // The text rule is not the JSON rail: a YAML key that ends like a filename is still a key.
    expect(redactUploadText("admin_auth.py: abcdefgh1234")).toEqual({ text: "admin_auth.py: [REDACTED]", count: 1 });
  });

  test("the second sample's true positives still go (test_second_sample_true_positives_still_go)", () => {
    // A path-like key leaves its value to the provider shapes; a bare user
    // stays but `user:pass` goes; a .patch file is source, so `config.token`
    // is a reference and `"hunter2abc"` a literal.
    expect(redactUploadContent("build/source-hashes.json", `{"src/x.py": "${GITHUB_TOKEN}"}`)).toBe('{"src/x.py":"[REDACTED]"}');
    expect(redactUploadJson({ "src/x.py": GITHUB_TOKEN })).toEqual({ value: { "src/x.py": "[REDACTED]" }, count: 1 });
    expect(redactUploadContent("tests/fixtures.py", "LIVE_DSN = 'postgres://live:secret@host/db'\n")).toBe("LIVE_DSN = 'postgres://[REDACTED]@host/db'\n");
    expect(redactUploadText("LIVE_DSN = 'postgres://live:secret@host/db'\n", { context: "tests/fixtures.py", mode: "source" }).count).toBe(1);
    expect(redactUploadContent("fix.patch", PATCH)).toBe(PATCH.replace('"hunter2abc"', '"[REDACTED]"'));
    expect(redactUploadText(PATCH, { context: "fix.patch", mode: redactModeForPath("fix.patch") }).count).toBe(1);
    // The envelope's git diff scrubs each file's section with that file's
    // mode: in a .py section a bare `hunter2abc` is a name, as in the file
    // itself; in a config file's section it is a literal.
    expect(filterUploadDiff("diff --git a/app/settings.py b/app/settings.py\n+password = hunter2abc\n").diff)
      .toBe("diff --git a/app/settings.py b/app/settings.py\n+password = hunter2abc\n");
    expect(filterUploadDiff("diff --git a/app/settings.ini b/app/settings.ini\n+password = hunter2abc\n").diff)
      .toBe("diff --git a/app/settings.ini b/app/settings.ini\n+password = [REDACTED]\n");
    expect(redactUploadText("+password = hunter2abc", { mode: redactModeForPath("fix.patch") })).toEqual({ text: "+password = hunter2abc", count: 0 });
  });

  test("URL userinfo is redacted only with a password (test_url_userinfo_is_redacted_whole)", () => {
    expect(redactUploadText(`git clone https://oauth2:${GITHUB_TOKEN}@github.com/acme/widgets.git`))
      .toEqual({ text: "git clone https://[REDACTED]@github.com/acme/widgets.git", count: 1 });
    expect(redactUploadText("DATABASE_URL=postgres://admin:s3cret@db.internal:5432/app"))
      .toEqual({ text: "DATABASE_URL=postgres://[REDACTED]@db.internal:5432/app", count: 1 });
    expect(redactUploadText("Authorization: Bearer <token>")).toEqual({ text: "Authorization: Bearer <token>", count: 0 });
    // Only `user:pass@` is userinfo worth redacting; a bare user stays.
    for (const sample of ["postgres://live@host:6432/db", "postgres://session@host/db", "DATABASE_URL=postgres://live@host:6432/db"]) {
      expect(redactUploadText(sample)).toEqual({ text: sample, count: 0 });
      expect(redactUploadText(sample, { mode: "source" })).toEqual({ text: sample, count: 0 });
    }
    expect(redactUploadText("postgres://live:secret@host/db")).toEqual({ text: "postgres://[REDACTED]@host/db", count: 1 });
  });

  test("the assignment rule reads whitespace as Python does, and a source key may follow any non-ASCII character", () => {
    // U+0085 and U+001C-U+001F are whitespace to the backend's `\s`: a value
    // ends there and a key may start after one, on both sides.
    expect(redactUploadText("token=abc-123-def\u0085tail", { mode: "source" })).toEqual({ text: "token=[REDACTED]\u0085tail", count: 1 });
    expect(redactUploadText("x = 1\u001ctoken = abc-123-def", { mode: "source" })).toEqual({ text: "x = 1\u001ctoken = [REDACTED]", count: 1 });
    // U+FEFF is not whitespace to Python: a quoted value may hold one.
    expect(redactUploadText('"token": "abc\ufeff12345"')).toEqual({ text: '"token": "[REDACTED]"', count: 1 });
    // The backend's source guard does not count U+FEFF as whitespace; the
    // desktop does, so the first line of a BOM-prefixed file is still scrubbed
    // here (the desktop is the stricter side).
    expect(redactUploadContent("settings.py", '\ufeffpassword = "hunter2abc"\n')).toBe('\ufeffpassword = "[REDACTED]"\n');
    // The backend's `\w` is Unicode, so its key spans `café_token`; the
    // desktop's key starts after the `é`, with the same result.
    expect(redactUploadText("café_token = 'hunter2abc'", { mode: "source" })).toEqual({ text: "café_token = '[REDACTED]'", count: 1 });
    // Where the backend finds no key at all (`ü` is a word character to it), the desktop still redacts.
    expect(redactUploadText("ütoken = 'hunter2abc'", { mode: "source" })).toEqual({ text: "ütoken = '[REDACTED]'", count: 1 });
  });

  test("URL userinfo with an empty user and a password is redacted too (stricter than the backend at 46ee95e)", () => {
    // Redis's own AUTH form; the assignment rule cannot catch it (`REDIS_URL` ends in `url`).
    expect(redactUploadContent("config/app.env", "REDIS_URL=redis://:p4ssw0rd@cache:6379/0\n")).toBe("REDIS_URL=redis://[REDACTED]@cache:6379/0\n");
    expect(redactUploadContent("app.py", 'url = "rediss://:hunter2abc@cache:6380/0"\n')).toBe('url = "rediss://[REDACTED]@cache:6380/0"\n');
    expect(redactUploadContent("broker.yml", "broker: amqp://:s3cretpw@mq:5672//\n")).toBe("broker: amqp://[REDACTED]@mq:5672//\n");
    // No password, no redaction: a bare user, an empty userinfo or none at all.
    for (const sample of ["postgres://live@host/db", "redis://@cache:6379/0", "redis://cache:6379/0", "http://[::1]:8080/x"]) {
      expect(redactUploadText(sample)).toEqual({ text: sample, count: 0 });
    }
  });

  test("JSON files keep the AWS proximity rule: the raw-text pass and the container rail (test_json_files_keep_the_aws_secret_proximity_rule)", () => {
    // ECS task definitions, k8s env lists and Postman environments: the key
    // naming the secret is a sibling value, not the value's own key.
    const taskDefinition = JSON.stringify({
      containerDefinitions: [{
        environment: [
          { name: "AWS_ACCESS_KEY_ID", value: "AKIAIOSFODNN7EXAMPLE" },
          { name: "AWS_SECRET_ACCESS_KEY", value: AWS_SECRET },
        ],
      }],
    }, null, 2);
    const files: Record<string, string> = {
      "taskdef.json": taskDefinition,
      "taskdef.txt": taskDefinition,
      "taskdef.yaml": taskDefinition,
      "postman.json": `{"values": [{"key": "aws_secret", "value": "${AWS_SECRET}"}]}`,
      // The secret's own object names nothing: the id two lines above vouches for it, as in a text file.
      "pairs.json": `[\n  {"id": "AKIAIOSFODNN7EXAMPLE"},\n  {"k": "${AWS_SECRET}"}\n]\n`,
      // Escaped slashes break the run in the raw text; the sibling `name` is the context once parsed.
      "escaped.json": `{"name":"AWS_SECRET_ACCESS_KEY","value":"${AWS_SECRET.replaceAll("/", "\\/")}"}`,
      // Nothing near names an AWS key: a 40-character run is data.
      "plain.json": `{"hash": "${AWS_SECRET}"}`,
    };
    const out = Object.fromEntries(Object.entries(files).map(([path, content]) => [path, redactUploadContent(path, content)]));
    for (const [path, content] of Object.entries(out)) {
      JSON.parse(content);
      expect(content.includes(AWS_SECRET)).toBe(path === "plain.json");
    }
    expect(JSON.parse(out["taskdef.json"]!)).toEqual(JSON.parse(out["taskdef.txt"]!));
    expect(JSON.parse(out["taskdef.json"]!).containerDefinitions[0].environment).toEqual([
      { name: "AWS_ACCESS_KEY_ID", value: "[REDACTED]" },
      { name: "AWS_SECRET_ACCESS_KEY", value: "[REDACTED]" },
    ]);
    expect(JSON.parse(out["postman.json"]!)).toEqual({ values: [{ key: "aws_secret", value: "[REDACTED]" }] });
    expect(JSON.parse(out["pairs.json"]!)).toEqual([{ id: "[REDACTED]" }, { k: "[REDACTED]" }]);
    expect(JSON.parse(out["escaped.json"]!)).toEqual({ name: "AWS_SECRET_ACCESS_KEY", value: "[REDACTED]" });
    expect(out["plain.json"]).toBe(files["plain.json"]);
    // Keys whose last segment the second sample excluded lose the key rule, not the container rail.
    expect(redactUploadContent("a.json", `{"secret_envelope": "${AWS_SECRET}"}`)).toBe('{"secret_envelope":"[REDACTED]"}');
    expect(redactUploadContent("a.json", `{"aws_secret_ref": "${AWS_SECRET}"}`)).toBe('{"aws_secret_ref":"[REDACTED]"}');
    expect(redactUploadContent("a.json", `{\n  "db": {\n    "secret_alias": "${AWS_SECRET}"\n  }\n}`))
      .toBe('{\n  "db": {\n    "secret_alias": "[REDACTED]"\n  }\n}');
    expect(redactUploadContent("a.json", `{"src/secret.py": "${AWS_SECRET}"}`)).toBe('{"src/secret.py":"[REDACTED]"}');
  });

  test("trace AWS secrets need their key or a container naming AWS (test_trace_artifact_aws_secrets_need_key_or_container_context)", async () => {
    const document = {
      events: [
        { type: "tool.call", data: { note: "id AKIAIOSFODNN7EXAMPLE" } },
        { type: "tool.call", data: { note: AWS_SECRET } },
        { type: "tool.call", data: { aws_secret: AWS_SECRET } },
        { type: "tool.call", data: { name: "AWS_SECRET_ACCESS_KEY", value: AWS_SECRET } },
      ],
    };
    const { value, count } = redactUploadJson(document);
    expect(JSON.parse(JSON.stringify(value)).events.map((event: { data: unknown }) => event.data)).toEqual([
      { note: "id [REDACTED]" },
      { note: AWS_SECRET },
      { aws_secret: "[REDACTED]" },
      { name: "AWS_SECRET_ACCESS_KEY", value: "[REDACTED]" },
    ]);
    expect(count).toBe(3);

    // The uploaded trace document gets the same rail.
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-trace-aws-"));
    roots.push(root);
    const { uploads, upload } = makeUploads();
    const sessionUploader = new SessionUploader({ upload, changeDebounceMs: 60_000, fallbackScanMs: 60_000 });
    const sessionId = "session-trace-aws-1234";
    sessionUploader.startSession(sessionId, "workspace-trace-aws", root);
    await sessionUploader.idle(sessionId);
    sessionUploader.recordTrace(sessionId, "tool.call", { name: "AWS_SECRET_ACCESS_KEY", value: AWS_SECRET });
    sessionUploader.flushTrace(sessionId);
    await sessionUploader.stop();
    expect(JSON.stringify(uploads)).not.toContain(AWS_SECRET);
    const trace = uploads.find((item) => item.snapshot_type === "trace")!;
    expect(trace.trace?.find((event) => event.type === "tool.call")?.data).toEqual({ name: "AWS_SECRET_ACCESS_KEY", value: "[REDACTED]" });
  });

  test("JSON repeated keys are kept and scrubbed (test_json_repeated_keys_are_kept_and_scrubbed)", () => {
    const deep = `{"a": 1, "a": ${"[".repeat(600)}${"]".repeat(600)}}`;
    const cases: Array<[string, string]> = [
      ['{"a": "x@acme-mail.io", "a": "clean"}', '{"a":"[REDACTED_PII]","a":"clean"}'],
      [`{"a": "${GITHUB_TOKEN}", "a": "clean"}`, '{"a":"[REDACTED]","a":"clean"}'],
      ['{"password": "hunter2abc", "password": "x"}', '{"password":"[REDACTED]","password":"x"}'],
      [
        '{"list": [{"k": "hunter2abc", "k": 1, "password": "hunter2abc"}], "n": 1.5, "t": true, "z": null, "u": "\\u00e9 \\"q\\""}',
        '{"list":[{"k":"hunter2abc","k":1,"password":"[REDACTED]"}],"n":1.5,"t":true,"z":null,"u":"é \\"q\\""}',
      ],
      // Nothing to redact: byte-identical, repeated key and all.
      ['{"a": "clean", "a": "cleaner"}', '{"a": "clean", "a": "cleaner"}'],
      // Too deep for the structural scrub: the text scrub instead.
      [deep, deep],
      // A shadowed provider token, with nothing else to redact.
      [`{"token": "${GITHUB_TOKEN}", "token": ""}`, '{"token":"[REDACTED]","token":""}'],
    ];
    for (const [input, expected] of cases) {
      const output = redactUploadContent("a.json", input);
      expect(output).toBe(expected);
      JSON.parse(output);
    }
    // An indented document keeps its indentation, every pair and its empty containers.
    expect(redactUploadContent("a.json", '{\n  "x": {"password": "hunter2abc", "password": "y"},\n  "e": [],\n  "o": {}\n}\n'))
      .toBe('{\n  "x": {\n    "password": "[REDACTED]",\n    "password": "y"\n  },\n  "e": [],\n  "o": {}\n}\n');
    // A `__proto__` key stays an ordinary member.
    expect(redactUploadContent("a.json", '{"__proto__": {"password": "hunter2abc"}}')).toBe('{"__proto__":{"password":"[REDACTED]"}}');
  });

  test("a .patch file is scrubbed as source, and the envelope's git diff with each file's own mode", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-patch-"));
    roots.push(root);
    await git(root, "init", "-q");
    await mkdir(join(root, "app"), { recursive: true });
    await writeFile(join(root, "app", "settings.py"), "import config\n");
    await git(root, "add", "-A");
    await git(root, "commit", "-q", "-m", "initial");
    await writeFile(join(root, "app", "settings.py"), "import config\npassword = hunter2abc\n");
    await writeFile(join(root, "fix.patch"), PATCH);
    await writeFile(join(root, "notes.diff"), "+password = hunter2abc\n");
    const { uploads, upload } = makeUploads();
    const sessionUploader = new SessionUploader({ upload, fallbackScanMs: 60_000 });
    sessionUploader.startSession("session-patch-1", "workspace-patch", root);
    await sessionUploader.stop();

    const start = uploads.find((item) => item.snapshot_type === "start")!;
    const content = (path: string) => start.files.find((file) => file.path === path)?.content;
    // Workspace files: .py, .patch and .diff are source, so a bare name stays and a quoted literal goes.
    expect(content("app/settings.py")).toBe("import config\npassword = hunter2abc\n");
    expect(content("fix.patch")).toBe(PATCH.replace('"hunter2abc"', '"[REDACTED]"'));
    expect(content("notes.diff")).toBe("+password = hunter2abc\n");
    // The envelope's git diff scrubs the .py section as source, as the file itself.
    const gitBlock = start.workspace.git as { diff: string };
    expect(gitBlock.diff).toContain("+password = hunter2abc");
    expect(gitBlock.diff).not.toContain("[REDACTED]");
  });
});

// --- gateway auth: stale device tokens ---------------------------------------

describe("session uploader gateway auth", () => {
  type Warning = { message: string; attributes?: Record<string, unknown> };

  async function authHarness(respond: (attempt: number) => Response, refresh?: () => Promise<string | null>) {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-auth-"));
    const stateDir = await mkdtemp(join(tmpdir(), "omnirush-upload-auth-state-"));
    roots.push(root, stateDir);
    await writeFile(join(root, "app.txt"), "hello\n");
    const uploads: Envelope[] = [];
    const warnings: Warning[] = [];
    const counters = { attempts: 0, refreshes: 0 };
    const sessionUploader = new SessionUploader({
      stateDir,
      upload: async (_sessionId, compressed) => {
        counters.attempts += 1;
        const response = respond(counters.attempts);
        if (response.ok) uploads.push(withTraceEvents(JSON.parse(zstdDecompressSync(compressed).toString("utf8"))) as Envelope);
        return response;
      },
      ...(refresh
        ? {
            refreshAccessToken: async () => {
              counters.refreshes += 1;
              return refresh();
            },
          }
        : {}),
      log: (level, message, attributes) => { if (level === "warn") warnings.push({ message, attributes }); },
      fallbackScanMs: 60_000,
      uploadRetryDelayMs: 1,
      retryBaseMs: 60_000,
    });
    const sessionId = "session-auth-1234";
    sessionUploader.startSession(sessionId, "workspace-auth", root);
    await sessionUploader.idle(sessionId);
    const rejected = warnings.filter((warning) => warning.message === "OmniRush session upload rejected as unauthorized");
    return { sessionUploader, sessionId, uploads, warnings, rejected, counters };
  }

  const unauthorized = (status: number, body: unknown = { error: "token_expired" }) => Response.json(body, { status });
  const created = () => Response.json({ ok: true }, { status: 201 });

  test("refreshes the access token after a 401 and retries the upload once", async () => {
    const { sessionUploader, sessionId, uploads, rejected, counters } = await authHarness(
      (attempt) => (attempt === 1 ? unauthorized(401) : created()),
      async () => "fresh-token",
    );
    expect(counters).toEqual({ attempts: 2, refreshes: 1 });
    expect(uploads.map((item) => [item.snapshot_type, item.sequence])).toEqual([["start", 1]]);
    expect(await sessionUploader.spoolStatus()).toEqual({ entries: 0, bytes: 0 });
    expect(await sessionUploader.sessionDeliveryStatus(sessionId)).toMatchObject({ failureCount: 0 });
    expect(rejected).toEqual([{ message: "OmniRush session upload rejected as unauthorized", attributes: { sessionId, status: 401, refreshed: true } }]);
    await sessionUploader.stop();
  });

  test("sends the refreshed bearer when retrying over the session upload endpoint", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-auth-fetch-"));
    roots.push(root);
    await writeFile(join(root, "app.txt"), "hello\n");
    const bearers: string[] = [];
    const sessionUploader = new SessionUploader({
      gatewayUrl: "https://gateway.example.test/v1",
      accessToken: "stale-token",
      fetch: async (_input: string, init?: RequestInit) => {
        bearers.push(String(new Headers(init?.headers).get("authorization")));
        return bearers.length === 1 ? unauthorized(401) : created();
      },
      refreshAccessToken: async () => "fresh-token",
      fallbackScanMs: 60_000,
      uploadRetryDelayMs: 1,
    });
    const sessionId = "session-auth-fetch-1234";
    sessionUploader.startSession(sessionId, "workspace-auth", root);
    await sessionUploader.idle(sessionId);
    expect(bearers).toEqual(["Bearer stale-token", "Bearer fresh-token"]);
    await sessionUploader.stop();
    expect(bearers.at(-1)).toBe("Bearer fresh-token");
  });

  test("spools the upload when the gateway still rejects the refreshed token", async () => {
    const { sessionUploader, sessionId, uploads, warnings, rejected, counters } = await authHarness(() => unauthorized(401), async () => "fresh-token");
    expect(counters).toEqual({ attempts: 2, refreshes: 1 });
    expect(uploads).toHaveLength(0);
    expect(await sessionUploader.spoolStatus()).toMatchObject({ entries: 1 });
    expect(await sessionUploader.sessionDeliveryStatus(sessionId)).toMatchObject({ failureCount: 1, lastSuccessAt: null });
    expect(rejected).toHaveLength(1);
    expect(warnings.map((warning) => warning.message)).toContain("OmniRush session upload artifact spooled for retry");
    await sessionUploader.stop();
  });

  test("spools the upload when the token refresh fails", async () => {
    const { sessionUploader, sessionId, uploads, rejected, counters } = await authHarness(
      (attempt) => (attempt === 1 ? unauthorized(401) : created()),
      async () => { throw new Error("refresh endpoint unavailable"); },
    );
    expect(counters).toEqual({ attempts: 1, refreshes: 1 });
    expect(uploads).toHaveLength(0);
    expect(await sessionUploader.spoolStatus()).toMatchObject({ entries: 1 });
    expect(rejected).toEqual([{
      message: "OmniRush session upload rejected as unauthorized",
      attributes: { sessionId, status: 401, refreshed: false, refreshError: "refresh endpoint unavailable" },
    }]);
    await sessionUploader.stop();
  });

  test("spools the upload when no token refresh is available", async () => {
    const { sessionUploader, uploads, rejected, counters } = await authHarness((attempt) => (attempt === 1 ? unauthorized(401) : created()));
    expect(counters).toEqual({ attempts: 1, refreshes: 0 });
    expect(uploads).toHaveLength(0);
    expect(await sessionUploader.spoolStatus()).toMatchObject({ entries: 1 });
    expect(rejected[0]?.attributes).toMatchObject({ status: 401, refreshed: false });
    await sessionUploader.stop();
  });

  test("keeps the upload in the spool, without a refresh, while this device has no account (a sign-in the server retired)", async () => {
    for (const status of [403, 401]) {
      const { sessionUploader, sessionId, uploads, rejected, counters } = await authHarness(
        () => unauthorized(status, { error: "omnirush_account_required" }),
        async () => "fresh-token",
      );
      expect(counters).toEqual({ attempts: 1, refreshes: 0 });
      expect(uploads).toHaveLength(0);
      expect(rejected).toHaveLength(0);
      expect(await sessionUploader.spoolStatus()).toMatchObject({ entries: 1 });
      // A drain while the account is still gone keeps it too.
      await sessionUploader.drainSpool();
      expect(await sessionUploader.spoolStatus()).toMatchObject({ entries: 1 });
      await sessionUploader.stop();
    }
  });
});

// --- snapshot cap ------------------------------------------------------------

describe("session uploader snapshot cap", () => {
  const KIB = 1024;
  const CAP = 3 * 1024 * 1024; // leaves 1 MiB for content once the 2 MiB wrapper margin is reserved
  const NAMES = Array.from({ length: 20 }, (_, index) => `file-${String(index).padStart(2, "0")}.txt`);

  /** Twenty files growing by 8 KiB each, 1.6 MiB in all: more than CAP leaves for content. */
  async function largeWorkspace(): Promise<string> {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-cap-"));
    roots.push(root);
    const line = "alpha beta gamma delta\n";
    await Promise.all(NAMES.map((name, index) => writeFile(join(root, name), line.repeat(Math.ceil(((index + 1) * 8 * KIB) / line.length)))));
    return root;
  }

  async function capture(root: string, options: {
    snapshotMaxBytes?: number;
    touched?: string[];
    traceEvents?: Array<{ type: string; data: unknown }>;
  }) {
    const uploads: Envelope[] = [];
    const rawBytes: number[] = [];
    const warnings: string[] = [];
    const sessionUploader = new SessionUploader({
      upload: async (_sessionId, compressed) => {
        const buffer = zstdDecompressSync(compressed);
        rawBytes.push(buffer.length);
        uploads.push(withTraceEvents(JSON.parse(buffer.toString("utf8")) as Envelope));
        return Response.json({ ok: true }, { status: 201 });
      },
      log: (level, message) => { if (level === "warn") warnings.push(message); },
      fallbackScanMs: 60_000,
      ...(options.snapshotMaxBytes ? { snapshotMaxBytes: options.snapshotMaxBytes } : {}),
    });
    const sessionId = "session-cap-1234";
    sessionUploader.startSession(sessionId, "workspace-cap", root);
    for (const path of options.touched ?? []) sessionUploader.recordTrace(sessionId, "file.read", { path });
    for (const event of options.traceEvents ?? []) sessionUploader.recordTrace(sessionId, event.type, event.data);
    sessionUploader.flushTrace(sessionId);
    await sessionUploader.stop();
    const start = uploads.find((item) => item.snapshot_type === "start")!;
    const startBytes = rawBytes[uploads.indexOf(start)]!;
    const sent = start.files.map((file) => file.path).filter((path) => !path.startsWith("__omnirush__/"));
    const manifestPaths = start.manifest.map((entry) => entry.path);
    const size = (path: string) => start.manifest.find((entry) => entry.path === path)!.size;
    const notes = uploads
      .filter((item) => item.snapshot_type === "trace")
      .flatMap((item) => item.trace ?? [])
      .filter((event) => event.type === "collector.snapshot_cap");
    return { start, startBytes, sent, manifestPaths, size, notes, warnings };
  }

  test("keeps touched files and the smallest others when a snapshot would exceed the cap", async () => {
    const root = await largeWorkspace();
    const touched = ["file-19.txt", "file-17.txt"];
    const { start, startBytes, sent, manifestPaths, size, notes, warnings } = await capture(root, { snapshotMaxBytes: CAP, touched });
    expect(startBytes).toBeLessThan(CAP);
    expect([...manifestPaths].sort()).toEqual(NAMES);
    for (const path of touched) expect(sent).toContain(path);
    const omitted = NAMES.filter((path) => !sent.includes(path));
    expect(omitted.length).toBeGreaterThan(0);
    expect(sent.length).toBeGreaterThan(touched.length);
    // Untouched content survives smallest first: nothing sent outranks anything omitted.
    const untouchedSent = sent.filter((path) => !touched.includes(path));
    expect(Math.max(...untouchedSent.map(size))).toBeLessThan(Math.min(...omitted.map(size)));
    // files[] keeps the listing order the manifest uses.
    expect(sent).toEqual(manifestPaths.filter((path) => sent.includes(path)));
    expect(start.privacy).toMatchObject({
      files_truncated: true,
      snapshot_cap_omitted_count: omitted.length,
      snapshot_cap_omitted_bytes: omitted.reduce((sum, path) => sum + size(path), 0),
    });
    expect(warnings.filter((message) => message === "OmniRush session upload snapshot trimmed to the snapshot cap")).toHaveLength(1);
    expect(notes).toHaveLength(1);
    expect(notes[0]).toMatchObject({ data: { snapshot_type: "start", trigger: "session_start", omitted_count: omitted.length } });
    expect(notes[0]?.data?.budget_bytes).toBeLessThan(CAP);
  });

  test("prioritizes paths from real engine tool messages, including nested apply_patch input", async () => {
    const root = await largeWorkspace();
    const traceEvents = [{
      type: "turn.messages",
      data: {
        messages: [{
          parts: [
            { type: "tool", tool: "edit", state: { input: { path: "file-19.txt" } } },
            { type: "tool", tool: "apply_patch", state: { input: { patch: "*** Update File: file-17.txt\n@@\n-old\n+new\n" } } },
            { type: "tool", tool: "read", state: { input: { filePath: "file-18.txt" } } },
          ],
        }],
      },
    }];
    const { start, sent } = await capture(root, { snapshotMaxBytes: CAP, traceEvents });
    for (const path of ["file-17.txt", "file-18.txt", "file-19.txt"]) {
      expect(start.touched_paths).toContain(path);
      expect(sent).toContain(path);
    }
  });

  test("keeps the smallest touched files when the touched files alone exceed the cap", async () => {
    const root = await largeWorkspace();
    const { startBytes, sent, size, start } = await capture(root, { snapshotMaxBytes: CAP, touched: NAMES });
    expect(startBytes).toBeLessThan(CAP);
    const omitted = NAMES.filter((path) => !sent.includes(path));
    expect(omitted.length).toBeGreaterThan(0);
    expect(sent.length).toBeGreaterThan(0);
    expect(Math.max(...sent.map(size))).toBeLessThan(Math.min(...omitted.map(size)));
    expect(start.privacy).toMatchObject({ snapshot_cap_omitted_count: omitted.length });
  });

  test("leaves a snapshot under the cap unchanged", async () => {
    const root = await largeWorkspace();
    const { start, sent, manifestPaths, notes, warnings } = await capture(root, { touched: ["file-19.txt"] });
    expect(sent).toEqual(manifestPaths);
    expect([...sent].sort()).toEqual(NAMES);
    expect(start.privacy).toMatchObject({ files_truncated: false, snapshot_cap_omitted_count: 0, snapshot_cap_omitted_bytes: 0 });
    expect(notes).toHaveLength(0);
    expect(warnings).not.toContain("OmniRush session upload snapshot trimmed to the snapshot cap");
  });
});

// --- incremental snapshots, watcher discipline and memory --------------------

describe("session uploader incremental snapshots", () => {
  const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

  /** A git workspace with tracked sources, a dependency tree and gitignored build output. */
  async function workspace(prefix: string, sourceFiles = 30): Promise<string> {
    const root = await mkdtemp(join(tmpdir(), `omnirush-upload-${prefix}-`));
    roots.push(root);
    await git(root, "init", "-q");
    await writeFile(join(root, ".gitignore"), "dist/\nnode_modules/\n");
    await mkdir(join(root, "src", "lib"), { recursive: true });
    await mkdir(join(root, "node_modules", "pkg"), { recursive: true });
    await mkdir(join(root, "dist"), { recursive: true });
    for (let index = 0; index < sourceFiles; index += 1) {
      await writeFile(join(root, "src", index % 2 ? "lib" : "", `f${String(index).padStart(2, "0")}.txt`), `source file ${index}\n`);
    }
    await writeFile(join(root, "README.md"), "# readme\n");
    await writeFile(join(root, "node_modules", "pkg", "index.js"), "module.exports = 1;\n");
    await writeFile(join(root, "dist", "bundle.js"), "bundled\n");
    await git(root, "add", "-A");
    await git(root, "commit", "-q", "-m", "init");
    return root;
  }

  const contentPaths = (envelope: Envelope) => envelope.files.map((file) => file.path).filter((path) => !path.startsWith("__omnirush__/"));
  const changes = (uploads: Envelope[]) => uploads.filter((item) => item.snapshot_type === "change");
  const triggerEvents = (uploads: Envelope[]) => uploads
    .filter((item) => item.snapshot_type === "trace")
    .flatMap((item) => item.trace ?? [])
    .filter((event) => event.type === "collector.trigger")
    .map((event) => event.data);

  test("mapBounded keeps at most `limit` operations in flight and returns results in order", async () => {
    let inFlight = 0;
    let peak = 0;
    const items = Array.from({ length: 50 }, (_, index) => index);
    const results = await mapBounded(items, 8, async (item) => {
      inFlight += 1;
      peak = Math.max(peak, inFlight);
      await sleep(1 + (item % 3));
      inFlight -= 1;
      return item * 2;
    });
    expect(results).toEqual(items.map((item) => item * 2));
    expect(peak).toBe(8);
    expect(await mapBounded([1, 2], 8, async (item) => item)).toEqual([1, 2]);
    expect(await mapBounded([], 8, async (item: number) => item)).toEqual([]);
  });

  test("a change snapshot reads only the changed file and reuses digests across sessions on one root", async () => {
    const root = await workspace("cache");
    const { uploads, upload } = makeUploads();
    const sessionUploader = new SessionUploader({ upload, changeDebounceMs: 60_000, fallbackScanMs: 60_000 });
    const first = "session-cache-first-1";
    sessionUploader.startSession(first, "workspace-cache", root);
    await sessionUploader.idle(first);
    const afterStart = { ...sessionUploader.metrics };
    expect(afterStart.fullScans).toBe(1);
    expect(afterStart.fileReads).toBeGreaterThanOrEqual(31);

    await writeFile(join(root, "src", "f06.txt"), "source file 6, edited\n");
    sessionUploader.captureSnapshot(first, "turn_completed");
    await sessionUploader.idle(first);
    const afterChange = { ...sessionUploader.metrics };
    const change = changes(uploads)[0]!;
    expect(contentPaths(change)).toEqual(["src/f06.txt"]);
    expect(change.files_scope).toBe("changed");
    expect(change.changed_paths).toEqual(["src/f06.txt"]);
    expect(change.manifest).toHaveLength(32);
    expect(change.manifest.find((entry) => entry.path === "src/f06.txt")?.sha256).toBe(sha256("source file 6, edited\n"));
    // One dirty-path scan: the journal read, the scan read and the upload read of that one file, no listing pass.
    expect(afterChange.fullScans).toBe(1);
    expect(afterChange.dirtyScans).toBe(1);
    expect(afterChange.fileReads - afterStart.fileReads).toBeLessThanOrEqual(3);
    expect(afterChange.fileStats - afterStart.fileStats).toBeLessThanOrEqual(3);

    // A second chat on the same workspace starts from the shared cache: a stat per file, no reads.
    const second = "session-cache-second-1";
    sessionUploader.startSession(second, "workspace-cache", root);
    await sessionUploader.idle(second);
    const afterSecond = { ...sessionUploader.metrics };
    expect(afterSecond.fullScans).toBe(2);
    const secondStart = uploads.find((item) => item.snapshot_type === "start" && item.session_id === second)!;
    expect(secondStart.files_scope).toBe("full");
    expect(contentPaths(secondStart)).toHaveLength(32);
    // The scan read nothing; the only reads are the upload pass sending each
    // file as it is on disk, verified by digest, without the regex pipeline.
    expect(afterSecond.fileReads - afterChange.fileReads).toBe(32);
    expect(afterSecond.fileRedactions - afterChange.fileRedactions).toBe(0);
    expect(sessionUploader.cacheStatus()).toEqual({ roots: 1, entries: 32 });
    await sessionUploader.stop();
    expect(sessionUploader.cacheStatus()).toEqual({ roots: 0, entries: 0 });
  });

  test.skipIf(process.platform === "win32")("detects a same-size replacement after the old mtime is restored", async () => {
    const root = await workspace("signature", 1);
    const target = join(root, "src", "f00.txt");
    const { uploads, upload } = makeUploads();
    const sessionUploader = new SessionUploader({ upload, changeDebounceMs: 60_000, fallbackScanMs: 60_000 });
    const sessionId = "session-signature-1234";
    sessionUploader.startSession(sessionId, "workspace-signature", root);
    await sessionUploader.idle(sessionId);
    const before = await stat(target);
    const original = await readFile(target);
    const replacement = Buffer.from(original);
    replacement[0] = replacement[0] === 115 ? 116 : 115;
    await writeFile(target, replacement);
    await utimes(target, before.atime, before.mtime);
    sessionUploader.captureSnapshot(sessionId, "turn_completed");
    await sessionUploader.idle(sessionId);

    const change = changes(uploads)[0]!;
    expect(contentPaths(change)).toEqual(["src/f00.txt"]);
    expect(change.files.find((file) => file.path === "src/f00.txt")?.content).toBe(replacement.toString("utf8"));
    expect(change.changed_paths).toEqual(["src/f00.txt"]);
    await sessionUploader.stop();
  });

  test("skips a milestone capture outright when nothing is dirty, and rescans after a new directory appears", async () => {
    const root = await workspace("dirty", 10);
    const { uploads, upload } = makeUploads();
    const sessionUploader = new SessionUploader({ upload, changeDebounceMs: 60_000, fallbackScanMs: 60_000 });
    const sessionId = "session-dirty-1234";
    sessionUploader.startSession(sessionId, "workspace-dirty", root);
    await sessionUploader.idle(sessionId);
    expect(sessionUploader.sessionDiagnostics(sessionId)).toMatchObject({ watchMode: "watching", dirtyPaths: 0, dirtyOverflow: false });
    const before = { ...sessionUploader.metrics };
    sessionUploader.captureSnapshot(sessionId, "turn_completed");
    sessionUploader.captureSnapshot(sessionId, "prompt");
    await sessionUploader.idle(sessionId);
    const after = { ...sessionUploader.metrics };
    expect(after.capturesSkipped - before.capturesSkipped).toBe(2);
    expect(after.fileStats - before.fileStats).toBe(0);
    expect(after.fullScans + after.dirtyScans).toBe(before.fullScans + before.dirtyScans);
    expect(changes(uploads)).toHaveLength(0);

    // Files inside a directory that appears whole arrive without events of
    // their own: the rename of the directory taints the dirty set and the next
    // capture rescans the tree.
    await mkdir(join(root, "feature"));
    await writeFile(join(root, "feature", "new.txt"), "brand new\n");
    await sleep(150);
    expect(sessionUploader.sessionDiagnostics(sessionId)?.dirtyOverflow).toBe(true);
    sessionUploader.captureSnapshot(sessionId, "turn_completed");
    await sessionUploader.idle(sessionId);
    expect(sessionUploader.metrics.fullScans).toBe(before.fullScans + 1);
    expect(contentPaths(changes(uploads)[0]!)).toEqual(["feature/new.txt"]);
    expect(sessionUploader.sessionDiagnostics(sessionId)?.watchedPaths).toContain("feature");
    sessionUploader.flushTrace(sessionId);
    await sessionUploader.stop();
    expect(triggerEvents(uploads)).toEqual([
      { trigger: "turn_completed", captured: false },
      { trigger: "prompt", captured: false },
      { trigger: "turn_completed", captured: true },
    ]);
  });

  test("watches only directories with eligible files, batches ignore checks and polls past the watched-files cap", async () => {
    const root = await workspace("watch", 6);
    const { uploads, upload } = makeUploads();
    const sessionUploader = new SessionUploader({ upload, changeDebounceMs: 10, fallbackScanMs: 60_000 });
    const sessionId = "session-watch-1234";
    sessionUploader.startSession(sessionId, "workspace-watch", root);
    await sessionUploader.idle(sessionId);
    expect(sessionUploader.sessionDiagnostics(sessionId)?.watchedPaths.sort()).toEqual([".", "src"]);
    const before = { ...sessionUploader.metrics };
    // Churn in the dependency tree and in gitignored output never reaches a callback.
    for (let index = 0; index < 200; index += 1) {
      await writeFile(join(root, "node_modules", "pkg", `churn-${index}.js`), `// ${index}\n`);
      await writeFile(join(root, "dist", `chunk-${index}.js`), `// ${index}\n`);
    }
    await sleep(250);
    await sessionUploader.idle(sessionId);
    expect(sessionUploader.metrics.watchEvents - before.watchEvents).toBe(0);
    expect(sessionUploader.metrics.ignoreCheckSpawns - before.ignoreCheckSpawns).toBe(0);
    expect(changes(uploads)).toHaveLength(0);
    await sessionUploader.stop();
    expect(JSON.stringify(uploads)).not.toContain("churn-");
    expect(JSON.stringify(uploads)).not.toContain("chunk-");

    // New files are put to git's ignore rules in one spawn per burst, not one
    // per file (the production debounce is 2 s).
    const batched = makeUploads();
    const batcher = new SessionUploader({ upload: batched.upload, changeDebounceMs: 60_000, fallbackScanMs: 60_000 });
    const batchedId = "session-batched-1234";
    batcher.startSession(batchedId, "workspace-batched", root);
    await batcher.idle(batchedId);
    await writeFile(join(root, ".gitignore"), "dist/\nnode_modules/\n*.log\n");
    await sleep(120);
    const beforeBurst = batcher.metrics.ignoreCheckSpawns;
    for (let index = 0; index < 20; index += 1) await writeFile(join(root, `scratch-${index}.log`), `log ${index}\n`);
    await writeFile(join(root, "kept.txt"), "kept\n");
    await sleep(150);
    batcher.captureSnapshot(batchedId, "turn_completed");
    await batcher.idle(batchedId);
    // One spawn for the burst (two if it straddles a batch window), and one
    // fresh answer for everything the snapshot is about to carry.
    expect(batcher.metrics.ignoreCheckSpawns - beforeBurst).toBeLessThanOrEqual(3);
    const batchedChange = changes(batched.uploads).at(-1)!;
    expect(contentPaths(batchedChange)).toContain("kept.txt");
    expect(batchedChange.manifest.map((entry) => entry.path)).not.toContain("scratch-0.log");
    await batcher.stop();
    // Only excluded_files may name an ignored file (as left out, with no content).
    const withoutExclusions = batched.uploads.map((envelope) => ({ ...envelope, excluded_files: undefined }));
    expect(JSON.stringify(withoutExclusions)).not.toContain("scratch-");
    const listed = batched.uploads.flatMap((envelope) => (((envelope as Record<string, unknown>).excluded_files as { entries?: Array<{ path: string; reason: string }> } | undefined)?.entries ?? []));
    expect(listed.filter((entry) => entry.path.startsWith("scratch-")).every((entry) => entry.reason === "gitignored")).toBe(true);

    // Past the cap the tree is polled: no watchers, and a milestone rescans it.
    const polled = makeUploads();
    const poller = new SessionUploader({ upload: polled.upload, changeDebounceMs: 60_000, fallbackScanMs: 60_000, maxWatchedFiles: 3 });
    const polledId = "session-polled-1234";
    poller.startSession(polledId, "workspace-polled", root);
    await poller.idle(polledId);
    expect(poller.sessionDiagnostics(polledId)).toMatchObject({ watchMode: "polling", watchedPaths: [], dirtyOverflow: true });
    await writeFile(join(root, "src", "f01.txt"), "source file 1, polled edit\n");
    poller.captureSnapshot(polledId, "turn_completed");
    await poller.idle(polledId);
    expect(poller.metrics.fullScans).toBe(2);
    expect(contentPaths(changes(polled.uploads)[0]!)).toEqual(["src/f01.txt"]);
    await poller.stop();
  });

  test("labels snapshot scope and re-sends changes the gateway never accepted", async () => {
    const root = await workspace("scope", 4);
    const stateDir = await mkdtemp(join(tmpdir(), "omnirush-upload-scope-state-"));
    roots.push(stateDir);
    let status = 201;
    const uploads: Envelope[] = [];
    const sessionUploader = new SessionUploader({
      stateDir,
      upload: async (_sessionId, compressed) => {
        if (status !== 201) return Response.json({ error: "rejected" }, { status });
        uploads.push(withTraceEvents(JSON.parse(zstdDecompressSync(compressed).toString("utf8"))) as Envelope);
        return Response.json({ ok: true }, { status: 201 });
      },
      changeDebounceMs: 60_000,
      fallbackScanMs: 60_000,
    });
    const sessionId = "session-scope-1234";
    sessionUploader.startSession(sessionId, "workspace-scope", root);
    await sessionUploader.idle(sessionId);
    expect(uploads[0]).toMatchObject({ snapshot_type: "start", files_scope: "full" });
    expect(uploads[0]).not.toHaveProperty("changed_paths");

    await writeFile(join(root, "src", "f00.txt"), "rejected edit\n");
    status = 400;
    sessionUploader.captureSnapshot(sessionId, "turn_completed");
    await sessionUploader.idle(sessionId);
    expect(changes(uploads)).toHaveLength(0);
    status = 201;
    sessionUploader.captureSnapshot(sessionId, "turn_completed");
    await sessionUploader.idle(sessionId);
    const resent = changes(uploads)[0]!;
    expect(contentPaths(resent)).toEqual(["src/f00.txt"]);
    expect(resent.changed_paths).toEqual(["src/f00.txt"]);
    expect(resent.files_scope).toBe("changed");

    sessionUploader.flushTrace(sessionId);
    await sessionUploader.stop();
    const end = uploads.find((item) => item.snapshot_type === "end")!;
    expect(end.files_scope).toBe("changed");
    expect(end.changed_paths).toEqual([]);
    expect(uploads.find((item) => item.snapshot_type === "trace")?.files_scope).toBe("full");
    // Envelopes are streamed through a temp file that never outlives the upload.
    expect((await readdir(join(stateDir, "omnirush-upload-tmp")).catch(() => [])).filter((name) => name.endsWith(".tmp"))).toEqual([]);
    expect(sessionUploader.sessionDiagnostics(sessionId)).toBeNull();
  });

  test("spaces filesystem-driven change snapshots by the minimum interval while milestones capture at once", async () => {
    const root = await workspace("interval", 4);
    const { uploads, upload } = makeUploads();
    const sessionUploader = new SessionUploader({ upload, changeDebounceMs: 10, fallbackScanMs: 60_000, minChangeIntervalMs: 500 });
    const sessionId = "session-interval-1234";
    sessionUploader.startSession(sessionId, "workspace-interval", root);
    await sessionUploader.idle(sessionId);
    await writeFile(join(root, "src", "f00.txt"), "first burst\n");
    await sleep(120);
    await sessionUploader.idle(sessionId);
    expect(changes(uploads)).toHaveLength(1);
    const firstAt = Date.parse(changes(uploads)[0]!.captured_at as string);
    // Two edits inside the window merge into one deferred snapshot.
    await writeFile(join(root, "src", "f01.txt"), "second burst a\n");
    await sleep(60);
    await writeFile(join(root, "src", "f02.txt"), "second burst b\n");
    await sleep(120);
    await sessionUploader.idle(sessionId);
    expect(changes(uploads)).toHaveLength(1);
    expect(sessionUploader.metrics.capturesDeferred).toBeGreaterThanOrEqual(1);
    await sleep(500);
    await sessionUploader.idle(sessionId);
    expect(changes(uploads)).toHaveLength(2);
    expect(contentPaths(changes(uploads)[1]!).sort()).toEqual(["src/f01.txt", "src/f02.txt"]);
    expect(Date.parse(changes(uploads)[1]!.captured_at as string) - firstAt).toBeGreaterThanOrEqual(450);
    // A turn milestone inside the window is not held back.
    await writeFile(join(root, "src", "f03.txt"), "milestone edit\n");
    sessionUploader.captureSnapshot(sessionId, "turn_completed");
    await sessionUploader.idle(sessionId);
    expect(changes(uploads)).toHaveLength(3);
    expect(contentPaths(changes(uploads)[2]!)).toEqual(["src/f03.txt"]);
    await sessionUploader.stop();
  });

  test("neither watches nor rescans a rebuilt gitignored directory, and rescans once .gitignore changes", async () => {
    const root = await workspace("ignored", 6);
    const { uploads, upload } = makeUploads();
    const sessionUploader = new SessionUploader({ upload, changeDebounceMs: 60_000, fallbackScanMs: 60_000 });
    const sessionId = "session-ignored-1234";
    sessionUploader.startSession(sessionId, "workspace-ignored", root);
    await sessionUploader.idle(sessionId);
    const before = { ...sessionUploader.metrics };
    // A build that wipes and recreates its gitignored output directory.
    await rm(join(root, "dist"), { recursive: true, force: true });
    await mkdir(join(root, "dist"));
    await writeFile(join(root, "dist", "bundle.js"), "rebuilt\n");
    await sleep(200);
    expect(sessionUploader.sessionDiagnostics(sessionId)).toMatchObject({ dirtyOverflow: false });
    expect(sessionUploader.sessionDiagnostics(sessionId)?.watchedPaths).not.toContain("dist");
    sessionUploader.captureSnapshot(sessionId, "turn_completed");
    await sessionUploader.idle(sessionId);
    expect(sessionUploader.metrics.fullScans).toBe(before.fullScans);
    expect(changes(uploads)).toHaveLength(0);

    // An untracked log goes out; a new ignore rule then hides it, and the
    // edit to .gitignore makes the next capture rescan the tree under it.
    await writeFile(join(root, "notes.log"), "scratch notes\n");
    await sleep(150);
    sessionUploader.captureSnapshot(sessionId, "turn_completed");
    await sessionUploader.idle(sessionId);
    expect(changes(uploads).at(-1)!.manifest.map((entry) => entry.path)).toContain("notes.log");
    await writeFile(join(root, ".gitignore"), "dist/\nnode_modules/\n*.log\n");
    await sleep(150);
    expect(sessionUploader.sessionDiagnostics(sessionId)?.dirtyOverflow).toBe(true);
    sessionUploader.captureSnapshot(sessionId, "turn_completed");
    await sessionUploader.idle(sessionId);
    const last = changes(uploads).at(-1)!;
    expect(sessionUploader.metrics.fullScans).toBe(before.fullScans + 1);
    expect(last.manifest.map((entry) => entry.path)).not.toContain("notes.log");
    expect(last.changed_paths).toEqual([".gitignore"]);
    await sessionUploader.stop();
  });

  test("drops the files of a directory moved out of the workspace without rescanning the tree", async () => {
    const root = await workspace("moved", 10);
    const outside = await mkdtemp(join(tmpdir(), "omnirush-upload-moved-out-"));
    roots.push(outside);
    const { uploads, upload } = makeUploads();
    const sessionUploader = new SessionUploader({ upload, changeDebounceMs: 60_000, fallbackScanMs: 60_000 });
    const sessionId = "session-moved-1234";
    sessionUploader.startSession(sessionId, "workspace-moved", root);
    await sessionUploader.idle(sessionId);
    const before = { ...sessionUploader.metrics };
    // One event for the directory, none for the five files inside it.
    await rename(join(root, "src", "lib"), join(outside, "lib"));
    await sleep(200);
    sessionUploader.captureSnapshot(sessionId, "turn_completed");
    await sessionUploader.idle(sessionId);
    const change = changes(uploads)[0]!;
    const paths = change.manifest.map((entry) => entry.path);
    expect(paths.filter((path) => path.startsWith("src/lib/"))).toEqual([]);
    expect(paths).toContain("src/f00.txt");
    expect(sessionUploader.metrics.fullScans).toBe(before.fullScans);
    expect(sessionUploader.metrics.dirtyScans).toBe(before.dirtyScans + 1);
    await sessionUploader.stop();
  });

  test("polls a workspace with more top-level directories than it watches", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-wide-"));
    roots.push(root);
    for (let index = 0; index < 65; index += 1) {
      await mkdir(join(root, `dir${index}`));
      await writeFile(join(root, `dir${index}`, "a.txt"), `file ${index}\n`);
    }
    const { upload } = makeUploads();
    const sessionUploader = new SessionUploader({ upload, changeDebounceMs: 60_000, fallbackScanMs: 60_000 });
    const sessionId = "session-wide-1234";
    sessionUploader.startSession(sessionId, "workspace-wide", root);
    await sessionUploader.idle(sessionId);
    expect(sessionUploader.sessionDiagnostics(sessionId)).toMatchObject({ watchMode: "polling", watchedPaths: [], dirtyOverflow: true });
    await sessionUploader.stop();
  });

  test("keeps a file larger than the change journal out of it, and still snapshots the file", async () => {
    const root = await workspace("journal", 4);
    const { uploads, upload } = makeUploads();
    const sessionUploader = new SessionUploader({ upload, changeDebounceMs: 60_000, fallbackScanMs: 60_000 });
    const sessionId = "session-journal-1234";
    sessionUploader.startSession(sessionId, "workspace-journal", root);
    await sessionUploader.idle(sessionId);
    await writeFile(join(root, "src", "small.txt"), "small edit\n");
    await writeFile(join(root, "src", "large.txt"), "large log line\n".repeat(70_000));
    await sleep(200);
    sessionUploader.captureSnapshot(sessionId, "turn_completed");
    await sessionUploader.idle(sessionId);
    const change = changes(uploads)[0]!;
    expect(contentPaths(change).sort()).toEqual(["src/large.txt", "src/small.txt"]);
    const journal = change.files.find((file) => file.path === "__omnirush__/changes.json")!;
    expect(journal.content).toContain('"path":"src/small.txt"');
    expect(journal.content).not.toContain("src/large.txt");
    await sessionUploader.stop();
  });

  test("runs one reconcile pass per interval for every session on a root, and it finds what no watcher reported", async () => {
    const root = await workspace("reconcile", 4);
    // Every watcher slot is taken, so assets/, which held no file at the start, gets none.
    await fillWatchSlots(root);
    await mkdir(join(root, "assets"));
    const { uploads, upload } = makeUploads();
    const sessionUploader = new SessionUploader({ upload, changeDebounceMs: 10, fallbackScanMs: 300, minChangeIntervalMs: 0 });
    const sessions = ["session-reconcile-a1", "session-reconcile-b1"];
    for (const sessionId of sessions) sessionUploader.startSession(sessionId, "workspace-reconcile", root);
    for (const sessionId of sessions) await sessionUploader.idle(sessionId);
    expect(sessionUploader.sessionDiagnostics(sessions[0]!)).toMatchObject({ watchMode: "watching" });
    expect(sessionUploader.sessionDiagnostics(sessions[0]!)?.watchedPaths).toHaveLength(65);
    expect(sessionUploader.sessionDiagnostics(sessions[0]!)?.watchedPaths).not.toContain("assets");
    const before = sessionUploader.metrics.reconciles;
    await writeFile(join(root, "assets", "found.txt"), "found by the reconcile pass\n");
    await sleep(1_000);
    for (const sessionId of sessions) await sessionUploader.idle(sessionId);
    const passes = sessionUploader.metrics.reconciles - before;
    // About three passes in a second at a 300 ms interval; per-session passes would make six.
    expect(passes).toBeGreaterThanOrEqual(1);
    expect(passes).toBeLessThanOrEqual(4);
    for (const sessionId of sessions) {
      const change = changes(uploads).find((item) => item.session_id === sessionId);
      expect(change && contentPaths(change)).toEqual(["assets/found.txt"]);
    }
    await sessionUploader.stop();
  });

  test("two chats on one folder: only the one running a turn uploads the edits made meanwhile, and each still captures its own milestones", async () => {
    const root = await workspace("shared", 4);
    const { uploads, upload } = makeUploads();
    const sessionUploader = new SessionUploader({ upload, changeDebounceMs: 10, fallbackScanMs: 150, minChangeIntervalMs: 0 });
    const working = "session-shared-working-1";
    const idle = "session-shared-idle-0001";
    const both = [working, idle];
    for (const sessionId of both) sessionUploader.startSession(sessionId, "workspace-shared", root);
    for (const sessionId of both) await sessionUploader.idle(sessionId);
    const settle = async () => {
      // Past the debounce and several reconcile passes.
      await sleep(600);
      for (const sessionId of both) await sessionUploader.idle(sessionId);
    };
    const changesOf = (sessionId: string) => changes(uploads)
      .filter((item) => item.session_id === sessionId)
      .map((item) => [item.trigger, contentPaths(item).sort()]);
    // Whichever of the watcher and the reconcile pass saw the edit first.
    const edit = expect.stringMatching(/^(?:fs_change|periodic)$/);

    sessionUploader.captureSnapshot(working, "prompt");
    await sessionUploader.idle(working);
    await writeFile(join(root, "src", "f00.txt"), "the agent's edit\n");
    await settle();
    expect(changesOf(working)).toEqual([[edit, ["src/f00.txt"]]]);
    expect(changesOf(idle)).toEqual([]);
    expect(sessionUploader.metrics.capturesHeld).toBeGreaterThan(0);

    // The turn ends: the other chat still leaves that turn's edits alone, reconcile passes included.
    sessionUploader.captureSnapshot(working, "turn_completed");
    await settle();
    expect(changesOf(idle)).toEqual([]);

    // An edit between turns is uploaded once, by the chat that ran the last turn.
    await writeFile(join(root, "README.md"), "# edited by hand\n");
    await settle();
    expect(changesOf(working).at(-1)).toEqual([edit, ["README.md"]]);
    expect(changesOf(idle)).toEqual([]);

    // The other chat's own prompt carries what it has not sent yet; while it
    // runs its turn, the first chat holds back in turn.
    sessionUploader.captureSnapshot(idle, "prompt");
    await sessionUploader.idle(idle);
    expect(changesOf(idle)).toEqual([["prompt", ["README.md", "src/f00.txt"]]]);
    const sentByWorking = changesOf(working).length;
    await writeFile(join(root, "src", "f02.txt"), "the other agent's edit\n");
    await settle();
    expect(changesOf(idle).at(-1)).toEqual([edit, ["src/f02.txt"]]);
    expect(changesOf(working)).toHaveLength(sentByWorking);
    sessionUploader.captureSnapshot(idle, "turn_completed");
    await sessionUploader.idle(idle);
    for (const sessionId of both) sessionUploader.flushTrace(sessionId);
    await sessionUploader.stop();
    for (const sessionId of both) {
      const milestones = uploads
        .filter((item) => item.snapshot_type === "trace" && item.session_id === sessionId)
        .flatMap((item) => item.trace ?? [])
        .filter((event) => event.type === "collector.trigger")
        .map((event) => event.data?.trigger);
      expect(milestones).toEqual(["prompt", "turn_completed"]);
    }
  });

  test("keeps gitignored files out of change snapshots and the journal in a workspace git does not manage", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-nogit-"));
    roots.push(root);
    await writeFile(join(root, ".gitignore"), "*.log\nbuild/\n");
    await mkdir(join(root, "src"));
    await writeFile(join(root, "src", "a.txt"), "a\n");
    const { uploads, upload } = makeUploads();
    const sessionUploader = new SessionUploader({ upload, changeDebounceMs: 60_000, fallbackScanMs: 60_000 });
    const sessionId = "session-nogit-1234";
    sessionUploader.startSession(sessionId, "workspace-nogit", root);
    await sessionUploader.idle(sessionId);
    // git answers nothing here: the watcher-reported paths go through the
    // .gitignore files the listing walker applies.
    await writeFile(join(root, "src", "debug.log"), "debug output\n");
    await mkdir(join(root, "build"));
    await writeFile(join(root, "build", "out.txt"), "build output\n");
    await writeFile(join(root, "src", "b.txt"), "b\n");
    await sleep(200);
    sessionUploader.captureSnapshot(sessionId, "turn_completed");
    await sessionUploader.idle(sessionId);
    const change = changes(uploads)[0]!;
    expect(contentPaths(change)).toEqual(["src/b.txt"]);
    expect(change.manifest.map((entry) => entry.path).sort()).toEqual([".gitignore", "src/a.txt", "src/b.txt"]);
    await sessionUploader.stop();
    expect(JSON.stringify(uploads)).not.toContain("debug.log");
    expect(JSON.stringify(uploads)).not.toContain("out.txt");
  });

  /** src/ plus 63 more top-level directories with files: every watcher slot taken. */
  async function fillWatchSlots(root: string): Promise<void> {
    for (let index = 0; index < 63; index += 1) {
      const directory = join(root, `d${String(index).padStart(2, "0")}`);
      await mkdir(directory);
      await writeFile(join(directory, "a.txt"), `file ${index}\n`);
    }
  }

  test("watches the top-level directories the listing did not name, unless git ignores or the denylist names them", async () => {
    const root = await workspace("unlisted", 4);
    await mkdir(join(root, "config"));
    await writeFile(join(root, "config", ".env"), "API=1\n"); // denied, so config/ lists nothing
    await mkdir(join(root, "scripts")); // empty
    await mkdir(join(root, "secrets")); // a denied name
    const { uploads, upload } = makeUploads();
    const sessionUploader = new SessionUploader({ upload, changeDebounceMs: 10, fallbackScanMs: 60_000, minChangeIntervalMs: 0 });
    const sessionId = "session-unlisted-1234";
    sessionUploader.startSession(sessionId, "workspace-unlisted", root);
    await sessionUploader.idle(sessionId);
    // Not dist/ (gitignored), node_modules/, secrets/ or .git/ (denied).
    expect(sessionUploader.sessionDiagnostics(sessionId)?.watchedPaths.sort()).toEqual([".", "config", "scripts", "src"]);
    // Another editor writes next to the denied file: the watcher sees it at once.
    await writeFile(join(root, "config", "app.yml"), "mode: production\n");
    await sleep(300);
    await sessionUploader.idle(sessionId);
    const change = changes(uploads)[0]!;
    expect(change.trigger).toBe("fs_change");
    expect(contentPaths(change)).toEqual(["config/app.yml"]);
    await sessionUploader.stop();
    expect(JSON.stringify(uploads)).not.toContain("API=1");
  });

  test("a turn's writes where no watcher reaches still land in that turn's change snapshot", async () => {
    const root = await workspace("unwatched", 4);
    await fillWatchSlots(root);
    await mkdir(join(root, "assets"));
    const { uploads, upload } = makeUploads();
    const sessionUploader = new SessionUploader({ upload, changeDebounceMs: 60_000, fallbackScanMs: 60_000 });
    const sessionId = "session-unwatched-1234";
    sessionUploader.startSession(sessionId, "workspace-unwatched", root);
    await sessionUploader.idle(sessionId);
    expect(sessionUploader.sessionDiagnostics(sessionId)?.watchedPaths).not.toContain("assets");
    sessionUploader.captureSnapshot(sessionId, "prompt");
    await sessionUploader.idle(sessionId);
    // A bash tool writes it; no trace event names it and no watcher covers assets/.
    await mkdir(join(root, "assets", "db"));
    await writeFile(join(root, "assets", "db", "migrate.sh"), "#!/bin/sh\necho migrate\n");
    await sleep(200);
    sessionUploader.captureSnapshot(sessionId, "turn_completed");
    await sessionUploader.idle(sessionId);
    // The end-of-turn artifact scan marks it dirty for the turn's own snapshot.
    expect(contentPaths(changes(uploads)[0]!)).toEqual(["assets/db/migrate.sh"]);
    sessionUploader.flushTrace(sessionId);
    await sessionUploader.stop();
    expect(triggerEvents(uploads)).toEqual([
      { trigger: "prompt", captured: false },
      { trigger: "turn_completed", captured: true },
    ]);
  });

  test.skipIf(process.platform === "win32")("a path git refuses to answer for (beyond a symlinked directory) neither changes the ignore answer for its batch nor gets read", async () => {
    const base = await mkdtemp(join(tmpdir(), "omnirush-upload-symlink-"));
    roots.push(base);
    const root = join(base, "repo");
    const outside = join(base, "shared-lib");
    await mkdir(join(root, "src"), { recursive: true });
    await mkdir(outside);
    await git(root, "init", "-q");
    await appendFile(join(root, ".git", "info", "exclude"), "private-notes.txt\n");
    await writeFile(join(root, "src", "app.ts"), "export const app = 1;\n");
    await writeFile(join(outside, "util.ts"), "export const OUTSIDE_WORKSPACE = true;\n");
    // A symlinked shared package: `git check-ignore linked/util.ts` exits 128.
    await symlink("../shared-lib", join(root, "linked"));
    await git(root, "add", "-A");
    await git(root, "commit", "-q", "-m", "init");
    const { uploads, upload } = makeUploads();
    const sessionUploader = new SessionUploader({ upload, changeDebounceMs: 60_000, fallbackScanMs: 60_000 });
    const sessionId = "session-symlink-1234";
    sessionUploader.startSession(sessionId, "workspace-symlink", root);
    await sessionUploader.idle(sessionId);
    // In one ignore batch: a note git ignores only through .git/info/exclude,
    // the agent's traced read through the symlinked package, and a real edit.
    await writeFile(join(root, "private-notes.txt"), "PRIVATE: salary negotiation notes\n");
    sessionUploader.recordTrace(sessionId, "tool.read", { filePath: "linked/util.ts" });
    await writeFile(join(root, "src", "app.ts"), "export const app = 2;\n");
    await sleep(200);
    sessionUploader.captureSnapshot(sessionId, "turn_completed");
    await sessionUploader.idle(sessionId);
    const change = changes(uploads)[0]!;
    expect(contentPaths(change)).toEqual(["src/app.ts"]);
    // Capture v2: the symlink itself is listed with its target (never followed, nothing behind it read).
    expect(change.manifest.filter((entry) => entry.type !== "symlink").map((entry) => entry.path)).toEqual(["src/app.ts"]);
    expect(change.manifest.find((entry) => entry.path === "linked")).toMatchObject({ type: "symlink", target: "../shared-lib", broken: false });
    expect(change.files.find((file) => file.path === "__omnirush__/changes.json")?.content).toContain('"path":"src/app.ts"');
    await sessionUploader.stop();
    const all = JSON.stringify(uploads);
    expect(all).not.toContain("salary negotiation");
    expect(all).not.toContain("OUTSIDE_WORKSPACE");
  });

  test("a listed file the user then ignores leaves the manifest, files[] and the journal, through .gitignore or .git/info/exclude", async () => {
    for (const via of ["gitignore", "exclude"] as const) {
      const root = await workspace(`newly-ignored-${via}`, 4);
      await writeFile(join(root, "notes.txt"), "scratch v1\n"); // untracked, not ignored yet
      const { uploads, upload } = makeUploads();
      const sessionUploader = new SessionUploader({ upload, changeDebounceMs: 60_000, fallbackScanMs: 60_000 });
      const sessionId = `session-newly-ignored-${via}`;
      sessionUploader.startSession(sessionId, "workspace-newly-ignored", root);
      await sessionUploader.idle(sessionId);
      expect(uploads[0]!.manifest.map((entry) => entry.path)).toContain("notes.txt");
      // An edit while it is still uploaded: git's "not ignored" is now cached.
      await writeFile(join(root, "notes.txt"), "scratch v1b\n");
      await sleep(200);
      sessionUploader.captureSnapshot(sessionId, "turn_completed");
      await sessionUploader.idle(sessionId);
      expect(contentPaths(changes(uploads)[0]!)).toEqual(["notes.txt"]);
      // The user hides it from git (.git/info/exclude raises no event), then writes something private into it.
      if (via === "gitignore") await writeFile(join(root, ".gitignore"), "dist/\nnode_modules/\nnotes.txt\n");
      else await appendFile(join(root, ".git", "info", "exclude"), "notes.txt\n");
      await sleep(150);
      await writeFile(join(root, "notes.txt"), "PRIVATE: do not share v2\n");
      await sleep(200);
      sessionUploader.captureSnapshot(sessionId, "turn_completed");
      await sessionUploader.idle(sessionId);
      const change = changes(uploads)[1]!;
      expect(change.manifest.map((entry) => entry.path)).not.toContain("notes.txt");
      expect(contentPaths(change)).not.toContain("notes.txt");
      await sessionUploader.stop();
      expect(JSON.stringify(uploads)).not.toContain("do not share v2");
    }
  });

  test("a resumed session's start snapshot carries every file again, even when its earlier start never reached the backend", async () => {
    const root = await workspace("resume-full", 4);
    const stateDir = await mkdtemp(join(tmpdir(), "omnirush-upload-resume-full-state-"));
    roots.push(stateDir);
    const sessionId = "session-resume-full-1";
    // Offline: the start snapshot is only spooled, and sign-out then deletes the spool.
    const offline = new SessionUploader({
      stateDir,
      upload: async () => new Response("unavailable", { status: 503 }),
      uploadRetryDelayMs: 1,
      retryBaseMs: 60_000,
      retryMaxMs: 60_000,
      changeDebounceMs: 60_000,
      fallbackScanMs: 60_000,
    });
    offline.startSession(sessionId, "workspace-resume-full", root);
    await offline.idle(sessionId);
    await offline.stop();
    await offline.clearSpool();

    await writeFile(join(root, "src", "f00.txt"), "source file 0, edited while the app was closed\n");
    const { uploads, upload } = makeUploads();
    for (let run = 0; run < 2; run += 1) {
      const sessionUploader = new SessionUploader({ stateDir, upload, changeDebounceMs: 60_000, fallbackScanMs: 60_000 });
      sessionUploader.startSession(sessionId, "workspace-resume-full", root);
      await sessionUploader.idle(sessionId);
      await sessionUploader.stop();
    }
    const starts = uploads.filter((item) => item.snapshot_type === "start");
    expect(starts.map((item) => [item.trigger, item.session_segment, item.files_scope, contentPaths(item).length])).toEqual([
      ["resume", 2, "full", 6],
      ["resume", 3, "full", 6],
    ]);
    expect(starts.every((item) => item.changed_paths === undefined)).toBe(true);
  });

  test("a new chat on a captured workspace sends scrubbed files from the redacted-text cache, not the scrubber", async () => {
    const root = await workspace("texts", 4);
    await writeFile(join(root, "src", "contact.txt"), "mail jane@acme-mail.io about it\n");
    await writeFile(join(root, "src", "config.yml"), "password: hunter2hunter2\n");
    const { uploads, upload } = makeUploads();
    const sessionUploader = new SessionUploader({ upload, changeDebounceMs: 60_000, fallbackScanMs: 60_000 });
    const start = (id: string) => uploads.find((item) => item.snapshot_type === "start" && item.session_id === id)!;
    const content = (envelope: Envelope, path: string) => envelope.files.find((file) => file.path === path)?.content;

    sessionUploader.startSession("session-texts-first-1", "workspace-texts", root);
    await sessionUploader.idle("session-texts-first-1");
    // The scan scrubbed each file once; the upload pass reused that text for the two files the scrubber changed.
    expect(sessionUploader.metrics.redactedTextHits).toBe(2);
    const before = { ...sessionUploader.metrics };
    sessionUploader.startSession("session-texts-second", "workspace-texts", root);
    await sessionUploader.idle("session-texts-second");
    expect(sessionUploader.metrics.fileRedactions - before.fileRedactions).toBe(0);
    expect(sessionUploader.metrics.redactedTextHits - before.redactedTextHits).toBe(2);
    const first = start("session-texts-first-1");
    const second = start("session-texts-second");
    expect(content(second, "src/contact.txt")).toBe("mail [REDACTED_PII] about it\n");
    expect(content(second, "src/config.yml")).toBe("password: [REDACTED]\n");
    expect(second.files.filter((file) => !file.path.startsWith("__omnirush__/"))).toEqual(first.files.filter((file) => !file.path.startsWith("__omnirush__/")));
    expect(second.manifest).toEqual(first.manifest);

    // New bytes are scrubbed again, never served from the text of the old ones.
    await writeFile(join(root, "src", "contact.txt"), "mail joe@acme-mail.io instead of jane\n");
    const edited = { ...sessionUploader.metrics };
    sessionUploader.startSession("session-texts-third1", "workspace-texts", root);
    await sessionUploader.idle("session-texts-third1");
    expect(content(start("session-texts-third1"), "src/contact.txt")).toBe("mail [REDACTED_PII] instead of jane\n");
    expect(sessionUploader.metrics.fileRedactions - edited.fileRedactions).toBeGreaterThanOrEqual(1);
    await sessionUploader.stop();
  });

  test("snapshots a 60 MiB workspace with peak RSS growth under 120 MB", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-memory-"));
    roots.push(root);
    await mkdir(join(root, "src"));
    // Pseudo-random words so the content neither compresses away nor trips the scrubber.
    const words = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india", "juliet", "kilo", "lima"];
    const filler = (seed: number, bytes: number): string => {
      let out = "";
      let value = seed;
      while (out.length < bytes) {
        value = (value * 1103515245 + 12345) % 2147483648;
        out += `${words[value % words.length]} ${value.toString(36)}${value % 7 === 0 ? "\n" : " "}`;
      }
      return out.slice(0, bytes);
    };
    let total = 0;
    for (let index = 0; index < 8; index += 1) {
      const text = filler(index + 1, 3 * 1024 * 1024);
      total += text.length;
      await writeFile(join(root, "src", `large-${index}.txt`), text);
    }
    for (let index = 0; index < 280; index += 1) {
      const text = filler(100 + index, 128 * 1024);
      total += text.length;
      await writeFile(join(root, "src", `small-${String(index).padStart(3, "0")}.txt`), text);
    }
    // Just under what the 64 MiB snapshot cap leaves for content.
    expect(total).toBeGreaterThanOrEqual(58 * 1024 * 1024);

    const compressedEnvelopes: Uint8Array[] = [];
    const sessionUploader = new SessionUploader({
      upload: async (_sessionId, compressed) => {
        compressedEnvelopes.push(compressed);
        return Response.json({ ok: true }, { status: 201 });
      },
      changeDebounceMs: 60_000,
      fallbackScanMs: 60_000,
    });
    const gc = (globalThis as { gc?: () => void }).gc ?? (globalThis as { Bun?: { gc?: (force: boolean) => void } }).Bun?.gc?.bind(null, true);
    gc?.();
    await sleep(50);
    const baseline = process.memoryUsage().rss;
    let peak = baseline;
    const sampler = setInterval(() => { peak = Math.max(peak, process.memoryUsage().rss); }, 20);
    const sessionId = "session-memory-1234";
    sessionUploader.startSession(sessionId, "workspace-memory", root);
    await sessionUploader.idle(sessionId);
    peak = Math.max(peak, process.memoryUsage().rss);
    clearInterval(sampler);
    await sessionUploader.stop();

    const growthMB = (peak - baseline) / (1024 * 1024);
    expect(growthMB).toBeLessThan(120);
    const start = withTraceEvents(JSON.parse(zstdDecompressSync(compressedEnvelopes[0]!).toString("utf8"))) as Envelope;
    expect(start.snapshot_type).toBe("start");
    expect(start.files.reduce((sum, file) => sum + file.content.length, 0)).toBeGreaterThanOrEqual(58 * 1024 * 1024);
    expect(start.privacy).toMatchObject({ files_truncated: false });
  }, 60_000);
});

describe("upload features", () => {
  test("without the backend's idempotency_key feature (or any capability answer) no Idempotency-Key is sent and no integrity read is made", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-upload-nofeat-"));
    roots.push(root);
    const keys: Array<string | undefined> = [];
    let integrity = 0;
    for (const capabilities of [undefined, async () => ({ schema_versions: [1, 2], canonical_trace: false })]) {
      const sessionUploader = new SessionUploader({
        upload: async (_sessionId, _compressed, _signal, request) => {
          keys.push(request?.idempotencyKey);
          return Response.json({ ok: true }, { status: 201 });
        },
        sessionIntegrity: async () => {
          integrity += 1;
          return Response.json({ max_segment: 4, max_sequence: 9 });
        },
        ...(capabilities ? { capabilities } : {}),
        fallbackScanMs: 60_000,
      });
      sessionUploader.startSession("session-nofeat-1234", "workspace-nofeat", root);
      await sessionUploader.stop();
    }
    expect(keys.length).toBeGreaterThan(0);
    expect(keys.every((key) => key === undefined)).toBe(true);
    expect(integrity).toBe(0);
  });
});

describe("integrity confirmation", () => {
  const FEATURES = async () => ({ schema_versions: [1, 2], canonical_trace: false, idempotency_key: true, integrity: true, integrity_summary: true });

  async function endedChat(options: { refuseSecond?: boolean } = {}) {
    const root = await mkdtemp(join(tmpdir(), "omnirush-confirm-"));
    const stateDir = await mkdtemp(join(tmpdir(), "omnirush-confirm-state-"));
    roots.push(root, stateDir);
    await writeFile(join(root, "app.txt"), "hello\n");
    let uploads = 0;
    const first = new SessionUploader({
      stateDir,
      capabilities: FEATURES,
      upload: async () => {
        uploads += 1;
        return options.refuseSecond && uploads === 2 ? Response.json({ detail: "bad" }, { status: 422 }) : Response.json({ ok: true }, { status: 201 });
      },
      sessionIntegrity: async () => Response.json({ detail: "session_not_found" }, { status: 404 }),
      confirm: false,
      fallbackScanMs: 60_000,
    });
    first.startSession("session-confirm-1234", "workspace-confirm", root);
    first.recordTrace("session-confirm-1234", "tool.call", {});
    first.flushTrace("session-confirm-1234");
    await first.stop();
    return { root, stateDir };
  }

  test("a good or not-good answer is final; the ledger keeps it", async () => {
    const { stateDir } = await endedChat();
    let calls = 0;
    const uploader = new SessionUploader({
      stateDir,
      capabilities: FEATURES,
      upload: async () => Response.json({ ok: true }, { status: 201 }),
      sessionIntegrity: async (_sessionId, options) => {
        calls += 1;
        expect(options).toEqual({ summary: true });
        return Response.json({ integrity: "ok", reasons: [], good_session: true, good_session_reasons: [], segments: [{ segment: 1, sequences: [1, 2, 3], gaps: [] }] });
      },
      confirm: false,
    });
    expect(await uploader.confirmSession("session-confirm-1234")).toMatchObject({ verdict: "good", checks: 1 });
    expect(calls).toBe(1);
    await uploader.stop();
    const ledger = JSON.parse(await readFile(join(stateDir, "omnirush-upload-sessions.json"), "utf8")) as { sessions: Record<string, { confirmation?: { verdict: string; nextAt?: string } }> };
    expect(ledger.sessions["session-confirm-1234"]?.confirmation).toMatchObject({ verdict: "good" });
    expect(ledger.sessions["session-confirm-1234"]?.confirmation?.nextAt).toBeUndefined();
  });

  test("a gap the ledger explains (an upload the server refused) asks for nothing; pending is asked again later", async () => {
    const { stateDir } = await endedChat({ refuseSecond: true });
    let repairs = 0;
    const uploader = new SessionUploader({
      stateDir,
      capabilities: FEATURES,
      upload: async () => Response.json({ ok: true }, { status: 201 }),
      sessionIntegrity: async () => Response.json({ integrity: "incomplete", reasons: ["sequence_gaps"], good_session: "pending", segments: [{ segment: 1, sequences: [1, 3], gaps: [2] }] }),
      repairTranscript: async () => {
        repairs += 1;
        return [[]];
      },
      confirm: false,
    });
    const confirmation = await uploader.confirmSession("session-confirm-1234");
    expect(confirmation).toMatchObject({ verdict: "pending", checks: 1 });
    expect(confirmation?.nextAt).toBeDefined();
    expect(confirmation?.repairedAt).toBeUndefined();
    expect(repairs).toBe(0);
    await uploader.stop();
  });

  test("a gap nothing here explains gets the transcript re-sent from the engine, once", async () => {
    const { stateDir, root } = await endedChat();
    const sent: Array<Record<string, unknown>> = [];
    const asked: Array<{ sessionId: string; workspaceId: string; root: string }> = [];
    const uploader = new SessionUploader({
      stateDir,
      capabilities: FEATURES,
      upload: async (_sessionId, compressed) => {
        sent.push(withTraceEvents(JSON.parse(zstdDecompressSync(compressed).toString("utf8"))) as Record<string, unknown>);
        return Response.json({ ok: true }, { status: 201 });
      },
      sessionIntegrity: async () => Response.json({ integrity: "incomplete", reasons: ["sequence_gaps"], good_session: "pending", segments: [{ segment: 1, sequences: [1, 3], gaps: [2] }] }),
      repairTranscript: async (chat) => {
        asked.push(chat);
        return [[{ info: { id: "msg_1", role: "user" }, parts: [] }]];
      },
      confirm: false,
    });
    const first = await uploader.confirmSession("session-confirm-1234");
    expect(first?.repairedAt).toBeDefined();
    expect(asked).toEqual([{ sessionId: "session-confirm-1234", workspaceId: "workspace-confirm", root }]);
    expect(sent).toHaveLength(1);
    const types = (sent[0]!.trace as Array<{ type: string }>).map((event) => event.type);
    expect(types[0]).toBe("collector.repair");
    expect(types).toContain("turn.messages");
    expect(sent[0]).toMatchObject({ snapshot_type: "trace", session_segment: 1, sequence: 4 });
    await uploader.confirmSession("session-confirm-1234");
    expect(asked).toHaveLength(1);
    await uploader.stop();
  });

  test("a gap a spooled upload will fill drains the spool instead of re-sending", async () => {
    const { stateDir } = await endedChat();
    const spool = join(stateDir, "omnirush-upload-spool");
    await mkdir(spool, { recursive: true });
    const id = "000000000009-000009-00000009";
    await writeFile(join(spool, `${id}.zst`), Buffer.alloc(32, 9));
    await writeFile(join(spool, `${id}.json`), JSON.stringify({ id, session_id: "session-confirm-1234", snapshot_type: "trace", trigger: "trace_flush", sequence: 2, bytes: 32, created_at: new Date().toISOString(), attempts: 1 }));
    let repairs = 0;
    const delivered: string[] = [];
    const uploader = new SessionUploader({
      stateDir,
      capabilities: FEATURES,
      upload: async (sessionId) => {
        delivered.push(sessionId);
        return Response.json({ ok: true }, { status: 201 });
      },
      sessionIntegrity: async () => Response.json({ integrity: "incomplete", reasons: ["sequence_gaps"], good_session: "pending", segments: [{ segment: 1, sequences: [1, 3], gaps: [2] }] }),
      repairTranscript: async () => {
        repairs += 1;
        return [[]];
      },
      confirm: false,
      retryBaseMs: 60_000,
    });
    await uploader.confirmSession("session-confirm-1234");
    await uploader.drainSpool();
    expect(repairs).toBe(0);
    expect(delivered).toContain("session-confirm-1234");
    await uploader.stop();
  });

  test("at launch, recent ended chats without a final verdict are checked; a judged one is not", async () => {
    const { stateDir } = await endedChat();
    const ledgerPath = join(stateDir, "omnirush-upload-sessions.json");
    const ledger = JSON.parse(await readFile(ledgerPath, "utf8")) as { version: 1; sessions: Record<string, Record<string, unknown>> };
    const record = ledger.sessions["session-confirm-1234"]!;
    ledger.sessions["session-judged-1234"] = { ...record, confirmation: { verdict: "not_good", checkedAt: new Date().toISOString(), checks: 1 } };
    await writeFile(ledgerPath, JSON.stringify(ledger));
    const checked: string[] = [];
    const uploader = new SessionUploader({
      stateDir,
      capabilities: FEATURES,
      upload: async () => Response.json({ ok: true }, { status: 201 }),
      sessionIntegrity: async (sessionId) => {
        checked.push(sessionId);
        return Response.json({ integrity: "ok", reasons: [], good_session: true, segments: [] });
      },
    });
    for (let waited = 0; waited < 25_000 && checked.length === 0; waited += 100) await new Promise((resolve) => setTimeout(resolve, 100));
    await new Promise((resolve) => setTimeout(resolve, 300));
    expect(checked).toEqual(["session-confirm-1234"]);
    await uploader.stop();
  }, 40_000);

  test("reads an integrity answer against the refusals the ledger holds", () => {
    expect(integrityFindings({ good_session: "pending", reasons: ["sequence_gaps"], segments: [{ segment: 2, gaps: [5, 6] }, { segment: null, gaps: [1] }] }, ["2:5"]))
      .toEqual({ verdict: "pending", gaps: ["2:6", "?:1"], missing: false });
    expect(integrityFindings({ good_session: false, reasons: ["no_trace"], segments: [] })).toEqual({ verdict: "not_good", gaps: [], missing: true });
    expect(integrityFindings("nope")).toBeNull();
  });

  test("keeps the Git baseline and defers only ordinary watched-edit metadata", async () => {
    const root = await mkdtemp(join(tmpdir(), "omnirush-git-review-"));
    roots.push(root);
    await writeFile(join(root, "note.txt"), "baseline\\n");
    await execFileAsync("git", ["init", "-q", "-b", "main", root]);
    await execFileAsync("git", ["-C", root, "add", "."]);
    await execFileAsync("git", ["-C", root, "-c", "user.email=t@example.com", "-c", "user.name=t", "commit", "-qm", "baseline"]);
    const uploads: Array<Record<string, unknown>> = [];
    const uploader = new SessionUploader({
      upload: async (_sessionId, compressed) => {
        uploads.push(JSON.parse(zstdDecompressSync(compressed).toString("utf8")) as Record<string, unknown>);
        return Response.json({ ok: true }, { status: 201 });
      },
      changeDebounceMs: 10,
      fallbackScanMs: 60_000,
    });
    const sessionId = "session-git-review-1234";
    uploader.startSession(sessionId, "workspace-git", root);
    await uploader.idle(sessionId);
    const start = uploads.find((item) => item.snapshot_type === "start")!;
    const startGit = (start.workspace as { git: { commit: string; branch: string; dirty: string } }).git;
    expect(startGit.branch).toBe("main");
    expect(startGit.commit).toMatch(/^[0-9a-f]{40}$/);
    await writeFile(join(root, "note.txt"), "edited\\n");
    uploader.captureSnapshot(sessionId, "prompt");
    await uploader.idle(sessionId);
    const change = uploads.find((item) => item.snapshot_type === "change")!;
    expect(change.workspace).toMatchObject({ git: null, git_deferred: "session_end" });
    await uploader.stop();
    const end = uploads.find((item) => item.snapshot_type === "end")!;
    expect((end.workspace as { git: { commit: string } }).git.commit).toBe(startGit.commit);
  });

});
