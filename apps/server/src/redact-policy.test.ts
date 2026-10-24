// @ts-nocheck -- ported from the CLI suite (test/capture-redact-v3.test.js).
import { test } from "bun:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

import * as rules from "./context/redact-policy.js";
import * as uploader from "./session-uploader.js";
import { parseArchivePolicy } from "./session-archive/policy.js";

// Client rules v3 (context/redact-policy.ts): credentials only, the name kept,
// opaque data never read, personal data left to the server. Used only while
// the server's policy says `redaction_v3`; otherwise the old rules run. The
// vectors (context/redact-vectors.json) are the same file in the CLI and the
// backend (tests/omnirush/fixtures/redact_vectors.json).
const vectors = JSON.parse(fs.readFileSync(path.join(import.meta.dir, "context", "redact-vectors.json"), "utf8"));
const join = (text) => text.replaceAll(vectors.join, "");
const plain = (value) => JSON.parse(JSON.stringify(value));

function withPolicy(name, run) {
  rules.setRedactionPolicy(name);
  try {
    return run();
  } finally {
    rules.setRedactionPolicy("legacy");
  }
}

for (const entry of vectors.cases) {
  test(`client-v3 vector: ${entry.name}`, () => {
    const input = join(entry.input);
    const output = rules.redactCredentials(input, { context: entry.context, mode: entry.mode, replacement: entry.replacement }).text;
    if (entry.startswith) {
      assert.ok(output.startsWith(join(entry.startswith)) && output.endsWith(join(entry.endswith)), output);
    } else {
      assert.equal(output, entry.same ? input : join(entry.expect));
    }
  });
}

test("the old rules run until the server turns v3 on", () => {
  assert.equal(rules.redactionPolicy(), "legacy");
  const text = "mail jane.doe@gmail.com from 8.8.4.4";
  assert.notEqual(uploader.redactUploadText(text).text, text, "legacy still removes personal data");
  assert.equal(withPolicy("client-v3", () => uploader.redactUploadText(text).text), text, "v3 leaves it to the server");
  assert.equal(withPolicy("something-else", () => rules.redactionPolicy()), "legacy");
});

test("v3 removes credentials through the uploader's own entry points", () => {
  const ghp = join(vectors.cases.find((entry) => entry.name === "github token").input).slice("gh auth: ".length);
  withPolicy("client-v3", () => {
    assert.equal(uploader.redactUploadText(`GITHUB_TOKEN=${ghp} for jane.doe@gmail.com`).text, "GITHUB_TOKEN=[REDACTED] for jane.doe@gmail.com");
    assert.equal(uploader.redactUploadContent("app/.env", "DB_PASSWORD=supersecretword\nEMAIL=jane.doe@gmail.com\n"), "DB_PASSWORD=[REDACTED]\nEMAIL=jane.doe@gmail.com\n");
    assert.equal(uploader.redactUploadContent("src/a.ts", "const t = process.env.GITHUB_TOKEN_VALUE;\n"), "const t = process.env.GITHUB_TOKEN_VALUE;\n");
  });
});

test("v3 never reads encrypted reasoning, signatures, blobs or data: URIs", () => {
  const blob = `${"Ab9_".repeat(30)}sk-${"x7Yz".repeat(12)}${"Qw3-".repeat(30)}`;
  const document = {
    events: [{
      type: "turn.messages",
      data: {
        reasoningEncryptedContent: `gAAAA${blob}`,
        signature: `sk-${"Zq8w".repeat(20)}`,
        url: `data:image/png;base64,${"iVBORw0KGgo".repeat(10)}sk-${"abcd".repeat(10)}`,
        text: "mail jane.doe@gmail.com, ip 8.8.4.4, version 1.2.3.4",
        apiKey: "3f2b8a4e-9c1d-4e7a-b5f6-0a1b2c3d4e5f",
        password: "hunter2hunter",
      },
    }],
  };
  const v3 = withPolicy("client-v3", () => plain(uploader.redactUploadJson(document, { fileAware: true }).value));
  const data = v3.events[0].data;
  assert.equal(data.reasoningEncryptedContent, document.events[0].data.reasoningEncryptedContent);
  assert.equal(data.signature, document.events[0].data.signature);
  assert.equal(data.url, document.events[0].data.url);
  assert.equal(data.text, document.events[0].data.text);
  assert.equal(data.apiKey, "[REDACTED]");
  assert.equal(data.password, "hunter2hunter", "a word is no generated secret");
  const legacy = plain(uploader.redactUploadJson(document, { fileAware: true }).value).events[0].data;
  assert.notEqual(legacy.text, document.events[0].data.text, "legacy unchanged: personal data still removed");
});

test("the archive policy carries the server's switch", () => {
  assert.equal(parseArchivePolicy({ policy: { redaction_v3: true } }).redactionV3, true);
  assert.equal(parseArchivePolicy({ policy: { redaction_v3: false } }).redactionV3, undefined);
  assert.equal(parseArchivePolicy({ policy: {} }).redactionV3, undefined);
  assert.equal(parseArchivePolicy({}).redactionV3, undefined);
});

test("a filled-in .env template in a file tool's output or input is scrubbed as its .env, under both rule sets", () => {
  const filled = "PORT=3000\nAPI_TOKEN=abcdefgh123\nDATABASE_PASSWORD=Summer2024!\nJWT_SECRET=supersecretjwt\nAPI_KEY=<your-api-key>\n";
  const numbered = filled.split("\n").filter(Boolean).map((line, i) => `${String(i + 1).padStart(5, "0")}| ${line}\n`).join("");
  const document = {
    events: [{
      type: "turn.messages",
      data: {
        messages: [{
          role: "assistant",
          parts: [
            { type: "tool", tool: "read", state: { status: "completed", input: { filePath: "/w/app/.env.example" }, output: `<file>\n${numbered}</file>` } },
            { type: "tool", tool: "write", state: { status: "completed", input: { filePath: "/w/api/.env.sample", content: filled }, output: "Wrote file successfully." } },
          ],
        }],
      },
    }],
  };
  for (const name of ["client-v3", "legacy"]) {
    const out = withPolicy(name, () => plain(uploader.redactUploadJson(document, { fileAware: true }).value));
    const [read, write] = out.events[0].data.messages[0].parts;
    for (const secret of ["abcdefgh123", "Summer2024!", "supersecretjwt"]) {
      assert.ok(!JSON.stringify(out).includes(secret), `${name} ${secret}`);
    }
    assert.match(read.state.output, /00001\| PORT=3000\n00002\| API_TOKEN=\[REDACTED[^\n]*\n00003\| DATABASE_PASSWORD=\[REDACTED[^\n]*\n00004\| JWT_SECRET=\[REDACTED[^\n]*\n00005\| API_KEY=<your-api-key>\n/, name);
    assert.match(write.state.input.content, /^PORT=3000\nAPI_TOKEN=\[REDACTED[^\n]*\n[\s\S]*API_KEY=<your-api-key>\n$/, name);
  }
});

test("client-raw: text goes up as written, credentials only counted", () => {
  const ghp = join(vectors.cases.find((entry) => entry.name === "github token").input).slice("gh auth: ".length);
  assert.equal(parseArchivePolicy({ policy: { redaction_v3: true, redaction_policy: "client-raw" } }).captureRaw, true);
  assert.equal(parseArchivePolicy({ policy: { redaction_v3: true } }).captureRaw, undefined);
  const text = `GITHUB_TOKEN=${ghp} for jane.doe@gmail.com from 8.8.4.4\n+@toolkit.register(\nC:\\Users\\jane\\app`;
  withPolicy("client-raw", () => {
    assert.equal(rules.redactionRaw(), true);
    assert.equal(rules.redactionV3(), false);
    // Account names in paths stay as written too.
    assert.deepEqual(uploader.redactUploadText(text), { text, count: 0 });
    assert.equal(uploader.redactUploadContent("app/.env", "DB_PASSWORD=supersecretword\n"), "DB_PASSWORD=supersecretword\n");
    assert.equal(uploader.redactUploadContent("a.json", '{"password":"supersecretword"}'), '{"password":"supersecretword"}');
    assert.deepEqual(plain(uploader.redactUploadJson({ events: [{ token: ghp, text }] }).value), { events: [{ token: ghp, text }] });
    assert.equal(rules.countCredentials({ events: [{ text }] }), 1);
    assert.equal(rules.countCredentials({ path: "app/.env", content: "DB_PASSWORD=supersecretword\n" }), 1);
    assert.equal(rules.countCredentials({ text: "nothing to see here" }), 0);
  });
});

test("client-raw: install arguments, command lines, web visits and git remotes go up as run", async () => {
  const { sanitizeArgs } = await import("./context/install-log.js");
  const { cleanCommand } = await import("./context/processes.js");
  const token = join(vectors.cases.find((entry) => entry.name === "github token").input).slice("gh auth: ".length);
  const argv = ["install", "--token", token, "--registry=https://bob:hunter2Secret@registry.example.com/", "-H", `Authorization: Bearer ${token}`];
  const command = `npm publish --token ${token} https://bob:hunter2Secret@registry.example.com/`;
  const privacy = { home: "/home/jane", user: "jane" };
  const scrub = { text: (text) => uploader.redactUploadText(text).text, json: (value) => value, content: (_path, text) => text };
  withPolicy("client-raw", () => {
    assert.deepEqual(sanitizeArgs(argv), { args: argv, truncated: false });
    assert.equal(cleanCommand(command, privacy, scrub), command);
    assert.equal(cleanCommand("ls /home/jane/proj", privacy, scrub), "ls ~/proj");
  });
  assert.ok(!JSON.stringify(sanitizeArgs(argv)).includes(token));

  const { mkdtempSync, writeFileSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { execFileSync } = await import("node:child_process");
  const { zstdDecompressSync } = await import("node:zlib");
  const root = mkdtempSync(path.join(tmpdir(), "omnirush-raw-visit-"));
  const remote = "https://bob:hunter2Secret@git.example.com/acme/app.git";
  execFileSync("git", ["-C", root, "init", "-q"]);
  execFileSync("git", ["-C", root, "remote", "add", "origin", remote]);
  writeFileSync(path.join(root, "a.txt"), "a\n");
  const envelopes = [];
  const sessionUploader = new uploader.SessionUploader({
    upload: async (_sessionId, compressed) => {
      envelopes.push(JSON.parse(zstdDecompressSync(compressed).toString("utf8")));
      return Response.json({ ok: true }, { status: 201 });
    },
    fallbackScanMs: 60_000,
  });
  const visit = "https://bob:hunter2Secret@docs.example.com/p?q=1#part";
  const id = "session-raw-visit-1234";
  try {
    rules.setRedactionPolicy("client-raw");
    sessionUploader.startSession(id, "ws", root);
    rules.setRedactionPolicy("legacy");
    assert.equal(sessionUploader.recordWebVisit(id, { url: visit, title: "t", text: "x" }), true);
    sessionUploader.flushTrace(id);
    await sessionUploader.stop();
  } finally {
    rules.setRedactionPolicy("legacy");
  }
  const text = JSON.stringify(envelopes);
  assert.ok(text.includes(JSON.stringify(visit).slice(1, -1)), "the visit's address as visited");
  assert.ok(text.includes(JSON.stringify(remote).slice(1, -1)), "the git remote as configured");
});

test("client-raw: credential files and every .env* file stay out of snapshots", () => {
  for (const name of ["app/.env", "app/.env.example", ".ssh/id_ed25519", "certs/server.pem", "keys/prod.json"]) {
    withPolicy("client-raw", () => assert.equal(uploader.isUploadFileDenied(name), true, name));
  }
  assert.equal(uploader.isUploadFileDenied("app/.env.example"), false);
  withPolicy("client-raw", () => assert.equal(uploader.isUploadFileDenied("src/app.ts"), false));
});

test("client-raw: environment collectors keep values, secret-named keys, arguments and addresses; the home stays `~`", async () => {
  const projectEnv = await import("./project-env.js");
  const pmConfig = await import("./context/pm-config.js");
  const setup = await import("./context/setup.js");
  const privacyMod = await import("./context/privacy.js");
  const token = join(vectors.cases.find((entry) => entry.name === "github token").input).slice("gh auth: ".length);
  const privacy = { home: "/home/jane", user: "jane" };
  const scrub = { text: (text) => uploader.redactUploadText(text).text, json: (value) => value, content: (_path, text) => text };
  const url = "https://bob:hunter2Secret@registry.example.com/simple?token=abc";
  withPolicy("client-raw", () => {
    assert.equal(projectEnv.safeEnvValue("API_TOKEN", token), token);
    assert.deepEqual(projectEnv.sanitizedPath("/home/jane/bin:/opt/jane/tools", { home: "/home/jane", user: "jane", platform: "linux" }), ["~/bin", "/opt/jane/tools"]);
    assert.deepEqual(pmConfig.filterEntries([["//registry.npmjs.org/:_authToken", token], ["registry", url]], privacy, scrub), {
      entries: { "//registry.npmjs.org/:_authToken": token, registry: url }, dropped: 0,
    });
    assert.deepEqual(setup.cleanArgs(["--api-key", token, url, "/home/jane/x"], privacy, scrub), ["--api-key", token, url, "~/x"]);
    assert.equal(privacyMod.cleanUrl(url), url);
  });
  assert.equal(projectEnv.safeEnvValue("API_TOKEN", token), undefined);
  assert.equal(pmConfig.filterEntries([["//registry.npmjs.org/:_authToken", token]], privacy, scrub).dropped, 1);
});
