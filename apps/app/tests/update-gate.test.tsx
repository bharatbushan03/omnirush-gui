import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";

import {
  NO_UPDATE_GATE,
  chatBlockedByUpdate,
  formatUpdateCountdown,
  normalizeUpdateGateState,
  requiredUpdateAction,
  requiredUpdateUnreachable,
  shouldStartBackgroundDownload,
  updateBannerText,
  updateButtonLabel,
  useUpdateGateStore,
  type UpdateGateState,
} from "../src/app/lib/update-gate";
import { RequiredUpdateBanner, UpdateRequiredView } from "../src/react-app/shell/update-gate";

const read = (relative: string) => readFileSync(fileURLToPath(new URL(relative, import.meta.url)), "utf8");

const NOW = Date.parse("2026-10-04T12:00:00Z");
const required: UpdateGateState = {
  status: "required",
  current: "3.0.2",
  minimum: "3.1.0",
  deadline: "2026-10-04T17:12:00.000Z",
  message: null,
  downloadUrl: "https://omnirush.ai/download",
  source: "header",
};
const blocked: UpdateGateState = { ...required, status: "blocked", message: "Update OmniRush.ai to 3.1.0 to keep using models.", source: "rejection" };

function fakeUpdate(over: Partial<{ label: string; working: boolean; detail: string | null; command: string | null; installFailed: boolean }> = {}) {
  return {
    updateNow: () => undefined,
    working: false,
    detail: null,
    label: "Update and restart",
    command: null,
    installFailed: false,
    showDownloaded: () => undefined,
    ...over,
  };
}

describe("update gate state from the desktop bridge", () => {
  test("normalizes the main-process state and rejects anything malformed", () => {
    expect(normalizeUpdateGateState(required)).toEqual(required);
    expect(normalizeUpdateGateState(null)).toEqual(NO_UPDATE_GATE);
    expect(normalizeUpdateGateState({ status: "panic", deadline: "soon", downloadUrl: "" })).toEqual({
      ...NO_UPDATE_GATE,
      status: "none",
    });
  });

  test("only the blocked state disables the chat input", () => {
    expect(chatBlockedByUpdate(blocked)).toBe(true);
    expect(chatBlockedByUpdate(required)).toBe(false);
    expect(chatBlockedByUpdate(NO_UPDATE_GATE)).toBe(false);
  });
});

describe("required-update banner", () => {
  test("counts down to the deadline", () => {
    expect(formatUpdateCountdown(required.deadline, NOW)).toBe("5h 12m");
    expect(formatUpdateCountdown(required.deadline, NOW + 5 * 3_600_000)).toBe("12m");
    expect(formatUpdateCountdown("2026-10-06T16:00:00Z", NOW)).toBe("2d 4h");
    expect(formatUpdateCountdown(required.deadline, Date.parse(required.deadline!) - 10_000)).toBe("less than a minute");
    expect(formatUpdateCountdown(null, NOW)).toBeNull();
  });

  test("names the required version", () => {
    expect(updateBannerText(required, "OmniRush.ai", NOW)).toBe("OmniRush.ai 3.1.0 is required in 5h 12m");
    expect(updateBannerText({ ...required, minimum: null, deadline: null }, "OmniRush.ai", NOW)).toBe("A newer OmniRush.ai is required");
  });

  test("renders the countdown and a button that says what it does, with no way to dismiss it", () => {
    const html = renderToStaticMarkup(
      <RequiredUpdateBanner gate={required} appName="OmniRush.ai" update={fakeUpdate({ label: "Restart to update" })} />,
    );
    expect(html).toContain("data-testid=\"update-required-banner\"");
    expect(html).toMatch(/OmniRush\.ai 3\.1\.0 is required in \d+(d \d+h|h \d+m|m)|less than a minute/);
    expect(html).toContain("Restart to update");
    expect(html.toLowerCase()).not.toContain("dismiss");
    expect(html).not.toContain("aria-label=\"Close\"");
  });
});

describe("blocked view", () => {
  test("is full-screen, shows the server message, both versions and the download progress", () => {
    const html = renderToStaticMarkup(
      <UpdateRequiredView gate={blocked} appName="OmniRush.ai" update={fakeUpdate({ label: "Downloading 3.1.1… 40%", working: true })} />,
    );
    expect(html).toContain("data-testid=\"update-required-view\"");
    expect(html).toContain("fixed inset-0");
    expect(html).toContain("Update required");
    expect(html).toContain(blocked.message!);
    expect(html).toContain(">3.0.2<");
    expect(html).toContain(">3.1.0<");
    expect(html).toContain("Downloading 3.1.1… 40%");
    expect(html).toContain("keep uploading in the background");
    expect(html).toContain("Open the download page instead");
  });

  test("shows the install command for a package install", () => {
    const command = "sudo apt install /home/pat/Downloads/omnirush-linux-amd64-3.1.1.deb";
    const html = renderToStaticMarkup(
      <UpdateRequiredView gate={blocked} appName="OmniRush.ai" update={fakeUpdate({ label: "Copy install command", command })} />,
    );
    expect(html).toContain("data-testid=\"update-install-command\"");
    expect(html).toContain(command);
    expect(html).toContain("Copy install command");
    expect(html).toContain("Show the downloaded file");
  });
});

describe("Update now", () => {
  test("installs a staged update in place (Linux AppImage, Windows, macOS signed or not)", () => {
    expect(requiredUpdateAction({ supported: true, installMode: "in-place", updaterState: "ready" })).toBe("install");
    expect(requiredUpdateAction({ supported: true, installMode: "in-place", updaterState: "available" })).toBe("download-then-install");
    expect(requiredUpdateAction({ supported: true, installMode: "in-place", updaterState: null })).toBe("download-then-install");
    expect(requiredUpdateAction({ supported: true, installMode: "in-place", updaterState: "downloading" })).toBe("wait");
  });

  test("opens download_url only where the app cannot replace itself, and says so", () => {
    // A translocated macOS copy (run from Downloads) cannot be replaced.
    expect(requiredUpdateAction({ supported: true, installMode: "manual-dmg", updaterState: "ready" })).toBe("open-download");
    // A tar.gz install: no package in the feed.
    expect(requiredUpdateAction({ supported: true, installMode: "package", packageKind: null, updaterState: "available" })).toBe("open-download");
    expect(updateButtonLabel({ action: "open-download" })).toBe("Open download page");
    expect(requiredUpdateAction({ supported: false, installMode: null, updaterState: null })).toBe("open-download");
    expect(requiredUpdateAction({ supported: true, installMode: "in-place", updaterState: "blocked" })).toBe("open-download");
  });

  test("tries the download again after a failed check or download", () => {
    expect(requiredUpdateAction({ supported: true, installMode: "in-place", updaterState: "error" })).toBe("download-then-install");
    expect(updateButtonLabel({ action: "download-then-install", updaterState: "error" })).toBe("Try the update again");
  });

  test("a package install downloads the package and then offers its command", () => {
    const base = { supported: true, installMode: "package" as const, packageKind: "deb" };
    expect(requiredUpdateAction({ ...base, updaterState: "available" })).toBe("download-package");
    expect(requiredUpdateAction({ ...base, updaterState: "downloading" })).toBe("wait");
    expect(requiredUpdateAction({ ...base, updaterState: "ready" })).toBe("copy-command");
    expect(updateButtonLabel({ action: "download-package", version: "3.1.1", packageKind: "deb" })).toBe("Download 3.1.1 (.deb)");
    expect(updateButtonLabel({ action: "copy-command" })).toBe("Copy install command");
  });

  test("the button says what happens: progress while downloading, then restart", () => {
    expect(updateButtonLabel({ action: "wait", updaterState: "downloading", version: "3.1.1", progress: 42 })).toBe("Downloading 3.1.1… 42%");
    expect(updateButtonLabel({ action: "wait", updaterState: "checking" })).toBe("Checking for the update…");
    expect(updateButtonLabel({ action: "install" })).toBe("Restart to update");
    expect(updateButtonLabel({ action: "install", restarting: true })).toBe("Restarting…");
    expect(updateButtonLabel({ action: "download-then-install" })).toBe("Update and restart");
  });

  test("nothing opens a browser by itself", () => {
    const hook = read("../src/react-app/shell/update-gate.tsx");
    // openDownload runs only from the "open-download" action and the explicit links.
    expect(hook.match(/openDownload\(/g)?.length).toBe(4);
    expect(hook).toContain('case "open-download":\n        openDownload(gate.downloadUrl);');
  });

  test("a restart that did not go through offers the manual download beside the retry", () => {
    const failed = renderToStaticMarkup(
      <RequiredUpdateBanner gate={required} appName="OmniRush.ai" update={fakeUpdate({ installFailed: true, detail: "The update did not finish: moved" })} />,
    );
    expect(failed).toContain('data-testid="update-required-banner-download"');
    expect(failed).toContain("Download manually");
    const fine = renderToStaticMarkup(<RequiredUpdateBanner gate={required} appName="OmniRush.ai" update={fakeUpdate()} />);
    expect(fine).not.toContain("update-required-banner-download");
  });

  test("Restarting… never spins forever: the main answer and the quit both have a watchdog", () => {
    const state = read("../src/react-app/domains/settings/state/electron-updater-state.ts");
    expect(state).toContain("withRestartWatchdog(bridge.installAndRestart())");
    expect(state).toContain("RESTART_STALLED_MS");
    expect(state).toContain('result?.fallback === "move-to-applications"');
  });

  test("the download starts in the background as soon as an update is required", () => {
    const base = { supported: true, installMode: "in-place" as const };
    expect(shouldStartBackgroundDownload({ ...base, gate: required, updaterState: null })).toBe(true);
    expect(shouldStartBackgroundDownload({ ...base, gate: blocked, updaterState: "idle" })).toBe(true);
    expect(shouldStartBackgroundDownload({ ...base, gate: required, updaterState: "downloading" })).toBe(false);
    expect(shouldStartBackgroundDownload({ ...base, gate: required, updaterState: "ready" })).toBe(false);
    expect(shouldStartBackgroundDownload({ ...base, gate: NO_UPDATE_GATE, updaterState: null })).toBe(false);
    expect(shouldStartBackgroundDownload({ supported: true, installMode: "manual-dmg", gate: required, updaterState: null })).toBe(false);
    // A package lands in Downloads: it waits for a click.
    expect(shouldStartBackgroundDownload({ supported: true, installMode: "package", gate: required, updaterState: null })).toBe(false);
  });
});

describe("required version the feed does not offer", () => {
  // 3.3.8 was published after 3.4.1 and marked Latest while the server
  // required 3.4.1: the check found nothing newer, the button spin and stopped.
  const gated: UpdateGateState = { ...blocked, current: "3.3.8", minimum: "3.4.1" };

  test("a finished check with nothing newer is a dead end the gate names", () => {
    const message = requiredUpdateUnreachable({ gate: gated, updaterState: "idle", checkedAt: NOW, feedVersion: "3.3.8" });
    expect(message).toContain("3.4.1 or newer is required");
    expect(message).toContain("nothing newer than 3.3.8");
    expect(message).toContain("newest published release is 3.3.8");
    expect(message).toContain("download page");
  });

  test("is not reported before a check finished, while it runs, or without a gate", () => {
    expect(requiredUpdateUnreachable({ gate: gated, updaterState: "idle", checkedAt: null })).toBeNull();
    expect(requiredUpdateUnreachable({ gate: gated, updaterState: null, checkedAt: NOW })).toBeNull();
    expect(requiredUpdateUnreachable({ gate: gated, updaterState: "checking", checkedAt: NOW })).toBeNull();
    expect(requiredUpdateUnreachable({ gate: gated, updaterState: "available", checkedAt: NOW })).toBeNull();
    expect(requiredUpdateUnreachable({ gate: NO_UPDATE_GATE, updaterState: "idle", checkedAt: NOW })).toBeNull();
  });

  test("the button opens the download page instead of retrying a check that cannot help", () => {
    const action = requiredUpdateAction({ supported: true, installMode: "in-place", updaterState: "idle", unreachable: true });
    expect(action).toBe("open-download");
    expect(updateButtonLabel({ action })).toBe("Open download page");
    expect(requiredUpdateAction({ supported: true, installMode: "package", packageKind: "deb", updaterState: "idle", unreachable: true })).toBe("open-download");
    // A newer release appearing later turns the button back into the update.
    expect(requiredUpdateAction({ supported: true, installMode: "in-place", updaterState: "available", unreachable: false })).toBe("download-then-install");
  });

  test("the blocked view shows why instead of an idle button", () => {
    const message = requiredUpdateUnreachable({ gate: gated, updaterState: "idle", checkedAt: NOW, feedVersion: "3.3.8" });
    const html = renderToStaticMarkup(
      <UpdateRequiredView gate={gated} appName="OmniRush.ai" update={fakeUpdate({ detail: message, label: "Open download page" })} />,
    );
    expect(html).toContain("nothing newer than 3.3.8");
    expect(html).toContain("Open download page");
  });

  test("an install request ends when the check finds nothing", () => {
    const hook = read("../src/react-app/shell/update-gate.tsx");
    expect(hook).toContain('(updaterState === "idle" && status?.lastCheckedAt)');
  });
});

describe("wiring", () => {
  test("both composers are disabled while the gate blocks", () => {
    expect(read("../src/react-app/domains/session/surface/session-surface.tsx")).toMatch(/disabled=\{[^}]*\|\| updateBlocked\}/);
    expect(read("../src/react-app/domains/session/chat/new-task-composer.tsx")).toMatch(/disabled=\{[^}]*\|\| updateBlocked\}/);
    useUpdateGateStore.getState().set(blocked);
    expect(chatBlockedByUpdate(useUpdateGateStore.getState().state)).toBe(true);
    useUpdateGateStore.getState().set(NO_UPDATE_GATE);
  });

  test("the gate only covers the UI: it never stops the session uploader or signs out", () => {
    const gate = read("../src/react-app/shell/update-gate.tsx") + read("../src/app/lib/update-gate.ts");
    for (const forbidden of ["signOut", "omnirushAccountSignOut", "omnirushServerRestart", "capture", "uploader", "nuke"]) {
      expect(gate).not.toContain(forbidden);
    }
    // The blocked view overlays the app instead of unmounting it.
    expect(read("../src/react-app/shell/update-gate.tsx")).toContain("{children}");
  });
});
