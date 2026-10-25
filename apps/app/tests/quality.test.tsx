import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";

import {
  DEFAULT_WHEEL_SEGMENTS,
  NOTICE_SEEN_STORAGE_KEY,
  canSpinNow,
  countUpValue,
  jackpotIndex,
  refreshAccountStatus,
  setQualitySessionId,
  nearMissText,
  noticeToShow,
  nudgeToShow,
  qualityBadgeText,
  readPref,
  sliceAtPointer,
  spinPayoutText,
  spinRefusalMessage,
  useAccountStatusStore,
  wheelEaseOut,
  wheelSlices,
  wheelTargetRotation,
  writePref,
  type AccountQuality,
  type QualitySpin,
  type QualityTier,
} from "../src/app/lib/quality";
import { QualityTierBadge, SpinCounts, streakText } from "../src/react-app/domains/quality/quality-parts";
import { QualityNoticeCard, QualityRewards, SessionReasons, failLabel } from "../src/react-app/domains/quality/quality-notice";
import { QualitySpinPanel, RecentSpins } from "../src/react-app/domains/quality/quality-spin-dialog";
import { WHEEL_LANDED_FILL, wheelSliceFill } from "../src/react-app/domains/quality/quality-wheel";

const quality: AccountQuality = {
  tier: "gold",
  score: 0.52,
  tokensMultiplier: 1,
  spinsAvailable: 2,
  reproSpinsAvailable: 1,
  clientSpinsAvailable: 0,
  spinsExpireAt: "2026-10-06T10:00:00Z",
  nextTierHint: "Score 0.52. Stay above 0.45 to keep Gold.",
  tips: ["Start omnirush inside the project folder, not ~, and keep edits there.", "Add tests: tested work earns spins."],
  notice: { id: "spins-1", kind: "spins", title: "You earned 2 spins", body: "Two sessions in my-app were reproducible." },
  notices: [{ id: "spins-1", kind: "spins", title: "You earned 2 spins", body: "Two sessions in my-app were reproducible." }],
  mode: "enforce",
  resting: false,
  preview: false,
  streakDays: 4,
  streakMultiplier: 1,
  streakNext: { days: 7, bonusSpins: 2 },
  nextSpinHint: { progress: 0.6, text: "Add tests to earn a spin.", sessionId: "ses_1" },
  biggestWinToday: { tokens: 10_000_000, at: "2026-10-04T09:00:00Z" },
  nudge: null,
  windowsCounts: false,
};

const spin: QualitySpin = {
  tokens: 1_000_000,
  prizeTokens: 1_000_000,
  segmentIndex: 2,
  segments: DEFAULT_WHEEL_SEGMENTS,
  preview: false,
  capped: false,
  reproducible: true,
  alreadySpin: false,
  spinAt: "2026-10-04T12:00:00Z",
  spinsAvailable: 1,
  potBalance: 12_500_000,
  celebrate: "none",
  nearMiss: false,
  jackpotTokens: 10_000_000,
  streakDays: 4,
  clientGrade: false,
};

function memoryStorage() {
  const values = new Map<string, string>();
  return { getItem: (key: string) => values.get(key) ?? null, setItem: (key: string, value: string) => void values.set(key, value) };
}

describe("tier badge", () => {
  const labels: Record<QualityTier, string> = { new: "New", standard: "Standard", gold: "Gold", coaching: "Coaching", limited: "Limited" };
  for (const [tier, label] of (Object.entries(labels) as [QualityTier, string][]).filter(([tier]) => tier !== "new")) {
    test(`shows ${label} for ${tier}`, () => {
      const html = renderToStaticMarkup(<QualityTierBadge quality={{ ...quality, tier, preview: false }} />);
      expect(html).toContain(`data-tier="${tier}"`);
      expect(html).toContain(`>${label}</span>`);
      expect(html).not.toContain("data-preview");
    });
  }

  test("new: no badge beside the name", () => {
    expect(renderToStaticMarkup(<QualityTierBadge quality={{ ...quality, tier: "new", preview: true }} />)).toBe("");
  });

  test("preview: the tier alone, preview only in the tooltip", () => {
    const html = renderToStaticMarkup(<QualityTierBadge quality={{ ...quality, preview: true }} />);
    expect(qualityBadgeText({ ...quality, preview: true })).toBe("Gold");
    expect(html).toContain(">Gold</span>");
    expect(html).not.toContain("Preview<");
    expect(html).not.toContain("border-dashed");
    expect(html).toContain("preview: spins pay 0 tokens");
  });

  test("renders nothing while quality is null (feature off)", () => {
    expect(renderToStaticMarkup(<QualityTierBadge quality={null} />)).toBe("");
  });

  test("the quality overlay renders nothing while quality is null, or signed out", () => {
    useAccountStatusStore.getState().set({ connected: true, gatewayConfigured: true, quality: null });
    expect(renderToStaticMarkup(<QualityRewards />)).toBe("");
    useAccountStatusStore.getState().set({ connected: false, gatewayConfigured: true, quality });
    expect(renderToStaticMarkup(<QualityRewards />)).toBe("");
    useAccountStatusStore.getState().set(null);
  });
});

describe("notice: once per id", () => {
  test("a notice shows until its id is seen; a new id shows again", () => {
    const storage = memoryStorage();
    expect(noticeToShow(quality, readPref(NOTICE_SEEN_STORAGE_KEY, storage))?.id).toBe("spins-1");
    writePref(NOTICE_SEEN_STORAGE_KEY, "spins-1", storage);
    expect(noticeToShow(quality, readPref(NOTICE_SEEN_STORAGE_KEY, storage))).toBeNull();
    const next = { id: "tier-gold-2", kind: "tier-gold", title: "You reached Gold", body: "" };
    expect(noticeToShow({ ...quality, notice: next, notices: [next, quality.notices[0]] }, "spins-1")?.id).toBe("tier-gold-2");
    expect(noticeToShow({ ...quality, notice: null, notices: [] }, null)).toBeNull();
    expect(noticeToShow(null, null)).toBeNull();
  });

  test("the nudge shows only when the server sends one, once per id", () => {
    expect(nudgeToShow(quality, null)).toBeNull();
    const nudged = { ...quality, nudge: { id: "nudge-1", text: "This session can earn spins: add tests." } };
    expect(nudgeToShow(nudged, null)?.text).toContain("add tests");
    expect(nudgeToShow(nudged, "nudge-1")).toBeNull();
  });

  test("the popup shows the notice, the tips and a Spin button while spins are ready", () => {
    const html = renderToStaticMarkup(
      <QualityNoticeCard quality={quality} notice={quality.notice} onSpin={() => undefined} onDismiss={() => undefined} />,
    );
    expect(html).toContain("data-notice-id=\"spins-1\"");
    expect(html).toContain("You earned 2 spins");
    expect(html).toContain("Two sessions in my-app were reproducible.");
    expect(html).toContain("keep edits there.");
    expect(html).toContain("data-testid=\"quality-notice-spin\"");
    expect(html).toContain("Spin (2)");
    expect(html).toContain("4-day streak");
    expect(html).toContain("Next spin · 60%");
    expect(html).not.toContain("WSL");
    // The app's toast style: theme surfaces, sentence case, no coloured bar or eyebrow.
    expect(html).toContain("bg-popover");
    expect(html).not.toMatch(/uppercase|tracking-\[|#a3e635|#0b1120|shadow-\[0_0/);
  });

  test("the popup's guide has no WSL tip, whatever windows_counts says", () => {
    for (const windowsCounts of [true, false]) {
      const html = renderToStaticMarkup(
        <QualityNoticeCard quality={{ ...quality, windowsCounts }} notice={quality.notice} onSpin={() => undefined} onDismiss={() => undefined} />,
      );
      expect(html).toContain("How to make a Good session");
      expect(html).not.toContain("WSL");
    }
  });

  test("no Spin button without spins; a resting wheel says so", () => {
    const none = renderToStaticMarkup(
      <QualityNoticeCard quality={{ ...quality, spinsAvailable: 0, reproSpinsAvailable: 0 }} notice={quality.notice} onSpin={() => undefined} onDismiss={() => undefined} />,
    );
    expect(none).not.toContain("quality-notice-spin");
    const resting = { ...quality, resting: true, reproSpinsAvailable: 0 };
    expect(canSpinNow(resting)).toBe(false);
    expect(canSpinNow({ ...resting, reproSpinsAvailable: 1 })).toBe(true);
    const html = renderToStaticMarkup(<QualityNoticeCard quality={resting} notice={null} onSpin={() => undefined} onDismiss={() => undefined} />);
    expect(html).toContain("The wheel is resting, back tomorrow.");
  });

  test("coaching reads as how to earn spins, with a see-why list", () => {
    const coaching = { ...quality, tier: "coaching" as const, spinsAvailable: 0 };
    const notice = { id: "c-1", kind: "tier-coaching", title: "Here is how to get spins", body: "A few habits make sessions count." };
    const html = renderToStaticMarkup(<QualityNoticeCard quality={coaching} notice={notice} onSpin={() => undefined} onDismiss={() => undefined} />);
    expect(html).toContain("How to earn spins");
    expect(html).toContain("See why");
    expect(html).toContain("data-coaching");
  });

  test("streak text", () => {
    expect(streakText(quality)).toBe("4-day streak · +1 spin per Good session ★ · 7 days: +2");
    expect(streakText({ streakDays: 0, streakMultiplier: 0, streakNext: null })).toBeNull();
  });
});

describe("wheel geometry", () => {
  const slices = wheelSlices(DEFAULT_WHEEL_SEGMENTS);

  test("slices follow the weights and fill the circle", () => {
    expect(slices[0].start).toBe(0);
    expect(slices.at(-1)!.end).toBe(360);
    expect(slices[0].end - slices[0].start).toBeCloseTo(126, 5);
    expect(slices[5].end - slices[5].start).toBeCloseTo(3.6, 5);
  });

  test("the target rotation stops every index under the pointer, after full turns", () => {
    for (let index = 0; index < DEFAULT_WHEEL_SEGMENTS.length; index += 1) {
      for (const from of [0, 137.5, 2_000]) {
        for (const offset of [-0.9, 0, 0.45]) {
          const target = wheelTargetRotation(DEFAULT_WHEEL_SEGMENTS, index, from, 6, offset);
          expect(sliceAtPointer(slices, target)).toBe(index);
          expect(target - from).toBeGreaterThanOrEqual(6 * 360);
          expect(target - from).toBeLessThan(7 * 360);
        }
      }
    }
  });

  test("index 2 (1M) stops at the middle of its slice with no offset", () => {
    const target = wheelTargetRotation(DEFAULT_WHEEL_SEGMENTS, 2, 0, 5);
    // Slice 2 spans 234°..306°: its middle (270°) is turned to the top.
    expect(((-target % 360) + 360) % 360).toBeCloseTo(270, 6);
  });

  test("one ease-out: starts and ends where it should, never goes back, never overshoots", () => {
    const to = wheelTargetRotation(DEFAULT_WHEEL_SEGMENTS, 5, 0, 4);
    expect(wheelEaseOut(0, 0, to)).toBe(0);
    expect(wheelEaseOut(1, 0, to)).toBe(to);
    expect(wheelEaseOut(1.5, 0, to)).toBe(to);
    expect(sliceAtPointer(slices, wheelEaseOut(1, 0, to))).toBe(5);
    let previous = 0;
    let previousStep = Infinity;
    for (let step = 1; step <= 1_000; step += 1) {
      const angle = wheelEaseOut(step / 1_000, 0, to);
      expect(angle).toBeGreaterThanOrEqual(previous);
      expect(angle).toBeLessThanOrEqual(to);
      // Decelerates the whole way: every frame moves less than the one before.
      expect(angle - previous).toBeLessThanOrEqual(previousStep + 1e-9);
      previousStep = angle - previous;
      previous = angle;
    }
  });
});

describe("spin results", () => {
  test("refusals read as the API asks", () => {
    expect(spinRefusalMessage("wheel_resting")).toBe("The wheel is resting, back tomorrow.");
    expect(spinRefusalMessage("no_spins")).toBe("No spins yet: good sessions earn spins.");
    expect(spinRefusalMessage("quality_rewards_off")).toContain("switched off");
  });

  test("paid, preview and capped", () => {
    expect(spinPayoutText(spin)).toBe("+1M tokens added to your pot");
    expect(spinPayoutText({ ...spin, preview: true, tokens: 0 })).toBe("Preview: no tokens paid");
    expect(spinPayoutText({ ...spin, capped: true, tokens: 0 })).toBe("Pot cap reached: this spin pays 0");
  });

  test("the near-miss tease only when the server flags it", () => {
    expect(nearMissText(spin)).toBeNull();
    expect(nearMissText({ ...spin, nearMiss: true, segmentIndex: 4 })).toBe("So close to 10M!");
  });

  test("the dialog shows the wheel, the odds and the Spin button", () => {
    const html = renderToStaticMarkup(<QualitySpinPanel quality={quality} onClose={() => undefined} />);
    expect(html).toContain("data-testid=\"quality-wheel\"");
    // The legend: each prize with its chance, one row per segment, the slice's tint as the swatch.
    expect(html).toContain("data-testid=\"quality-wheel-legend\"");
    expect(html).toMatch(/10M<\/span><\/td><td[^>]*>1%<\/td>/);
    expect(html).toMatch(/250K<\/span><\/td><td[^>]*>35%<\/td>/);
    expect(html).toContain("Spin for tokens");
    // The app's theme only: no hardcoded navy, lime glow, confetti or all-caps.
    expect(html).not.toMatch(/#0b1120|#a3e635|shadow-\[0_0|uppercase|<canvas/);
    expect(html).toContain("Spin (2 ready)");
    expect(html).toContain("Today&#x27;s biggest win: 10M tokens");
  });

  test("the wheel uses theme tints, and the accent only for the landed slice", () => {
    expect(wheelSliceFill(0, 6)).toBe("var(--slate-4)");
    expect(wheelSliceFill(5, 6)).toBe("var(--slate-9)");
    expect(WHEEL_LANDED_FILL).toBe("var(--lime-9)");
    const html = renderToStaticMarkup(<QualitySpinPanel quality={quality} onClose={() => undefined} />);
    expect(html).not.toContain(WHEEL_LANDED_FILL);
    expect(html).not.toContain("data-landed=");
  });
});

describe("revision: fail labels, jackpot, open session", () => {
  test("fail codes read with the server's labels, a fallback otherwise", () => {
    expect(failLabel("outside_path", { outside_path: "Edits outside the project folder" })).toBe("Edits outside the project folder");
    expect(failLabel("outside_path")).toBe("edits outside the project folder");
    expect(failLabel("capture_truncated")).toBe("capture truncated");
    expect(failLabel("old_client")).toBe("old app version");
    expect(failLabel("x", { x: "Recorded by an old client" })).toBe("Recorded by an old app version");
    const html = renderToStaticMarkup(
      <SessionReasons
        reasons={{
          failLabels: { home_folder: "Started in your home folder" },
          sessions: [{
            sessionId: "ses_1", at: null, verdict: "review", why: "Started in ~.", fails: ["home_folder"], workspace: "my-app", spins: 0, counted: true,
            reproducible: "pass", reproClient: "fail", clientGrade: false, workSize: 3, work: { codeFiles: 3, linesChanged: 120, toolCalls: 14, testRuns: 0, floor: 2, step: 3 },
          }],
        }}
      />,
    );
    expect(html).toContain("Started in your home folder");
    expect(html).toContain("3 code files · 120 lines · no tests");
    expect(html).toContain("Reproducible ✓");
    expect(html).not.toContain("Good session ★");
    expect(html).toContain("+2 spins on a richer wheel");
  });

  test("the sidebar row shows the ready count, and a ★ count only for Good session spins", () => {
    const plain = renderToStaticMarkup(<SpinCounts quality={quality} />);
    expect(plain).toContain("2 ready");
    expect(plain).not.toContain("quality-client-spins");
    const starred = renderToStaticMarkup(<SpinCounts quality={{ ...quality, clientSpinsAvailable: 1 }} />);
    expect(starred).toContain("data-testid=\"quality-client-spins\"");
    expect(starred).toContain("★1");
    expect(renderToStaticMarkup(<SpinCounts quality={{ ...quality, spinsAvailable: 0 }} />)).toBe("");
  });

  test("a Good session shows the star instead of the check", () => {
    const html = renderToStaticMarkup(
      <SessionReasons
        reasons={{
          failLabels: {},
          sessions: [{
            sessionId: "ses_2", at: null, verdict: "recommended", why: "Replays on a clean machine.", fails: [], workspace: "my-app", spins: 4, counted: true,
            reproducible: "pass", reproClient: "pass", clientGrade: true, workSize: 4, work: null,
          }],
        }}
      />,
    );
    expect(html).toContain("Good session ★");
    expect(html).not.toContain("Reproducible ✓");
  });

  test("the jackpot slice is the segment paying jackpot_tokens", () => {
    expect(jackpotIndex(DEFAULT_WHEEL_SEGMENTS, 10_000_000)).toBe(5);
    expect(jackpotIndex(DEFAULT_WHEEL_SEGMENTS, 5_000_000)).toBe(4);
    expect(jackpotIndex(DEFAULT_WHEEL_SEGMENTS, null)).toBe(5);
    expect(nearMissText({ ...spin, nearMiss: true, jackpotTokens: null }, 20_000_000)).toBe("So close to 20M!");
  });

  test("profile reads name the open session", async () => {
    const calls: unknown[] = [];
    const read = async (options?: { sessionId?: string | null }) => {
      calls.push(options ?? null);
      return { connected: true, gatewayConfigured: true, quality: null };
    };
    setQualitySessionId("ses_open");
    await refreshAccountStatus(read);
    setQualitySessionId(null);
    await refreshAccountStatus(read);
    expect(calls).toEqual([{ sessionId: "ses_open" }, null]);
    useAccountStatusStore.getState().set(null);
  });
});

describe("Good session wording, history and the count-up", () => {
  test("users never read the word client", () => {
    const starred = { ...quality, clientSpinsAvailable: 2, tier: "coaching" as const };
    const notice = { id: "c-1", kind: "tier-coaching", title: "Here is how to get spins", body: "" };
    const html = [
      renderToStaticMarkup(<SpinCounts quality={starred} />),
      renderToStaticMarkup(<QualityNoticeCard quality={starred} notice={notice} onSpin={() => undefined} onDismiss={() => undefined} />),
      renderToStaticMarkup(<QualitySpinPanel quality={starred} onClose={() => undefined} />),
      renderToStaticMarkup(
        <SessionReasons
          reasons={{
            failLabels: {},
            sessions: [{
              sessionId: "s", at: null, verdict: null, why: null, fails: ["old_client", "client_tool"], workspace: null, spins: 2, counted: true,
              reproducible: "pass", reproClient: "pass", clientGrade: true, workSize: null, work: null,
            }],
          }}
        />,
      ),
      renderToStaticMarkup(<RecentSpins spins={[{ id: "a", status: "spin", reason: null, reproducible: true, clientGrade: true, sessionId: null, earnedAt: null, expiresAt: null, spinAt: null, prizeTokens: 2_000_000, paidTokens: 2_000_000 }]} />),
    ].join("\n");
    // Only attribute values (test ids, data-*) may say "client"; no text a user reads.
    const text = html.replace(/<[^>]*>/g, " ");
    expect(text.toLowerCase()).not.toContain("client");
    expect(text).toContain("old app version");
    expect(text).toContain("Good session ★");
    expect(text).toContain("Good sessions earn +2 spins on a richer wheel.");
    expect(text.toLowerCase()).not.toContain("replay-ready");
  });

  test("recent spins: the last 10, ★ on Good session ones", () => {
    const spins = Array.from({ length: 12 }, (_, index) => ({
      id: `s${index}`, status: "spin" as const, reason: null, reproducible: true, clientGrade: index % 2 === 0, sessionId: null,
      earnedAt: null, expiresAt: null, spinAt: null, prizeTokens: 500_000, paidTokens: 500_000,
    }));
    const html = renderToStaticMarkup(<RecentSpins spins={spins} />);
    expect(html.match(/<li /g)?.length).toBe(10);
    expect(html.match(/data-good-session/g)?.length).toBe(5);
    expect(html).toContain("★ 500K");
    expect(renderToStaticMarkup(<RecentSpins spins={[]} />)).toBe("");
  });

  test("recent spins without prize tokens display 'spin'", () => {
    const spins = [{ id: "s1", status: "spin" as const, reason: null, reproducible: true, clientGrade: false, sessionId: null, earnedAt: null, expiresAt: null, spinAt: null, prizeTokens: null, paidTokens: null }];
    const html = renderToStaticMarkup(<RecentSpins spins={spins} />);
    expect(html).toContain("spin");
  });

  test("the count-up ends exactly on the server's prize and never passes it", () => {
    for (const value of [0, 250_000, 1_000_000, 1_234_567, 9_999_999, 10_000_000]) {
      let last = 0;
      for (let step = 0; step <= 100; step += 1) {
        const shown = countUpValue(value, step / 100);
        expect(shown).toBeLessThanOrEqual(value);
        expect(shown).toBeGreaterThanOrEqual(last);
        last = shown;
      }
      expect(countUpValue(value, 1)).toBe(value);
      expect(countUpValue(value, 1.5)).toBe(value);
      if (value > 0) expect(countUpValue(value, 0.999)).toBeLessThan(value);
    }
  });
});
