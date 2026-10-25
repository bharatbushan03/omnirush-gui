/** @jsxImportSource react */
import { useCallback, useEffect, useState, type ComponentType, type ReactNode } from "react";
import { Loader2, Volume2, VolumeX } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogTitle } from "@/components/ui/dialog";
import { cn } from "@/lib/utils";
import type { OmniRushQualitySpinRecord, OmniRushQualitySpinTotals } from "@omnirush/types/desktop-ipc";

import { omnirushAccountStatus, omnirushQualityDetails, omnirushQualitySpin, omnirushQualitySpins } from "../../../app/lib/desktop";
import { compactTokenCount } from "../../../app/lib/omnirush-usage";
import {
  CLIENT_GRADE_NOTE,
  GOOD_SESSION_STAR_LABEL,
  countUpValue,
  DEFAULT_WHEEL_SEGMENTS,
  SOUND_STORAGE_KEY,
  canSpinNow,
  nearMissText,
  newSpinIdempotencyKey,
  readPref,
  refreshAccountStatus,
  segmentOdds,
  spinPayoutText,
  spinRefusalMessage,
  writePref,
  type AccountQuality,
  type QualitySpin,
  type QualitySpinOutcome,
  type WheelSegment,
} from "../../../app/lib/quality";
import { BiggestWinTicker, QualityTierBadge, StreakLine } from "./quality-parts";
import { QualityWheel, WHEEL_LANDED_FILL, wheelSliceFill } from "./quality-wheel";

export function usePrefersReducedMotion(): boolean {
  const [reduced, setReduced] = useState(() =>
    typeof window !== "undefined" && typeof window.matchMedia === "function"
      ? window.matchMedia("(prefers-reduced-motion: reduce)").matches
      : false,
  );
  useEffect(() => {
    if (typeof window.matchMedia !== "function") return;
    const media = window.matchMedia("(prefers-reduced-motion: reduce)");
    const listener = () => setReduced(media.matches);
    media.addEventListener?.("change", listener);
    return () => media.removeEventListener?.("change", listener);
  }, []);
  return reduced;
}

/**
 * Counts up to `value` once `active`; jumps straight there with reduced
 * motion. `done` only once the shown number is exactly `value`.
 */
function useCountUp(value: number, active: boolean, reducedMotion: boolean, durationMs = 1_400): { shown: number; done: boolean } {
  const [shown, setShown] = useState(0);
  useEffect(() => {
    if (!active) {
      setShown(0);
      return;
    }
    if (reducedMotion) {
      setShown(value);
      return;
    }
    let frame = 0;
    const started = performance.now();
    const step = (now: number) => {
      const progress = Math.min(1, (now - started) / durationMs);
      setShown(countUpValue(value, progress));
      if (progress < 1) frame = requestAnimationFrame(step);
    };
    frame = requestAnimationFrame(step);
    return () => cancelAnimationFrame(frame);
  }, [active, durationMs, reducedMotion, value]);
  return { shown, done: active && shown === value };
}

type Phase = "idle" | "requesting" | "spinning" | "result" | "error";

function recentSpinLabel(spin: OmniRushQualitySpinRecord): string {
  if (spin.status === "spin") return spin.prizeTokens !== null ? compactTokenCount(spin.prizeTokens) : "spin";
  return spin.status === "ready" ? "ready" : spin.status;
}

/** The last spins (newest first) as one muted line, ★ on the Good session ones. */
export function RecentSpins({ spins }: { spins: OmniRushQualitySpinRecord[] }) {
  const shown = spins.slice(0, 10);
  if (!shown.length) return null;
  return (
    <div className="flex min-w-0 flex-wrap items-baseline gap-x-1.5 text-xs text-muted-foreground" data-testid="quality-recent-spins">
      <span>Recent spins:</span>
      <ul className="contents">
        {shown.map((spin, index) => (
          <li
            key={spin.id}
            data-good-session={spin.clientGrade ? "" : undefined}
            title={spin.clientGrade ? GOOD_SESSION_STAR_LABEL : spin.status}
            className="tabular-nums"
          >
            {spin.clientGrade ? "★ " : ""}
            {recentSpinLabel(spin)}
            {index < shown.length - 1 ? <span aria-hidden="true">,</span> : null}
          </li>
        ))}
      </ul>
    </div>
  );
}

/** Each prize with its chance; the swatch is the slice's tint, the accent once landed. */
function WheelLegend({ segments, landedIndex }: { segments: WheelSegment[]; landedIndex: number | null }) {
  return (
    <table className="w-full text-xs tabular-nums" data-testid="quality-wheel-legend">
      <thead>
        <tr className="text-muted-foreground">
          <th className="pb-1 text-start font-normal">Prize</th>
          <th className="pb-1 text-end font-normal">Chance</th>
        </tr>
      </thead>
      <tbody>
        {segments.map((segment, index) => {
          const landed = index === landedIndex;
          return (
            <tr
              key={index}
              data-landed={landed ? "" : undefined}
              className={cn("border-t border-border/60", landed ? "font-medium text-foreground" : "text-muted-foreground")}
            >
              <td className="py-1">
                <span className="flex items-center gap-2">
                  <span
                    className="size-2.5 shrink-0 rounded-[3px] ring-1 ring-border ring-inset"
                    style={{ background: landed ? WHEEL_LANDED_FILL : wheelSliceFill(index, segments.length) }}
                    aria-hidden="true"
                  />
                  {compactTokenCount(segment.tokens)}
                </span>
              </td>
              <td className="py-1 text-end">{segmentOdds(segments, index)}</td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

type SlotProps = { id?: string; className?: string; children?: ReactNode };

export type QualitySpinDialogProps = {
  quality: AccountQuality;
  onClose: () => void;
  /** Injected in tests; the desktop bridge otherwise. */
  spin?: (input: { idempotencyKey: string }) => Promise<QualitySpinOutcome>;
};

export type QualitySpinPanelProps = QualitySpinDialogProps & {
  /** The dialog's title and description parts; plain elements outside a dialog (tests). */
  Title?: ComponentType<SlotProps>;
  Description?: ComponentType<SlotProps>;
};

const PlainTitle = (props: SlotProps) => <h2 id={props.id} className={cn("font-heading text-base leading-none font-medium", props.className)}>{props.children}</h2>;
const PlainDescription = (props: SlotProps) => <p className={cn("text-sm text-muted-foreground", props.className)}>{props.children}</p>;

/**
 * The spin dialog's content: the wheel, the prizes with their odds, and the
 * result. The server picks the segment; the wheel animates to it, then the
 * prize counts up and the profile is read again.
 */
export function QualitySpinPanel(props: QualitySpinPanelProps) {
  const { quality } = props;
  const Title = props.Title ?? PlainTitle;
  const Description = props.Description ?? PlainDescription;
  const reducedMotion = usePrefersReducedMotion();
  const [segments, setSegments] = useState<WheelSegment[]>(DEFAULT_WHEEL_SEGMENTS);
  const [expectedTokens, setExpectedTokens] = useState<number | null>(null);
  const [jackpotTokens, setJackpotTokens] = useState<number | null>(null);
  const [clientSegments, setClientSegments] = useState<WheelSegment[]>([]);
  const [totals, setTotals] = useState<OmniRushQualitySpinTotals | null>(null);
  const [phase, setPhase] = useState<Phase>("idle");
  const [result, setResult] = useState<QualitySpin | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [spinId, setSpinId] = useState(0);
  const [soundEnabled, setSoundEnabled] = useState(() => readPref(SOUND_STORAGE_KEY) === "on");
  const spinsLeft = result ? result.spinsAvailable : quality.spinsAvailable;
  const count = useCountUp(result?.prizeTokens ?? 0, phase === "result", reducedMotion);
  const prize = count.shown;
  // The final state (payout, Spin again) waits for the count-up to land on the server's prize.
  const settled = phase === "result" && count.done;

  useEffect(() => {
    let active = true;
    void omnirushQualityDetails()
      .then((details) => {
        if (!active || !details) return;
        if (details.segments.length) setSegments(details.segments);
        setExpectedTokens(details.expectedTokens);
        setJackpotTokens(details.jackpotTokens ?? null);
        setClientSegments(details.clientSegments ?? []);
      })
      .catch(() => undefined);
    void omnirushQualitySpins()
      .then((next) => { if (active) setTotals(next); })
      .catch(() => undefined);
    return () => { active = false; };
  }, []);

  const runSpin = useCallback(async () => {
    if (phase === "requesting" || phase === "spinning") return;
    setPhase("requesting");
    setError(null);
    // One key per click: a retry of this click gets this click's result back.
    const idempotencyKey = newSpinIdempotencyKey();
    const send = props.spin ?? ((input: { idempotencyKey: string }) => omnirushQualitySpin(input));
    let outcome: QualitySpinOutcome;
    try {
      outcome = await send({ idempotencyKey });
    } catch {
      outcome = { ok: false, reason: "unreachable", status: null };
    }
    if (!outcome.ok) {
      setPhase("error");
      setError(spinRefusalMessage(outcome.reason));
      void refreshAccountStatus(omnirushAccountStatus);
      return;
    }
    if (outcome.spin.segments.length) setSegments(outcome.spin.segments);
    setResult(outcome.spin);
    setSpinId((value) => value + 1);
    setPhase("spinning");
  }, [phase, props.spin]);

  const landed = useCallback(() => {
    setPhase("result");
    void refreshAccountStatus(omnirushAccountStatus);
    void omnirushQualitySpins().then(setTotals).catch(() => undefined);
  }, []);

  const toggleSound = () => {
    setSoundEnabled((value) => {
      writePref(SOUND_STORAGE_KEY, value ? "off" : "on");
      return !value;
    });
  };

  const resting = !canSpinNow(quality) && quality.spinsAvailable > 0;
  const tease = result && settled ? nearMissText(result, jackpotTokens) : null;
  const celebrate = result?.celebrate ?? "none";
  const busy = phase === "requesting" || phase === "spinning" || (phase === "result" && !settled);
  const canSpin = !busy && spinsLeft > 0 && !(phase !== "result" && resting);
  // Before a spin: the wheel the next spin uses (the richer one while Good session ★ spins are
  // waiting). From the answer on: the wheel the server actually used.
  const nextIsReplayReady = !result && quality.clientSpinsAvailable > 0 && clientSegments.length > 0;
  const shownSegments = result ? segments : nextIsReplayReady ? clientSegments : segments;
  const replayWheel = result ? (result.clientGrade ? "Good session ★ wheel" : null) : nextIsReplayReady ? "Good session ★ wheel (next spin)" : null;
  const resultLine = result
    ? [
        result.preview || result.capped ? spinPayoutText(result) : result.potBalance !== null ? `Pot: ${compactTokenCount(result.potBalance)} tokens` : "Added to your pot",
        `${spinsLeft} spin${spinsLeft === 1 ? "" : "s"} left`,
        result.alreadySpin ? "already counted" : null,
      ].filter(Boolean).join(" · ")
    : "";

  return (
    <>
      <div className="flex flex-col gap-1.5 pe-20">
        <div className="flex min-w-0 items-center gap-2">
          <Title id="quality-spin-title">Spin for tokens</Title>
          <QualityTierBadge quality={quality} />
        </div>
        <Description>
          {spinsLeft} spin{spinsLeft === 1 ? "" : "s"} ready
          {!result && quality.clientSpinsAvailable > 0 ? (
            <span data-testid="quality-dialog-client-spins"> · ★{quality.clientSpinsAvailable} Good session</span>
          ) : null}
        </Description>
      </div>
      <Button
        type="button"
        variant="ghost"
        size="icon-sm"
        onClick={toggleSound}
        aria-pressed={soundEnabled}
        aria-label={soundEnabled ? "Turn sound off" : "Turn sound on"}
        title={soundEnabled ? "Sound on" : "Sound off"}
        data-testid="quality-sound-toggle"
        className="absolute top-4 inset-e-14 bg-secondary text-muted-foreground"
      >
        {soundEnabled ? <Volume2 /> : <VolumeX />}
      </Button>

      <div className="flex flex-col items-center gap-6 sm:flex-row sm:items-center" data-testid="quality-spin-dialog" data-phase={phase}>
        <QualityWheel
          segments={shownSegments}
          targetIndex={result ? result.segmentIndex : null}
          spinId={spinId}
          onDone={landed}
          celebrate={celebrate}
          soundEnabled={soundEnabled}
          reducedMotion={reducedMotion}
          size={196}
        />
        <div className="flex w-full min-w-0 flex-1 flex-col gap-3">
          {replayWheel ? (
            <Badge variant="outline" className="h-5 font-normal text-muted-foreground" data-testid="quality-client-grade-header">
              {replayWheel}
            </Badge>
          ) : null}
          <WheelLegend segments={shownSegments} landedIndex={result && settled ? result.segmentIndex : null} />
          <div className="flex flex-col gap-0.5">
            <StreakLine quality={quality} />
            <BiggestWinTicker quality={quality} />
          </div>
        </div>
      </div>

      <div className="flex min-h-14 flex-col justify-center gap-1" aria-live="polite">
        {phase === "result" && result ? (
          <div data-testid="quality-spin-result" data-celebrate={celebrate} className="flex flex-col gap-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xl font-semibold tabular-nums" data-testid="quality-spin-prize" data-value={prize}>
                +{compactTokenCount(prize)} tokens
              </span>
              {settled && celebrate === "jackpot" ? <Badge variant="secondary" className="font-normal">Jackpot</Badge> : null}
              {settled && result.clientGrade ? (
                <Badge variant="secondary" className="font-normal text-muted-foreground">{GOOD_SESSION_STAR_LABEL}</Badge>
              ) : settled && result.reproducible ? (
                <Badge variant="secondary" className="font-normal text-muted-foreground">Reproducible</Badge>
              ) : null}
            </div>
            {settled ? (
              <p className="text-sm text-muted-foreground" data-testid="quality-spin-payout">{resultLine}</p>
            ) : null}
            {tease ? <p className="text-xs text-muted-foreground" data-testid="quality-near-miss">{tease}</p> : null}
          </div>
        ) : phase === "error" && error ? (
          <p className="text-sm text-destructive" data-testid="quality-spin-error">{error}</p>
        ) : phase === "spinning" || phase === "requesting" ? (
          <p className="text-sm text-muted-foreground">Spinning…</p>
        ) : resting ? (
          <p className="text-sm text-muted-foreground">The wheel is resting, back tomorrow.</p>
        ) : (
          <>
            <p className="text-sm text-muted-foreground">
              {quality.preview ? "Preview: spins show what you would win, and pay 0 tokens." : "The wheel decides. Every prize goes into your pot."}
              {expectedTokens ? ` Average spin: ${compactTokenCount(expectedTokens)} tokens.` : null}
            </p>
            <p className="text-xs text-muted-foreground" data-testid="quality-client-grade-note">{CLIENT_GRADE_NOTE}</p>
          </>
        )}
        {totals ? <RecentSpins spins={totals.recent ?? []} /> : null}
      </div>

      <DialogFooter className="sm:items-center sm:justify-between">
        <p className="text-xs text-muted-foreground" data-testid="quality-spin-totals">
          {totals && totals.spin > 0
            ? `${totals.spin} spin${totals.spin === 1 ? "" : "s"} so far · ${compactTokenCount(totals.paidTokens)} tokens won`
            : null}
        </p>
        {spinsLeft > 0 || busy ? (
          <Button type="button" onClick={() => void runSpin()} disabled={!canSpin} data-testid="quality-spin-go">
            {busy ? <Loader2 className="animate-spin" aria-hidden="true" /> : null}
            {busy ? "Spinning" : settled ? `Spin again (${spinsLeft} left)` : spinsLeft > 1 ? `Spin (${spinsLeft} ready)` : "Spin"}
          </Button>
        ) : (
          <p className="text-sm text-muted-foreground">No spins left. Good sessions ★ earn more.</p>
        )}
      </DialogFooter>
    </>
  );
}

/** The spin dialog: the app's standard dialog around the spin panel. */
export function QualitySpinDialog(props: QualitySpinDialogProps) {
  return (
    <Dialog open onOpenChange={(open) => { if (!open) props.onClose(); }}>
      <DialogContent className="w-full max-w-lg sm:max-w-lg lg:max-w-lg" data-testid="quality-spin-overlay">
        <QualitySpinPanel {...props} Title={DialogTitle} Description={DialogDescription} />
      </DialogContent>
    </Dialog>
  );
}
