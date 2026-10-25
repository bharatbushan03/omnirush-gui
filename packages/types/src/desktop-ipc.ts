/**
 * Shared contract for the Electron desktop IPC bridge.
 *
 * Producer: apps/desktop/electron/main.mjs — `desktopCommandHandlers`, typed
 * via JSDoc against `DesktopCommandHandlers` so missing/extra/renamed
 * commands fail `typecheck:electron`.
 * Consumer: apps/app/src/app/lib/desktop.ts — the `desktopBridge` Proxy and
 * its named exports derive per-command signatures from `DesktopCommandMap`.
 *
 * Every command sent over the `omnirush:desktop` channel has exactly one
 * entry here: `args` is the tuple the renderer passes, `result` what the
 * main process resolves. Results marked `unknown` are not yet modeled —
 * tighten them instead of widening call sites.
 */
import type { ConnectLinkVerifyFailure, ConnectLinkVerifyResult } from "./connect-link.js";
import type { WorkspaceWire } from "./workspace.js";

// ---------------------------------------------------------------------------
// Payload shapes (moved from apps/app/src/app/lib/desktop-types.ts, which
// re-exports them — keep that file as the app-side import path).
// ---------------------------------------------------------------------------

export type OpencodeExecutionEnvEntry = {
  name: string;
  value: string;
  redacted: boolean;
};

export type OpencodeExecutionSnapshot = {
  command: string;
  args: string[];
  cwd: string;
  env: OpencodeExecutionEnvEntry[];
};

export type EngineInfo = {
  running: boolean;
  runtime: "direct";
  managedByServer: boolean;
  baseUrl: string | null;
  projectDir: string | null;
  hostname: string | null;
  port: number | null;
  opencodeUsername: string | null;
  opencodePassword: string | null;
  opencodeBinPath: string | null;
  opencodeBinSource: string | null;
  pid: number | null;
  lastStdout: string | null;
  lastStderr: string | null;
  execution: OpencodeExecutionSnapshot | null;
};

export type DesktopNotificationInput = {
  title: string;
  body?: string;
  href?: string;
  silent?: boolean;
  /** The chat the notification is about: a click focuses the window and opens it. */
  sessionId?: string;
  workspaceId?: string;
};

/** Sent to the renderer when a notification about a chat is clicked. */
export type DesktopNotificationOpenSession = { sessionId: string; workspaceId?: string };

export type DesktopNotificationResult =
  | { ok: true }
  | { ok: false; reason: string };

export type DesktopIntegrationIssue =
  | "appimage-path"
  | "desktop-entry"
  | "icon"
  | "protocol-handler"
  | "version";

export type DesktopIntegrationStatus = {
  supported: boolean;
  state: "unsupported" | "not_integrated" | "integrated" | "needs_repair" | "managed_externally";
  ownership: "none" | "omnirush" | "external";
  appImagePath: string | null;
  desktopEntryPath: string | null;
  handlerDesktopId: string | null;
  issues: DesktopIntegrationIssue[];
};

export type DesktopIntegrationResult = {
  ok: boolean;
  status: DesktopIntegrationStatus;
  error?: string;
};

/** One built-in server or engine restart, as recorded in runtime-restarts.jsonl. */
export type OmniRushRuntimeRestartRecord = {
  at: string;
  kind: "server" | "engine";
  /** restarting, started, deferred, skipped, dropped, stopping, or restarted (engine watchdog). */
  action: string;
  reason: string;
  source: string;
  [key: string]: unknown;
};

export type OmniRushServerInfo = {
  running: boolean;
  /**
   * Monotonic per-start identity of the embedded server within this desktop
   * process. Sticky ports and persisted tokens keep the connection details
   * identical across restarts, so clients that must re-deliver state to a new
   * server lifetime (e.g. the Connect policy) key on this value. Null when
   * the bridge predates the field or no start completed yet.
   */
  generation: number | null;
  remoteAccessEnabled: boolean;
  host: string | null;
  port: number | null;
  baseUrl: string | null;
  connectUrl: string | null;
  mdnsUrl: string | null;
  lanUrl: string | null;
  clientToken: string | null;
  ownerToken: string | null;
  hostToken: string | null;
  managedOpencodeBinPath: string | null;
  managedOpencodeBinSource: string | null;
  /** Structured server log on disk, or null when the server runs without a file sink. */
  logFilePath: string | null;
  pid: number | null;
  lastStdout: string | null;
  lastStderr: string | null;
  managedOpencodeExecution: OpencodeExecutionSnapshot | null;
  /** Recent restarts, newest first (omnirushServerInfo only). */
  restarts?: OmniRushRuntimeRestartRecord[];
  /** An automatic restart that waits until no session is running. */
  pendingRestart?: { action: string; reason: string; source: string; requestedAt: string } | null;
  /** Set on an omnirushServerRestart answer that kept the running server. */
  restartDeferred?: boolean;
  restartSkipped?: boolean;
};

/** Outcome of the remote device-session revocation attempted during sign-out. */
export type OmniRushAccountSignOutReason =
  /** The account server accepted the revocation (2xx). */
  | "revoked"
  /** The account server no longer knows the device session (401/403, or a 404 naming the session). */
  | "already_revoked"
  /** The account server could not be reached or failed (network error, 5xx, other errors). */
  | "unreachable"
  /** The account server has no device sign-out route (404 route missing, 405, 501). */
  | "endpoint_missing";

export type OmniRushAccountSignOutResult = {
  connected: false;
  remoteRevoked: boolean;
  reason: OmniRushAccountSignOutReason;
};

/**
 * The account's tokens (/device/me `usage`). The first three are what can be
 * used now (the grant left plus the pot). With daily grants (`grantModel`
 * "daily"), `day` is today's allowance (resets 00:00 UTC), `week` the weekly
 * cap over it (resets Monday 00:00 UTC) and `pot` the one-time tokens used
 * once either runs out; `limitScope` "week" means only the weekly cap binds.
 * The grant fields are optional: an older desktop bridge leaves them out.
 */
export type OmniRushAccountUsage = {
  tokenLimit: number;
  usedTokens: number;
  remainingTokens: number;
  period?: "day" | "week";
  grantModel?: "weekly" | "daily" | null;
  limitScope?: "day" | "week" | null;
  day?: { allowance: number; used: number; reserved: number; resetsAt: string | null } | null;
  week?: { limit: number; used: number; resetsAt: string | null } | null;
  pot?: number;
};

/**
 * The account server's word on this app's version (/device/me
 * `client_update`, product "gui"). Required: update before `deadline`;
 * blocked: model requests are refused until the app is updated.
 */
export type OmniRushClientUpdate = {
  required: boolean;
  blocked: boolean;
  current: string | null;
  minimum: string | null;
  /** UTC ISO 8601. */
  deadline: string | null;
  message: string | null;
  downloadUrl: string | null;
};

/**
 * What the app shows for a mandatory update, derived in the Electron main
 * process from `client_update`, the gateway's `x-omnirush-update-required`
 * header and HTTP 426 `update_required` refusals.
 */
export type OmniRushUpdateGateState = {
  status: "none" | "required" | "blocked";
  current: string;
  minimum: string | null;
  deadline: string | null;
  message: string | null;
  downloadUrl: string;
  source: "profile" | "header" | "rejection" | null;
};

export type OmniRushQualityTier = "new" | "standard" | "gold" | "coaching" | "limited";

/**
 * Quality rewards (/device/me `quality`). Absent or null: the feature is
 * off and the app shows nothing. `preview`: spins pay 0 tokens.
 */
export type OmniRushAccountQuality = {
  tier: OmniRushQualityTier;
  /** 0..1 */
  score: number;
  /** Below 1 while "limited" and the cut is in force. */
  tokensMultiplier: number;
  spinsAvailable: number;
  /** Of `spinsAvailable`, those earned by reproducible sessions (always payable). */
  reproSpinsAvailable: number;
  /** Of `spinsAvailable`, those earned by client-grade sessions (the richer wheel). */
  clientSpinsAvailable: number;
  /** UTC ISO 8601, the soonest expiry. */
  spinsExpireAt: string | null;
  nextTierHint: string | null;
  tips: string[];
  /** Shown once per `id`; the same as `notices[0]`. */
  notice: OmniRushQualityNotice | null;
  /** Newest first, up to 5. */
  notices: OmniRushQualityNotice[];
  mode: "shadow" | "enforce";
  /** The daily budget is spent: only reproducible spins can be spin until tomorrow. */
  resting: boolean;
  preview: boolean;
  /** Consecutive UTC days with a reproducible session. */
  streakDays: number;
  /** Extra spins per reproducible good session right now. */
  streakMultiplier: number;
  streakNext: { days: number; bonusSpins: number } | null;
  /** How close the latest session is to earning a spin (progress 0..1). */
  nextSpinHint: { progress: number; text: string; sessionId: string | null } | null;
  /** Anonymised, across all accounts. */
  biggestWinToday: { tokens: number; at: string | null } | null;
  /** Shown once per `id`, only when the server sends one. */
  nudge: { id: string; text: string } | null;
  /** `windows_counts`: the server counts native-Windows sessions for a Good session ★. */
  windowsCounts: boolean;
};

export type OmniRushQualityNotice = { id: string; kind: string | null; title: string; body: string };

/** One session in GET /me/quality: why it earned (or did not earn) spins. */
export type OmniRushQualitySession = {
  sessionId: string;
  at: string | null;
  verdict: string | null;
  why: string | null;
  fails: string[];
  workspace: string | null;
  spins: number;
  counted: boolean;
  /** The reward level of reproducibility. */
  reproducible: "pass" | "fail" | "unknown" | null;
  /** The strict client grade. */
  reproClient: "pass" | "fail" | "unknown" | null;
  /** Client-grade: +2 spins, on the richer wheel. */
  clientGrade: boolean;
  /** The work-size step, 0..4. */
  workSize: number | null;
  work: { codeFiles: number; linesChanged: number; toolCalls: number; testRuns: number; floor: number; step: number } | null;
};

export type OmniRushQualityDetails = {
  segments: OmniRushWheelSegment[];
  /** The richer wheel client-grade spins use. */
  clientSegments: OmniRushWheelSegment[];
  expectedTokens: number | null;
  /** The top segment's prize. */
  jackpotTokens: number | null;
  sessions: OmniRushQualitySession[];
  /** `{code: label}` for the sessions' `fails`. */
  failLabels: Record<string, string>;
};

/**
 * The server's live status for one session (GET /me/sessions/{id}/status).
 * Labels, hints and messages are server text, shown as given. Null from the
 * desktop: the app falls back to its own checklist.
 */
/** Buildathon (GET /omnirush/me/buildathon), parsed by the main process; null unless enrolled. */
export type OmniRushBuildathonTrack = { id: string; label: string };
export type OmniRushBuildathonPhase = "upcoming" | "building" | "judging" | "results" | "closed";
export type OmniRushBuildathonEvent = {
  id: string;
  name: string;
  startsAt: string | null;
  registrationEndsAt: string | null;
  deadlineAt: string;
  resultsAt: string | null;
  phase: OmniRushBuildathonPhase | null;
  pageUrl: string | null;
  submitUrl: string | null;
  rules: string[];
  tracks: OmniRushBuildathonTrack[];
  /** Largest first. */
  reminders: Array<{ beforeSeconds: number; text: string }>;
};
export type OmniRushBuildathonParticipant = {
  enrolledAt: string | null;
  tokensGranted: number;
  tokensUsed: number;
  tokensLeft: number;
  sessionsTagged: number;
  sessionsGood: number;
};
export type OmniRushBuildathonSubmission = {
  submissionId: string;
  submittedAt: string | null;
  updatedAt: string | null;
  track: string | null;
  title: string | null;
  repoUrl: string | null;
  demoVideoUrl: string | null;
  liveUrl: string | null;
  sessionIds: string[];
  checks: Array<{ id: string; ok: boolean; text: string }>;
  locked: boolean;
};
/** The event's reproducibility settings (defaults when the server sends none). */
export type OmniRushBuildathonRepro = {
  box: "on" | "offer" | "off";
  agentRules: string;
  checklist: Array<{ id: string; text: string }>;
};
export type OmniRushBuildathonCheck = { id: string; text: string; ok: boolean | null };
export type OmniRushBuildathonStatus = {
  enrolled: true;
  serverTime: string | null;
  event: OmniRushBuildathonEvent;
  participant: OmniRushBuildathonParticipant | null;
  submission: OmniRushBuildathonSubmission | null;
  repro: OmniRushBuildathonRepro;
  /** The updates feed, newest first (at most 20). */
  announcements: OmniRushBuildathonAnnouncement[];
  /** The linked GitHub account (needed to submit); null when none is linked. */
  github: { login: string; linkedAt: string | null } | null;
};
export type OmniRushBuildathonAnnouncement = {
  id: string;
  title: string;
  /** Plain text; may contain URLs. */
  body: string;
  url: string | null;
  level: "info" | "important";
  publishedAt: string | null;
};
/** A non-participant's promo (GET /me/buildathon `enrolled: false` + `promo`). */
export type OmniRushBuildathonPromo = {
  /** The dismissal key: a new id shows the promo again. */
  id: string;
  title: string;
  text: string | null;
  ctaLabel: string;
  ctaUrl: string | null;
  /** Registration close: hidden after it. */
  endsAt: string | null;
  /** True: open joining (on the web at `joinUrl`, which links GitHub; without one, POST /me/buildathon/join). */
  join: boolean;
  joinUrl: string | null;
};
export type OmniRushBuildathonPromoStatus = { enrolled: false; serverTime: string | null; promo: OmniRushBuildathonPromo };
/** What the app reads from GET /me/buildathon: a participant, a promo, or nothing to show. */
export type OmniRushBuildathonAnswer = OmniRushBuildathonStatus | OmniRushBuildathonPromoStatus | null;
export type OmniRushBuildathonSession = {
  sessionId: string;
  title: string | null;
  project: string | null;
  startedAt: string | null;
  endedAt: string | null;
  track: string | null;
  status: "good" | "pending" | "incomplete";
  reasons: string[];
  tokens: number;
};
export type OmniRushBuildathonLinkResult =
  | { ok: true; status: OmniRushBuildathonStatus }
  | { ok: false; error: string; closed?: boolean };
export type OmniRushBuildathonTagResult = "tagged" | "refused" | "retry";

/** A sponsored placement as the window draws it (apps/desktop/electron/placements/placements.mjs placementView). */
export type OmniRushPlacementSlot = "home_banner" | "turn_footer";
export type OmniRushPlacementSurface = "desktop_home" | "desktop_turn";
export type OmniRushPlacement = {
  id: string;
  /** This display's id (a random UUID made by the main process); every event about it carries it. */
  displayId: string;
  surface: OmniRushPlacementSurface;
  slot: OmniRushPlacementSlot;
  /** "Sponsored · <sponsor>" */
  label: string;
  sponsor: string;
  /** Plain text, at most 60 characters. */
  title: string;
  /** Plain text, at most 140 characters (may be empty). */
  body: string;
  /** At most 20 characters. */
  ctaLabel: string;
  /** https only; opened by the main process after a click. */
  url: string;
  /** https only, or null. */
  imageUrl: string | null;
  snoozeDays: number;
};
/** rendered / viewable / open (the click) / dismiss: about one display; conversation / activity: for the display rotation. */
export type OmniRushPlacementAction = "rendered" | "viewable" | "open" | "dismiss" | "conversation" | "activity";

/** In-app feedback (apps/desktop/electron/feedback-desktop.mjs and the shared feedback/feedback.mjs). */
export type OmniRushFeedbackKind = "turn" | "general" | "pulse";
export type OmniRushFeedbackTrigger = "sampled" | "command" | "menu" | "pulse";
/** How a finished turn ended: only "ok" turns may get the after-turn prompt. */
export type OmniRushFeedbackTurnOutcome = "ok" | "refused" | "limit" | "error" | "stopped";
export type OmniRushFeedbackPolicy = {
  enabled: boolean;
  turnSampleRate: number;
  maxPerDay: number;
  pulseEnabled: boolean;
  pulseAfterSessions: number;
  pulseEveryDays: number;
};
export type OmniRushFeedbackOffer = { kind: "turn" | "pulse" } | null;
export type OmniRushFeedbackInput = {
  kind: OmniRushFeedbackKind;
  /** "up" | "down" for a turn, 0-10 for the pulse, null for anytime feedback. */
  rating: "up" | "down" | number | null;
  categories: string[];
  comment: string | null;
  sessionId: string | null;
  /** 1-based user-turn index of the rated answer. */
  turn: number | null;
  trigger: OmniRushFeedbackTrigger;
  modelId: string | null;
  effort: string | null;
};
/**
 * queued: kept in feedback.json and sent later (offline, signed out, the
 * server has none yet, rate limited). ok false: not sent and not kept: the
 * input ("comment", "kind", "rating"), or the server refused it ("invalid":
 * a 422 with its wrong fields in `errors`; "too_large": a 413).
 */
export type OmniRushFeedbackResult =
  | { ok: true; sent: boolean; queued: boolean; reason?: "offline" | "signed_out" | "unavailable" | "rate_limited" }
  | { ok: false; error: string; errors?: Record<string, string> | null };
export type OmniRushFeedbackStatus = { policy: OmniRushFeedbackPolicy; queued: number; unavailable: boolean; allowed: boolean };

export type OmniRushSessionStatus = {
  sessionId: string;
  status: "on_track" | "at_risk" | "failing" | "unknown";
  reasons: { code: string; message: string }[];
  /** The headline above the checklist. */
  message: string | null;
  dock: {
    mode: "off" | "observe" | "warn" | "enforce";
    stage: "none" | "warn" | "surcharge" | "cap";
    weight: number;
    sessionTokens: number;
    surchargeTokens: number;
    capAtTokens: number | null;
    capped: boolean;
    message: string | null;
    link: string | null;
  } | null;
  verdict: { state: "pending" | "usable" | "not_usable"; reasons: string[]; rewardWeight: number | null } | null;
  /**
   * Whether the session was delivered and, when not, why (`delivery`; on
   * servers without it, read from a not_usable verdict's reasons). A reason
   * without the server's message has `message: null` (the app words it).
   */
  delivery?: { state: "delivered" | "not_delivered" | "pending"; reasons: { code: string; message: string | null }[]; message?: string | null } | null;
  /** In order; ids may grow. */
  checklist: { id: string; state: "pass" | "fail" | "warn" | "pending"; label: string; hint: string }[];
  evaluatedAt: string | null;
  /**
   * Server switches for the client; null on older servers (no auto-retry,
   * finish guard and one-more-turn nudge on).
   */
  client: {
    /** Send `message` once after a turn ends on a gateway, stream or tool-chain error (at most `max` in a row). */
    autoRetry: { enabled: boolean; max: number; message: string | null } | null;
    /** false: the finish guard's cut/awaiting states are off. */
    finishGuard: boolean;
    /** false: no one-more-turn nudge from the `depth` item. */
    oneMoreTurn: boolean;
  } | null;
  /** How often to re-ask while the session is active: 30 or more. */
  pollSeconds: number;
};

export type OmniRushQualitySpinRecord = {
  id: string;
  status: "ready" | "spin" | "expired" | "forfeit";
  reason: string | null;
  reproducible: boolean;
  /** Earned by a replay-ready (client-grade) session. */
  clientGrade: boolean;
  sessionId: string | null;
  earnedAt: string | null;
  expiresAt: string | null;
  spinAt: string | null;
  prizeTokens: number | null;
  paidTokens: number | null;
};

/**
 * Keep this computer awake while the agent works (apps/desktop/electron/keep-awake.mjs).
 * `available`: false over SSH or in CI, where it never runs; `forcedOff`: OMNIRUSH_KEEP_AWAKE=0 for this launch.
 */
export type KeepAwakeState = { enabled: boolean; active: boolean; available: boolean; forcedOff: boolean };

/** GET /me/quality/spins: totals and the newest spins (up to 10). */
export type OmniRushQualitySpinTotals = { spin: number; paidTokens: number; recent: OmniRushQualitySpinRecord[] };

export type OmniRushWheelSegment = { tokens: number; weight: number };

/** A 200 from POST /me/quality/spin. The server picks `segmentIndex`; the app only animates to it. */
export type OmniRushQualitySpin = {
  /** Paid into the pot: 0 in preview or past the pot cap. */
  tokens: number;
  /** The segment the wheel landed on. */
  prizeTokens: number;
  segmentIndex: number;
  segments: OmniRushWheelSegment[];
  preview: boolean;
  capped: boolean;
  reproducible: boolean;
  alreadySpin: boolean;
  spinAt: string | null;
  spinsAvailable: number;
  potBalance: number | null;
  /** big: prize >= 2M; jackpot: the top segment. */
  celebrate: "none" | "big" | "jackpot";
  /** Landed next to the jackpot. */
  nearMiss: boolean;
  jackpotTokens: number | null;
  streakDays: number | null;
  /** Earned by a client-grade session; spin on the richer wheel. */
  clientGrade: boolean;
};

export type OmniRushQualitySpinRefusal = "no_spins" | "wheel_resting" | "quality_rewards_off";

export type OmniRushQualitySpinOutcome =
  | { ok: true; spin: OmniRushQualitySpin }
  | { ok: false; reason: OmniRushQualitySpinRefusal | "signed_out" | "unreachable" | "failed"; status: number | null };

export type OmniRushAccountStatus = {
  connected: boolean;
  gatewayConfigured: boolean;
  reauthorizationRequired?: boolean;
  /** The account's opaque id (UUID) from /device/me; product analytics are linked to it. */
  accountId?: string | null;
  email?: string | null;
  displayName?: string | null;
  accountStatus?: string | null;
  usage?: OmniRushAccountUsage | null;
  /** Gateway URL the connected account uses, or the configured default while signed out. */
  gatewayUrl?: string | null;
  /** Display label for the account server, e.g. "omnirush.ai" or "localhost:8090 (local API)". */
  gatewayHost?: string | null;
  /**
   * "file": Linux without a usable keyring, so the sign-in is kept in an
   * owner-only file on this computer. Absent when a keyring protects it.
   */
  credentialStorage?: "file";
  /**
   * Linux: a sign-in sealed by a system keyring is on disk but no keyring is
   * usable now, so the user is asked to sign in again. Distinct from a
   * session the server ended (reauthorizationRequired alone).
   */
  keyringUnavailable?: boolean;
  /** /device/me `client_update` for this app; absent from an older desktop bridge. */
  clientUpdate?: OmniRushClientUpdate | null;
  /** Quality rewards; null (or absent from an older bridge) while the feature is off. */
  quality?: OmniRushAccountQuality | null;
};

export type EngineDoctorResult = {
  found: boolean;
  inPath: boolean;
  resolvedPath: string | null;
  resolvedSource: string | null;
  version: string | null;
  supportsServe: boolean;
  notes: string[];
  serveHelpStatus: number | null;
  serveHelpStdout: string | null;
  serveHelpStderr: string | null;
};

export type WorkspaceList = {
  selectedId?: string;
  watchedId?: string | null;
  activeId?: string | null;
  workspaces: WorkspaceWire[];
};

export type WorkspaceExportSummary = {
  outputPath: string;
  included: number;
  excluded: string[];
};

export type BrandIconApplyResult = { ok: boolean; reason?: string };
export type BrandIconState = { applied: boolean; sourceUrl: string | null; reason: string | null };
export type EvalRelaunchResult = { ok: true };

export type OpencodeCommandDraft = {
  name: string;
  description?: string;
  template: string;
  agent?: string;
  model?: string;
  subtask?: boolean;
};

export type WorkspaceOmniRushConfig = {
  version: number;
  workspace?: {
    name?: string | null;
    createdAt?: number | null;
    preset?: string | null;
  } | null;
  authorizedRoots: string[];
  reload?: {
    auto?: boolean;
    resume?: boolean;
  } | null;
};

export type AppBuildInfo = {
  version: string;
  gitSha?: string | null;
  buildEpoch?: string | null;
  omnirushDevMode?: boolean;
  os?: string | null;
  arch?: string | null;
};

export type DesktopDistributionInfo = {
  flavor: "public" | "enterprise";
  appName: string;
  appIdentifier: string;
  protocolScheme: string;
  requireSignin: boolean;
  requireActivation: boolean;
};

/** Org + first-skill identity shared by the handoff and prepared records. */
export type DesktopBootstrapOrgSkill = {
  orgId: string;
  orgName: string;
  orgSlug: string;
  skillId: string;
  skillTitle: string;
};

export type DesktopBootstrapConfig = {
  baseUrl: string;
  apiBaseUrl?: string | null;
  requireSignin: boolean;
  requireActivation?: boolean;
  brandAppName?: string | null;
  brandLogoUrl?: string | null;
  brandIconUrl?: string | null;
  writtenAt?: string | null;
  fromFile?: boolean;
  claimLinks?: Array<{
    id: string;
    role: string;
    token?: string;
    url: string;
    expiresAt: string;
  }> | null;
  handoff?: (DesktopBootstrapOrgSkill & {
    grant: string;
    denBaseUrl: string;
    createdAt: string;
  }) | null;
  prepared?: (DesktopBootstrapOrgSkill & {
    skillsDir: string;
    skillPath: string;
    preparedAt: string;
  }) | null;
  enterpriseActivation?: {
    activatedAt: string;
    denBaseUrl: string;
  } | null;
};

export type OmniRushDockerCleanupResult = {
  candidates: string[];
  removed: string[];
  errors: string[];
};

export type ExecResult = {
  ok: boolean;
  status: number;
  stdout: string;
  stderr: string;
};

export type LocalSkillCard = {
  name: string;
  path: string;
  description?: string;
  trigger?: string;
};

export type SkillFolderRead = {
  root: string;
  /** The folder's basename. */
  name: string;
  files: Array<{ path: string; contentBase64: string; executable: boolean }>;
  skipped: string[];
};

export type LocalSkillContent = {
  path: string;
  content: string;
};

export type OpencodeConfigFile = {
  path: string;
  exists: boolean;
  content: string | null;
};

export type UpdaterEnvironment = {
  supported: boolean;
  reason: string | null;
  executablePath: string | null;
  appBundlePath: string | null;
};

export type CacheResetResult = {
  removed: string[];
  missing: string[];
  errors: string[];
};

export type NukeManifestPreview = {
  deletePaths: string[];
  bootstrapPath: string;
  preserveBootstrapPath: string | null;
  partitions: string[];
};

export type NukeOptions = {
  preserveBootstrap: boolean;
};

export type NukeReceiptError = {
  path: string;
  message: string;
  code?: string;
};

export type NukeReceipt = {
  deleted: string[];
  pendingRetry: string[];
  errors: NukeReceiptError[];
  preservedBootstrap: boolean;
  relaunchMode: "cleanup_worker" | "direct";
  workerScheduled: boolean;
};

export type DesktopFetchInit = {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
  agentContextDiagnostics?: {
    deadlineAtMs: number;
  };
};

export type DesktopFetchResult = {
  status: number;
  statusText: string;
  headers: [string, string][];
  body: string;
};

export type DesktopMultipartUploadInput = {
  transferId: string;
  url: string;
  bytes: ArrayBuffer;
  filename: string;
  size: number;
  contentType?: string;
  fieldName?: string;
  fields?: Record<string, string>;
  method?: string;
  headers?: Record<string, string>;
  timeoutMs?: number;
};

export type DesktopBinaryDownloadInput = {
  transferId: string;
  url: string;
  destinationPath: string;
  maxBytes?: number;
  method?: string;
  headers?: Record<string, string>;
  timeoutMs?: number;
};

export type DesktopBinaryDownloadResult = {
  status: number;
  statusText: string;
  headers: [string, string][];
  path: string | null;
  bytes: number;
  body?: string;
};

export type WorkspaceCreateInput = {
  folderPath: string;
  name?: string | null;
  preset?: string | null;
};

export type WorkspaceCreateRemoteInput = {
  baseUrl: string;
  remoteType?: "omnirush" | "opencode" | null;
  directory?: string | null;
  displayName?: string | null;
  omnirushHostUrl?: string | null;
  omnirushToken?: string | null;
  omnirushClientToken?: string | null;
  omnirushHostToken?: string | null;
  omnirushWorkspaceId?: string | null;
  omnirushWorkspaceName?: string | null;
  sandboxBackend?: string | null;
  sandboxRunId?: string | null;
  sandboxContainerName?: string | null;
};

export type WorkspaceUpdateRemoteInput = WorkspaceCreateRemoteInput & {
  workspaceId: string;
};

export type UiControlBridgeInfo = {
  baseUrl?: string;
  token?: string;
};

export type ComputerUsePermissions = {
  platform?: string;
  modes?: string[];
  backgroundControl?: boolean;
  ok: boolean;
  accessibility: boolean;
  screenRecording: boolean;
  supported?: boolean;
  protocolVersion?: string;
  error?: string;
};

export type RunningAppsResult = {
  ok: boolean;
  apps: string[];
};

/** Computer use (contract v2): the app identity the host verified (exe path / bundle id, pid; none on the agent's own display). */
export type ComputerUseAppRef = { app_id: string; app_name: string; bundle_or_exe: string; pid: number | null };

/** A point in the session's frame pixels. */
export type ComputerUsePoint = { x: number; y: number };

/** The agent cursor's latest move (before a pointer act): the live view glides it from `from` to `to`. */
export type ComputerUseCursorMove = { session_id: string; from: ComputerUsePoint | null; to: ComputerUsePoint; path: ComputerUsePoint[]; action: string; width: number; height: number; seq: number; at: number };

/** One computer use session as the host sees it (apps/server/src/computer-use/shared/portable-host.mjs, virtual-host.mjs). */
export type ComputerUseSessionState = {
  id: string;
  phase: "working" | "paused" | "ended";
  mode: "observe" | "control";
  purpose: string;
  status: string;
  app: ComputerUseAppRef;
  window: { id: string; title: string };
  windows: Array<{ id: string; title: string }>;
  /** "setting": the person's screen (the person's real-screen setting); "virtual": the agent's own display. */
  approval: "setting" | "virtual" | null;
  actions: number;
  actions_left: number;
  seconds_left: number;
  can_continue: boolean;
  log: Array<{ at: string; action: string; intent: string; ok: boolean; code: string | null }>;
  frame: { sha: string; width: number; height: number; mime: string; data_url: string; at: string; cursor?: ComputerUsePoint | null } | null;
  chat: string | null;
  hidden?: boolean;
  window_bounds?: { x: number; y: number; width: number; height: number };
  /** The agent's own display. */
  display?: "virtual";
  virtual?: { kind: string; display: string; browser: string | null };
  /** The agent's cursor in frame pixels (the agent's own display). */
  cursor?: ComputerUsePoint | null;
  cursor_move?: ComputerUseCursorMove;
};

/** The pressed button's box (CSS pixels of the main window): the person's own press must land in it (Continue). */
export type ComputerUseButtonRect = { x: number; y: number; width: number; height: number };
export type ComputerUseControlAction = "stop" | "takeover" | "continue" | "hide" | "show";

export type ComputerUseStatus = {
  enabled: boolean;
  supported: boolean;
  /** Why it is off or unavailable (people-facing), when it is. */
  message: string | null;
  mode: "careful" | "normal" | "auto";
  sessions: ComputerUseSessionState[];
};

/** The person's one-time setting for their own screen (off by default). forced: the environment decides; allowed: the server allows it. */
/** `on`: this computer's own setting; `allowed`: the server's yes for the account (its opt-in, set only in the web console), read just now. Both are needed. */
export type ComputerUseRealScreen = { on: boolean; forced: boolean; allowed: boolean };

// ---------------------------------------------------------------------------
// The command map
// ---------------------------------------------------------------------------

export type DesktopCommandMap = {
  // Workspace state
  workspaceBootstrap: { args: []; result: WorkspaceList };
  workspaceSetSelected: { args: [workspaceId: string]; result: WorkspaceList };
  workspaceSetRuntimeActive: { args: [workspaceId: string | null]; result: WorkspaceList };
  workspaceCreate: { args: [input: WorkspaceCreateInput]; result: WorkspaceList };
  workspaceCreateRemote: { args: [input: WorkspaceCreateRemoteInput]; result: WorkspaceList };
  workspaceUpdateRemote: { args: [input: WorkspaceUpdateRemoteInput]; result: WorkspaceList };
  workspaceUpdateDisplayName: {
    args: [input: { workspaceId: string; displayName?: string | null }];
    result: WorkspaceList;
  };
  workspaceForget: { args: [workspaceId: string]; result: WorkspaceList };
  workspaceAddAuthorizedRoot: {
    args: [input: { workspacePath: string; folderPath?: string; authorizedRoot?: string }];
    result: unknown;
  };
  workspaceOmniRushRead: {
    args: [input: { workspacePath: string }];
    result: WorkspaceOmniRushConfig;
  };
  workspaceOmniRushWrite: {
    args: [input: { workspacePath: string; config: WorkspaceOmniRushConfig }];
    result: unknown;
  };
  workspaceExportConfig: {
    args: [input: { workspaceId: string; outputPath: string }];
    result: WorkspaceExportSummary;
  };
  workspaceImportConfig: {
    args: [input: { archivePath: string; targetDir: string; name?: string | null }];
    result: unknown;
  };

  // Opencode custom commands
  opencodeCommandList: {
    args: [input: { scope: string; projectDir?: string }];
    result: string[];
  };
  opencodeCommandWrite: {
    args: [input: { scope: string; projectDir?: string; command: OpencodeCommandDraft }];
    result: unknown;
  };
  opencodeCommandDelete: {
    args: [input: { scope: string; projectDir?: string; name: string }];
    result: unknown;
  };

  // Engine / runtime lifecycle
  engineStart: { args: [projectDir: string, options?: Record<string, unknown>]; result: EngineInfo };
  prepareFreshRuntime: { args: []; result: unknown };
  runtimeBootstrap: { args: []; result: unknown };
  runtimeStatus: { args: []; result: unknown };
  engineStop: { args: []; result: EngineInfo };
  engineRestart: { args: [options?: Record<string, unknown>]; result: EngineInfo };
  engineInfo: { args: []; result: EngineInfo };
  engineDoctor: { args: [projectDir?: string]; result: EngineDoctorResult };
  engineInstall: { args: []; result: unknown };

  // App / bridge info
  appBuildInfo: { args: []; result: AppBuildInfo };
  desktopNotificationShow: {
    args: [input: DesktopNotificationInput];
    result: DesktopNotificationResult;
  };
  desktopSentrySetSession: {
    args: [input: { userId: string; orgId: string }];
    result: { enabled: boolean };
  };
  desktopSentryClearSession: { args: []; result: { enabled: boolean } };
  /** Consent for desktop error reports; the app no longer grants it. */
  desktopSentrySetConsent: { args: [enabled: boolean]; result: { enabled: boolean } };
  desktopIntegrationStatus: { args: []; result: DesktopIntegrationStatus };
  desktopIntegrationInstall: {
    args: [options?: { useExternalLauncher?: boolean }];
    result: DesktopIntegrationResult;
  };
  desktopIntegrationRemove: { args: []; result: DesktopIntegrationResult };
  getUiControlBridgeInfo: { args: []; result: UiControlBridgeInfo | null };
  getOmniRushUiMcpCommand: { args: []; result: string[] };
  getComputerUseMcpCommand: { args: []; result: string[] };
  getComputerUseMcpEnvironment: { args: []; result: Record<string, string> };
  getComputerUseState: { args: []; result: ComputerUseStatus };
  getComputerUseRealScreen: { args: []; result: ComputerUseRealScreen };
  setComputerUseRealScreen: { args: [on: boolean]; result: ComputerUseRealScreen };
  computerUseControl: { args: [value: { session_id: string; action: ComputerUseControlAction; rect?: ComputerUseButtonRect }]; result: void };
  getOmniRushUiMcpEnvironment: { args: []; result: Record<string, string> };

  // Computer use
  checkComputerUsePermissions: { args: []; result: ComputerUsePermissions };
  listRunningApps: { args: []; result: RunningAppsResult };
  openComputerUsePermissionSetup: { args: []; result: ComputerUsePermissions };
  openComputerUsePermissionSettings: { args: []; result: unknown };

  // Bootstrap config
  getDesktopBootstrapConfig: { args: []; result: DesktopBootstrapConfig };
  debugDesktopBootstrapConfig: { args: []; result: unknown };
  clearDesktopBootstrapConfig: { args: []; result: unknown };
  setDesktopBootstrapConfig: {
    args: [config: Partial<DesktopBootstrapConfig>];
    result: DesktopBootstrapConfig;
  };

  // Connect links use a short-lived HTTPS exchange by default and can use an
  // embedded-key signed token when explicitly enabled. The renderer relays
  // only the raw URL. `connectLinkAccept` resolves it again after confirmation,
  // enforces one-time use, and persists the target as desktop bootstrap config.
  connectLinkVerify: { args: [rawUrl: string]; result: ConnectLinkVerifyResult };
  connectLinkAccept: {
    args: [rawUrl: string];
    result: { ok: true; config: DesktopBootstrapConfig } | ConnectLinkVerifyFailure;
  };
  nukeOmniRushAndOpencodeConfigPreview: { args: [options?: NukeOptions]; result: NukeManifestPreview };
  nukeOmniRushAndOpencodeConfigAndExit: { args: [options?: NukeOptions]; result: NukeReceipt };

  // Sandbox
  sandboxCleanupOmniRushContainers: { args: []; result: OmniRushDockerCleanupResult };

  // OmniRush.ai server sidecar
  omnirushServerInfo: { args: []; result: OmniRushServerInfo };
  omnirushAccountStatus: {
    args: [options?: { sessionId?: string | null }];
    result: OmniRushAccountStatus;
  };
  omnirushQualityDetails: { args: []; result: OmniRushQualityDetails | null };
  omnirushQualitySpins: { args: []; result: OmniRushQualitySpinTotals | null };
  keepAwakeStatus: { args: []; result: KeepAwakeState };
  keepAwakeSet: { args: [enabled: boolean]; result: KeepAwakeState };
  omnirushSessionStatus: { args: [input: { sessionId: string }]; result: OmniRushSessionStatus | null };
  omnirushQualitySpin: {
    args: [input: { idempotencyKey: string }];
    result: OmniRushQualitySpinOutcome;
  };
  omnirushBuildathon: { args: []; result: OmniRushBuildathonAnswer };
  omnirushBuildathonJoin: { args: []; result: OmniRushBuildathonLinkResult };
  omnirushPlacement: { args: [input: { slot: OmniRushPlacementSlot; sessionId?: string }]; result: OmniRushPlacement | null };
  omnirushPlacementAction: { args: [input: { action: OmniRushPlacementAction; id?: string; displayId?: string; sessionId?: string }]; result: { ok: boolean; opened?: boolean; rotate?: boolean } };
  omnirushFeedbackPolicy: { args: []; result: OmniRushFeedbackPolicy };
  omnirushFeedbackStatus: { args: []; result: OmniRushFeedbackStatus };
  omnirushFeedbackSessionStarted: { args: [input: { sessionId: string }]; result: boolean };
  omnirushFeedbackOffer: {
    args: [input: { sessionId: string; outcome: OmniRushFeedbackTurnOutcome; toolCalls: number; durationMs: number; text?: string }];
    result: OmniRushFeedbackOffer;
  };
  omnirushFeedbackShown: { args: [input: { kind: "turn" | "pulse" }]; result: { ok: boolean } };
  omnirushFeedbackSubmit: { args: [input: OmniRushFeedbackInput]; result: OmniRushFeedbackResult };
  omnirushBuildathonSessions: { args: []; result: OmniRushBuildathonSession[] | null };
  omnirushBuildathonLink: { args: [input: { code: string }]; result: OmniRushBuildathonLinkResult };
  omnirushBuildathonChecklist: {
    args: [input: { path: string; checklist: Array<{ id: string; text: string }> }];
    result: OmniRushBuildathonCheck[] | null;
  };
  omnirushBuildathonTagSession: {
    args: [input: { sessionId: string; track: string; project?: string | null }];
    result: OmniRushBuildathonTagResult;
  };
  omnirushAccountConnect: {
    args: [options?: { gatewayUrl?: string; deviceName?: string }];
    result: { connected: true; userCode: string };
  };
  omnirushAccountSignOut: { args: []; result: OmniRushAccountSignOutResult };
  automationRunnerConfigure: {
    args: [configuration: { baseUrl: string; token: string; runnerId: string } | null];
    result: { connected: boolean };
  };
  omnirushServerRestart: {
    args: [options?: Record<string, unknown>];
    result: OmniRushServerInfo;
  };

  // Dialogs
  pickDirectory: {
    args: [options?: { title?: string; defaultPath?: string; multiple?: boolean }];
    result: string | string[] | null;
  };
  pickFile: {
    args: [
      options?: {
        title?: string;
        defaultPath?: string;
        multiple?: boolean;
        filters?: { name: string; extensions: string[] }[];
      },
    ];
    result: string | string[] | null;
  };
  saveFile: {
    args: [options?: { title?: string; defaultPath?: string; filters?: { name: string; extensions: string[] }[] }];
    result: string | null;
  };

  // Skills
  importSkill: {
    args: [projectDir: string, sourceDir: string, options?: { overwrite?: boolean }];
    result: ExecResult;
  };
  /** Reads a picked/dropped skill folder for upload (links refused, junk skipped, capped). */
  readSkillFolder: { args: [sourceDir: string]; result: SkillFolderRead };
  installSkillTemplate: {
    args: [projectDir: string, name: string, content: string, options?: { overwrite?: boolean }];
    result: ExecResult;
  };
  listLocalSkills: { args: [projectDir: string]; result: LocalSkillCard[] };
  readLocalSkill: { args: [projectDir: string, skillName: string]; result: LocalSkillContent };
  writeLocalSkill: {
    args: [projectDir: string, skillName: string, content: string];
    result: ExecResult;
  };
  uninstallSkill: { args: [projectDir: string, skillName: string]; result: ExecResult };

  // Updater / config / resets
  updaterEnvironment: { args: []; result: UpdaterEnvironment };
  readOpencodeConfig: { args: [scope: string, projectDir?: string]; result: OpencodeConfigFile };
  writeOpencodeConfig: {
    args: [scope: string, projectDir: string, content: string];
    result: ExecResult;
  };
  /**
   * The renderer passes its reset-modal mode, but the main process currently
   * IGNORES it and always removes workspace state + bootstrap config; only
   * the renderer's localStorage cleanup is mode-scoped. Follow-up: decide
   * whether "onboarding" should preserve desktop workspace state.
   */
  resetOmniRushState: { args: [mode?: "onboarding" | "all"]; result: unknown };
  resetOpencodeCache: { args: []; result: CacheResetResult };
  opencodeMcpAuth: { args: [action: string, name: string]; result: ExecResult };
  setWindowDecorations: { args: [decorated: boolean]; result: unknown };

  /** Opens <userData>/logs in the system file manager. Takes no path from the renderer. */
  openLogsFolder: { args: []; result: { ok: boolean; error?: string } };
  /** Settings > Storage. Lists (dryRun) or removes what the app no longer needs; takes no path from the renderer. */
  freeUpSpace: {
    args: [options?: { dryRun?: boolean }];
    result: {
      ok: boolean;
      skipped: string | null;
      dryRun: boolean;
      freedBytes: number;
      freed: string;
      items: Array<{ kind: string; path: string; bytes: number; size: string; reason: string; inUse: boolean }>;
    };
  };

  // Window / OS utilities (dunder commands)
  __openPath: { args: [target: string]; result: unknown };
  __revealItemInDir: { args: [target: string]; result: unknown };
  __getFileIcon: { args: [target: string, size?: "small" | "normal" | "large"]; result: string | null };
  __applyBrandAppName: { args: [appName: string | null]; result: { ok: true; appName: string } };
  __applyBrandIcon: { args: [url: string | null]; result: BrandIconApplyResult };
  __getBrandIconState: { args: []; result: BrandIconState };
  __evalRelaunch: { args: []; result: EvalRelaunchResult };
  __getApplicationsForFile: { args: [target: string]; result: { name: string; appPath: string; icon: string | null }[] };
  __openWithApp: { args: [target: string, appPath: string]; result: unknown };
  __fetch: { args: [url: string, init?: DesktopFetchInit]; result: DesktopFetchResult };
  __uploadMultipart: { args: [input: DesktopMultipartUploadInput]; result: DesktopFetchResult };
  __downloadBinary: { args: [input: DesktopBinaryDownloadInput]; result: DesktopBinaryDownloadResult };
  __cancelTransfer: { args: [transferId: string]; result: boolean };
  __homeDir: { args: []; result: string };
  __joinPath: { args: [...segments: string[]]; result: string };
  __setZoomFactor: { args: [factor: number]; result: boolean };
  __setNativeTheme: { args: [theme: string]; result: unknown };
  __setApplicationMenuVisible: { args: [visible: boolean]; result: unknown };
  __setTurnRunning: { args: [running: boolean]; result: unknown };
  __setFinishState: { args: [state: { sessionId: string; kind: "awaiting" | "cut" | null }]; result: unknown };
};

export type DesktopCommandName = keyof DesktopCommandMap;

export type DesktopCommandArgs<C extends DesktopCommandName> = DesktopCommandMap[C]["args"];

export type DesktopCommandResult<C extends DesktopCommandName> = DesktopCommandMap[C]["result"];

/**
 * Main-process handler registry shape. `Event` is electron's
 * IpcMainInvokeEvent (kept generic so this package does not depend on
 * electron types).
 *
 * Args are deliberately loose (`any[]`) on this side: IPC input crosses a
 * trust boundary, so handlers validate/normalize whatever arrives with
 * defensive dynamic access (`String(args[0] ?? "")`, `input.foo ?? null`)
 * rather than assuming the renderer's tuple. `unknown[]` would force ~50
 * narrowing rewrites in the plain-JS main process for no runtime gain.
 * Key parity and result types are still enforced.
 */
type DesktopCommandHandler<Event, C extends DesktopCommandName> = (
  event: Event,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  ...args: any[]
) => Promise<DesktopCommandResult<C>>;

export type DesktopCommandHandlers<Event = unknown> = {
  [C in Exclude<DesktopCommandName, "__evalRelaunch">]: DesktopCommandHandler<Event, C>;
} & {
  __evalRelaunch?: DesktopCommandHandler<Event, "__evalRelaunch">;
};

/** Renderer-side bridge: one async function per command. */
export type DesktopCommandInvokers = {
  [C in DesktopCommandName]: (...args: DesktopCommandArgs<C>) => Promise<DesktopCommandResult<C>>;
};
