/**
 * Quality rewards: the `quality` block on /device/me, the wheel's
 * segments (GET /me/quality) and a spin (POST /me/quality/spin).
 *
 * `quality: null` means the feature is switched off: the app shows nothing.
 * The server picks every spin's outcome; the app only animates the wheel to
 * `segment_index`.
 */

export const QUALITY_TIERS = /** @type {const} */ (["new", "standard", "gold", "coaching", "limited"]);
export const SPIN_REFUSALS = /** @type {const} */ (["no_spins", "wheel_resting", "quality_rewards_off"]);

/**
 * @typedef {{ id: string, kind: string | null, title: string, body: string }} QualityNotice
 * @typedef {{
 *   tier: typeof QUALITY_TIERS[number],
 *   score: number,
 *   tokensMultiplier: number,
 *   spinsAvailable: number,
 *   reproSpinsAvailable: number,
 *   clientSpinsAvailable: number,
 *   spinsExpireAt: string | null,
 *   nextTierHint: string | null,
 *   tips: string[],
 *   notice: QualityNotice | null,
 *   mode: "shadow" | "enforce",
 *   resting: boolean,
 *   preview: boolean,
 *   notices: QualityNotice[],
 *   streakDays: number,
 *   streakMultiplier: number,
 *   streakNext: { days: number, bonusSpins: number } | null,
 *   nextSpinHint: { progress: number, text: string, sessionId: string | null } | null,
 *   biggestWinToday: { tokens: number, at: string | null } | null,
 *   nudge: { id: string, text: string } | null,
 *   windowsCounts: boolean,
 * }} AccountQuality
 * @typedef {{ tokens: number, weight: number }} WheelSegment
 * @typedef {{
 *   tokens: number,
 *   prizeTokens: number,
 *   segmentIndex: number,
 *   segments: WheelSegment[],
 *   preview: boolean,
 *   capped: boolean,
 *   reproducible: boolean,
 *   alreadySpin: boolean,
 *   spinAt: string | null,
 *   spinsAvailable: number,
 *   potBalance: number | null,
 *   celebrate: "none" | "big" | "jackpot",
 *   nearMiss: boolean,
 *   jackpotTokens: number | null,
 *   streakDays: number | null,
 * }} QualitySpin
 * @typedef {{ ok: true, spin: QualitySpin }
 *   | { ok: false, reason: typeof SPIN_REFUSALS[number] | "signed_out" | "unreachable" | "failed", status: number | null }} QualitySpinOutcome
 */

function text(value) {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function count(value) {
  const number = Number(value);
  return Number.isFinite(number) && number > 0 ? Math.floor(number) : 0;
}

function isoTime(value) {
  const raw = text(value);
  return raw && Number.isFinite(Date.parse(raw)) ? raw : null;
}

/** @returns {QualityNotice | null} */
function parseNotice(value) {
  if (!value || typeof value !== "object") return null;
  const id = text(value.id);
  const title = text(value.title);
  if (!id || !title) return null;
  return { id, kind: text(value.kind), title, body: text(value.body) ?? "" };
}

function fraction(value) {
  const number = Number(value);
  return Number.isFinite(number) ? Math.min(1, Math.max(0, number)) : 0;
}

function parseStreakNext(value) {
  if (!value || typeof value !== "object") return null;
  const days = count(value.days);
  return days ? { days, bonusSpins: count(value.bonus_spins) } : null;
}

function parseNextSpinHint(value) {
  if (!value || typeof value !== "object") return null;
  const hint = text(value.text);
  return hint ? { progress: fraction(value.progress), text: hint, sessionId: text(value.session_id) } : null;
}

function parseBiggestWin(value) {
  if (!value || typeof value !== "object") return null;
  const tokens = count(value.tokens);
  return tokens ? { tokens, at: isoTime(value.at) } : null;
}

function parseNudge(value) {
  if (!value || typeof value !== "object") return null;
  const id = text(value.id);
  const message = text(value.text);
  return id && message ? { id, text: message } : null;
}

/**
 * The `quality` block of a /device/me (or /me) answer; null when the
 * feature is off, the block is missing or it names no known tier.
 * @returns {AccountQuality | null}
 */
export function parseAccountQuality(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const tier = text(value.tier)?.toLowerCase();
  if (!tier || !QUALITY_TIERS.includes(/** @type {any} */ (tier))) return null;
  const score = Number(value.score);
  const multiplier = Number(value.tokens_multiplier);
  const spinsAvailable = count(value.spins_available);
  const notices = Array.isArray(value.notices) ? value.notices.map(parseNotice).filter((notice) => notice !== null).slice(0, 5) : [];
  return {
    tier: /** @type {AccountQuality["tier"]} */ (tier),
    score: Number.isFinite(score) ? Math.min(1, Math.max(0, score)) : 0,
    tokensMultiplier: Number.isFinite(multiplier) && multiplier > 0 ? multiplier : 1,
    spinsAvailable,
    reproSpinsAvailable: Math.min(spinsAvailable, count(value.repro_spins_available)),
    // Of those, earned by client-grade sessions (the richer wheel).
    clientSpinsAvailable: Math.min(spinsAvailable, count(value.client_spins_available)),
    spinsExpireAt: isoTime(value.spins_expire_at),
    nextTierHint: text(value.next_tier_hint),
    tips: Array.isArray(value.tips) ? value.tips.map(text).filter((tip) => tip !== null).slice(0, 8) : [],
    notice: notices[0] ?? parseNotice(value.notice),
    notices: notices.length ? notices : [parseNotice(value.notice)].filter((notice) => notice !== null),
    mode: value.mode === "enforce" ? "enforce" : "shadow",
    resting: value.resting === true,
    preview: value.preview === true,
    streakDays: count(value.streak_days),
    streakMultiplier: count(value.streak_multiplier),
    streakNext: parseStreakNext(value.streak_next),
    nextSpinHint: parseNextSpinHint(value.next_spin_hint),
    biggestWinToday: parseBiggestWin(value.biggest_win_today),
    nudge: parseNudge(value.nudge),
    // Native Windows counts like every other system unless the server says otherwise.
    windowsCounts: value.windows_counts !== false,
  };
}

/** @returns {WheelSegment[]} */
export function parseWheelSegments(value) {
  if (!Array.isArray(value)) return [];
  return value
    .filter((segment) => segment && typeof segment === "object")
    .map((segment) => ({ tokens: count(segment.tokens), weight: Math.max(0, Number(segment.weight) || 0) }));
}

/**
 * A 200 from POST /me/quality/spin; null when it does not name a segment
 * the wheel can land on.
 * @returns {QualitySpin | null}
 */
export function parseSpinResult(value) {
  if (!value || typeof value !== "object") return null;
  const segments = parseWheelSegments(value.segments);
  const segmentIndex = Number(value.segment_index);
  if (!Number.isInteger(segmentIndex) || segmentIndex < 0 || segmentIndex >= segments.length) return null;
  const pot = Number(value.pot_balance);
  return {
    tokens: count(value.tokens),
    prizeTokens: count(value.prize_tokens) || segments[segmentIndex].tokens,
    segmentIndex,
    segments,
    preview: value.preview === true,
    capped: value.capped === true,
    reproducible: value.reproducible === true,
    alreadySpin: value.already_spin === true,
    spinAt: isoTime(value.spin_at),
    spinsAvailable: count(value.spins_available),
    potBalance: value.pot_balance === null || value.pot_balance === undefined || !Number.isFinite(pot) ? null : Math.max(0, pot),
    celebrate: value.celebrate === "big" || value.celebrate === "jackpot" ? value.celebrate : "none",
    nearMiss: value.near_miss === true,
    jackpotTokens: count(value.jackpot_tokens) || null,
    streakDays: value.streak_days === undefined || value.streak_days === null ? null : count(value.streak_days),
    // A spin earned by a client-grade session, on the richer wheel (`segments` is the wheel used).
    clientGrade: value.client_grade === true,
  };
}

/** The `sessions` of GET /me/quality, for the coaching card's "see why". */
export function parseQualitySessions(value) {
  if (!Array.isArray(value)) return [];
  return value
    .filter((session) => session && typeof session === "object" && text(session.session_id))
    .slice(0, 50)
    .map((session) => ({
      sessionId: text(session.session_id),
      at: isoTime(session.at),
      verdict: text(session.verdict),
      why: text(session.why),
      fails: Array.isArray(session.fails) ? session.fails.map(text).filter((fail) => fail !== null) : [],
      workspace: text(session.workspace),
      spins: count(session.spins),
      counted: session.counted === true,
      // The looser reward level; `reproClient` is the strict client grade.
      reproducible: reproLevel(session.reproducible),
      reproClient: reproLevel(session.repro_client),
      clientGrade: session.client_grade === true,
      workSize: Number.isInteger(session.work_size) ? Math.min(4, Math.max(0, session.work_size)) : null,
      work: parseSessionWork(session.work),
    }));
}

function reproLevel(value) {
  return value === "pass" || value === "fail" || value === "unknown" ? value : null;
}

function parseSessionWork(value) {
  if (!value || typeof value !== "object") return null;
  return {
    codeFiles: count(value.code_files),
    linesChanged: count(value.lines_changed),
    toolCalls: count(value.tool_calls),
    testRuns: count(value.test_runs),
    floor: count(value.floor),
    step: count(value.step),
  };
}

const SPIN_STATUSES = ["ready", "spin", "expired", "forfeit"];

/** GET /me/quality/spins: the totals and the newest `limit` spins. */
export function parseSpinHistory(value, limit = 10) {
  if (!value || typeof value !== "object") return null;
  const totals = value.totals && typeof value.totals === "object" ? value.totals : {};
  const spins = Array.isArray(value.spins) ? value.spins : [];
  const spinCount = count(totals.spin);
  return {
    spin: spinCount,
    paidTokens: count(totals.paid_tokens),
    recent: spins
      .filter((spin) => spin && typeof spin === "object" && text(spin.id))
      .slice(0, limit)
      .map((spin) => ({
        id: text(spin.id),
        status: SPIN_STATUSES.includes(spin.status) ? spin.status : "ready",
        reason: text(spin.reason),
        reproducible: spin.reproducible === true,
        clientGrade: spin.client_grade === true,
        sessionId: text(spin.session_id),
        earnedAt: isoTime(spin.earned_at),
        expiresAt: isoTime(spin.expires_at),
        spinAt: isoTime(spin.spin_at),
        prizeTokens: spin.prize_tokens === null || spin.prize_tokens === undefined ? null : count(spin.prize_tokens),
        paidTokens: spin.paid_tokens === null || spin.paid_tokens === undefined ? null : count(spin.paid_tokens),
      })),
  };
}

/** `fail_labels` of GET /me/quality: `{code: label}`, strings only. */
export function parseFailLabels(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  /** @type {Record<string, string>} */
  const labels = {};
  for (const [code, label] of Object.entries(value)) {
    const clean = text(label);
    if (clean && /^[a-z0-9_-]{1,64}$/i.test(code)) labels[code] = clean;
  }
  return labels;
}

/** A session id the profile request may name (`/device/me?session_id=`), or null. */
export function profileSessionId(value) {
  const id = text(value);
  return id && /^[A-Za-z0-9_-]{1,128}$/.test(id) ? id : null;
}

/** `{"detail": "wheel_resting"}` (or `{"detail": {"code": ...}}`) from a 409. */
export function spinRefusal(payload) {
  const detail = payload && typeof payload === "object" ? payload.detail : null;
  const code = typeof detail === "string" ? detail : detail && typeof detail === "object" ? detail.code : null;
  return SPIN_REFUSALS.includes(code) ? code : null;
}

/** A caller's key, or a fresh one: at most 64 characters, as the server requires. */
export function spinIdempotencyKey(value) {
  const key = text(value);
  return key && key.length <= 64 && /^[0-9A-Za-z._:-]+$/.test(key) ? key : globalThis.crypto.randomUUID();
}

const SESSION_STATUSES = ["on_track", "at_risk", "failing", "unknown"];
const CHECK_STATES = ["pass", "fail", "warn", "pending"];
const DOCK_MODES = ["off", "observe", "warn", "enforce"];
const DOCK_STAGES = ["none", "warn", "surcharge", "cap"];
const VERDICT_STATES = ["pending", "usable", "not_usable"];
/** The fastest the app re-asks for a session's status, and its pace when the server names none. */
export const SESSION_STATUS_MIN_POLL_SECONDS = 30;
export const SESSION_STATUS_DEFAULT_POLL_SECONDS = 60;

function oneOf(value, allowed, fallback) {
  return allowed.includes(value) ? value : fallback;
}

function nonNegative(value) {
  const number = Number(value);
  return Number.isFinite(number) && number >= 0 ? number : 0;
}

function parseDock(value) {
  if (!value || typeof value !== "object") return null;
  const weight = Number(value.weight);
  const capAt = Number(value.cap_at_tokens);
  return {
    mode: oneOf(value.mode, DOCK_MODES, "off"),
    stage: oneOf(value.stage, DOCK_STAGES, "none"),
    weight: Number.isFinite(weight) && weight > 0 ? weight : 1,
    sessionTokens: nonNegative(value.session_tokens),
    surchargeTokens: nonNegative(value.surcharge_tokens),
    capAtTokens: value.cap_at_tokens === null || value.cap_at_tokens === undefined || !Number.isFinite(capAt) ? null : capAt,
    capped: value.capped === true,
    message: text(value.message),
    link: text(value.link),
  };
}

function parseVerdict(value) {
  if (!value || typeof value !== "object") return null;
  const weight = Number(value.reward_weight);
  return {
    state: oneOf(value.state, VERDICT_STATES, "pending"),
    reasons: Array.isArray(value.reasons) ? value.reasons.map(text).filter((reason) => reason !== null) : [],
    rewardWeight: Number.isFinite(weight) ? weight : null,
  };
}

const DELIVERY_STATES = ["delivered", "not_delivered", "pending"];

function deliveryReason(value) {
  const reason = value && typeof value === "object" && !Array.isArray(value) ? value : { code: value };
  const code = text(reason.code);
  const message = text(reason.message);
  return code || message ? { code: code ?? "", message } : null;
}

/**
 * Whether the session was delivered, and why not (`delivery`); on servers
 * without that block, a not_usable verdict's reason codes; null when the
 * server says nothing.
 */
export function parseDelivery(value, verdict) {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return {
      state: oneOf(value.state, DELIVERY_STATES, "pending"),
      reasons: Array.isArray(value.reasons) ? value.reasons.map(deliveryReason).filter((reason) => reason !== null) : [],
      message: text(value.message),
    };
  }
  if (verdict?.state === "not_usable" && verdict.reasons.length) {
    return { state: "not_delivered", reasons: verdict.reasons.map((code) => ({ code, message: null })), message: null };
  }
  return null;
}

/**
 * The block's `client` switches (contract revision 2); null when absent:
 * no auto-retry, the finish guard and the one-more-turn nudge on.
 */
function parseClientSwitches(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const retry = value.auto_retry && typeof value.auto_retry === "object" ? value.auto_retry : null;
  const max = Number(retry?.max);
  return {
    autoRetry: retry
      ? {
        enabled: retry.enabled === true,
        max: Number.isFinite(max) && max > 0 ? Math.min(3, Math.floor(max)) : 1,
        message: text(retry.message),
      }
      : null,
    finishGuard: value.finish_guard !== false,
    oneMoreTurn: value.one_more_turn !== false,
  };
}

/**
 * The server's status block for one session (GET /me/sessions/{id}/status,
 * or `session_status` on /device/me); null when it is missing or malformed.
 * Labels, hints and messages are the server's words, kept as given.
 */
export function parseSessionStatus(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const sessionId = text(value.session_id);
  if (!sessionId) return null;
  const poll = Number(value.poll_seconds);
  const verdict = parseVerdict(value.verdict);
  return {
    sessionId,
    status: oneOf(value.status, SESSION_STATUSES, "unknown"),
    reasons: Array.isArray(value.reasons)
      ? value.reasons
        .filter((reason) => reason && typeof reason === "object" && text(reason.message))
        .map((reason) => ({ code: text(reason.code) ?? "", message: text(reason.message) }))
      : [],
    message: text(value.message),
    dock: parseDock(value.dock),
    verdict,
    delivery: parseDelivery(value.delivery, verdict),
    checklist: Array.isArray(value.checklist)
      ? value.checklist
        .filter((item) => item && typeof item === "object" && text(item.id) && text(item.label))
        .map((item) => ({ id: text(item.id), state: oneOf(item.state, CHECK_STATES, "pending"), label: text(item.label), hint: text(item.hint) ?? "" }))
      : [],
    evaluatedAt: isoTime(value.evaluated_at),
    client: parseClientSwitches(value.client),
    pollSeconds: Number.isFinite(poll) && poll > 0
      ? Math.max(SESSION_STATUS_MIN_POLL_SECONDS, Math.floor(poll))
      : SESSION_STATUS_DEFAULT_POLL_SECONDS,
  };
}
