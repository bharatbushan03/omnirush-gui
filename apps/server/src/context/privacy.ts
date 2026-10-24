// What every capture-context item goes through before it is recorded: the
// home directory (and the account name wherever it appears in a path) becomes
// `~`, a Windows account's name in a profile path becomes `user` (whatever
// form the path takes: C:\Users\<name>, /mnt/c/Users/<name> under WSL,
// /c/Users/<name> in Git Bash, \\wsl$\<distro>\home\<name>), URLs lose
// their userinfo and secret-looking query values, and the text runs through
// the uploader's CONFIG secret scrub (injected, so this module is the same in
// the CLI and the desktop app).

import { homedir, userInfo } from "node:os";
import { redactionRaw } from "./redact-policy.js";

/** The uploader's scrubbers: free text (CONFIG mode) and whole JSON values. */
export type Scrubber = {
  text: (text: string) => string;
  json: <T>(value: T) => T;
  /** A file's content for upload, scrubbed by its path (source vs config rules). */
  content: (path: string, text: string) => string;
};

/** No scrubbing (tests that look at the raw shapes). */
export const IDENTITY_SCRUBBER: Scrubber = { text: (text) => text, json: (value) => value, content: (_path, text) => text };

export type PrivacyContext = { home: string | null; user: string | null };

export function currentPrivacy(): PrivacyContext {
  let home: string | null = null;
  let user: string | null = null;
  try {
    home = homedir() || null;
  } catch {
    home = null;
  }
  try {
    user = userInfo().username || null;
  } catch {
    user = null;
  }
  return { home, user };
}

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

const homeRegexCache = new Map<string, RegExp>();

/** What an account name in a Windows profile path becomes (one placeholder for every name, so the same name always masks the same). */
export const PROFILE_PLACEHOLDER = "user";
/** Profile folders that are not an account: kept. */
const SHARED_PROFILES = new Set(["public", "default", "default user", "all users", "defaultapppool", "wdagutilityaccount", PROFILE_PLACEHOLDER]);
/** A path separator: `/`, or a run of backslashes (JSON-escaped text doubles them). */
const SEP = String.raw`(?:\\+|/)`;
/** A character of a profile folder's name. */
const NAME_CHAR = String.raw`[^\\/\s"'\`<>|:*?;,()\[\]{}]`;
/**
 * A Windows profile path up to the account name: `<drive>:\Users\` (either
 * slash), `/mnt/<drive>/Users/` (WSL), `/<drive>/Users/` and
 * `/cygdrive/<drive>/Users/` (Git Bash, Cygwin), and the WSL home seen from
 * Windows, `\\wsl$\<distro>\home\` (or `\\wsl.localhost`). Then the name: one
 * path segment, with spaces only when another segment or a closing quote
 * follows (in free text a name ends at a space), never ending in a dot
 * (sentence punctuation).
 */
const WINDOWS_PROFILE = new RegExp(
  String.raw`((?<![\w.$-])(?:/mnt|/cygdrive)?/[A-Za-z]/[Uu][Ss][Ee][Rr][Ss]/|(?<![\w])[A-Za-z]:${SEP}[Uu][Ss][Ee][Rr][Ss]${SEP}|(?:\\+|//)wsl(?:\$|\.localhost)${SEP}[^\\/\s"']+${SEP}home${SEP})`
    + String.raw`(${NAME_CHAR}+(?: ${NAME_CHAR}+)*(?=\\|/|["'\`])|${NAME_CHAR}*[^\\/\s"'\`<>|:*?;,()\[\]{}.])`,
  "g",
);

/**
 * Every Windows account name in a profile path as PROFILE_PLACEHOLDER, the
 * path otherwise as it was: `/mnt/c/Users/Jane Doe/app` becomes
 * `/mnt/c/Users/user/app`, `C:\Users\sam` becomes `C:\Users\user`. Shared
 * profiles (Public, Default, All Users) are kept.
 */
export function maskWindowsProfiles(text: string): string {
  // client-raw: account names stay as written.
  if (!text || redactionRaw() || !/users|wsl/i.test(text)) return text;
  return text.replace(WINDOWS_PROFILE, (match: string, root: string, name: string) => (SHARED_PROFILES.has(name.toLowerCase()) ? match : root + PROFILE_PLACEHOLDER));
}

/**
 * Replaces the home directory with `~` wherever it appears in `text` (both
 * slash styles on Windows), and any other home-style path of the account
 * (`/home/<user>`, `/Users/<user>`) the same way. Every other Windows profile
 * path keeps its shape with the account name masked (maskWindowsProfiles).
 */
export function tildeText(text: string, privacy: PrivacyContext): string {
  if (!text) return text;
  let out = text;
  const homes = new Set<string>();
  if (privacy.home && privacy.home.length > 1) {
    homes.add(privacy.home);
    homes.add(privacy.home.replaceAll("\\", "/"));
    homes.add(privacy.home.replaceAll("/", "\\"));
  }
  for (const home of [...homes].sort((a, b) => b.length - a.length)) {
    let pattern = homeRegexCache.get(home);
    if (!pattern) {
      pattern = new RegExp(`${escapeRegExp(home)}(?=$|[\\\\/\\s"'\`:;,)\\]}>]|$)`, /^[A-Za-z]:/.test(home) ? "gi" : "g");
      homeRegexCache.set(home, pattern);
    }
    out = out.replace(pattern, "~");
  }
  // A Windows profile that is not the home (WSL's /mnt/c/Users/<name>, whatever the Windows account is called).
  out = maskWindowsProfiles(out);
  const user = privacy.user;
  if (user && user.length >= 2 && /^[\w.@-]+$/.test(user)) {
    const name = escapeRegExp(user);
    // Not inside a drive's profile folder (/mnt/c/Users/<user>, /c/Users/<user>): that is masked above, structure kept.
    out = out.replace(new RegExp(`(?<!/[A-Za-z]|[A-Za-z]:)(?:/home|/Users|/var/home)/${name}(?=$|[/\\s"'\`:;,)\\]}>])`, "g"), "~");
  }
  return out;
}

/** A path for the record: the home directory as `~`. */
export function tildePath(path: string, privacy: PrivacyContext): string {
  return tildeText(path, privacy);
}

const SECRET_QUERY_KEY = /(?:token|key|secret|password|passwd|pwd|auth|sig|signature|credential|session|code)/i;

/** A URL without userinfo and without secret-looking query values (unparseable: returned scrub-ready as given). */
export function cleanUrl(raw: string): string {
  // client-raw: the address as written.
  if (redactionRaw()) return raw;
  const trimmed = raw.trim();
  try {
    const url = new URL(trimmed);
    if (url.username || url.password) {
      url.username = "";
      url.password = "";
    }
    for (const key of [...url.searchParams.keys()]) {
      if (SECRET_QUERY_KEY.test(key)) url.searchParams.set(key, "[REDACTED]");
    }
    // Anaconda-style tokens live in the path: https://conda.anaconda.org/t/<token>/channel.
    url.pathname = url.pathname.replace(/\/t\/[^/]+/g, "/t/[REDACTED]");
    let out = url.toString().replace(/%5BREDACTED%5D/g, "[REDACTED]");
    // URL adds a "/" path to a bare origin; keep the value as it was written.
    if (!/^[a-z][a-z0-9+.-]*:\/\/[^/?#]*[/]/i.test(trimmed) && out.endsWith("/") && !url.search && !url.hash) out = out.slice(0, -1);
    return out;
  } catch {
    return trimmed.replace(/^([a-z][a-z0-9+.-]*:\/\/)[^/@\s]*@/i, "$1");
  }
}

/** Every URL inside free text without userinfo. */
export function stripUrlUserinfo(text: string): string {
  if (redactionRaw()) return text;
  return text.replace(/\b([a-z][a-z0-9+.-]*:\/\/)[^/@\s"'`]+@/gi, "$1");
}

/** A string for the record: URL userinfo stripped, the home as `~`, then the secret scrub. */
export function cleanText(text: string, privacy: PrivacyContext, scrub: Scrubber): string {
  return scrub.text(tildeText(stripUrlUserinfo(text), privacy));
}

/** UTF-8 byte length. */
export function utf8Bytes(text: string): number {
  return Buffer.byteLength(text, "utf8");
}

/** `text` cut to at most `maxBytes` UTF-8 bytes on a character boundary. */
export function capUtf8(text: string, maxBytes: number): { text: string; truncated: boolean } {
  if (utf8Bytes(text) <= maxBytes) return { text, truncated: false };
  const buffer = Buffer.from(text, "utf8").subarray(0, Math.max(0, maxBytes));
  let cut = buffer.toString("utf8");
  if (cut.endsWith("\uFFFD")) cut = cut.slice(0, -1);
  return { text: cut, truncated: true };
}

/** Keeps leading items of `items` while their JSON stays within `maxBytes`. */
export function capList<T>(items: readonly T[], maxBytes: number): { items: T[]; truncated: boolean } {
  const kept: T[] = [];
  let bytes = 2;
  for (const item of items) {
    const size = utf8Bytes(JSON.stringify(item)) + 1;
    if (bytes + size > maxBytes) return { items: kept, truncated: true };
    bytes += size;
    kept.push(item);
  }
  return { items: kept, truncated: false };
}

/** Whether a buffer holds text (no NUL in its first 8 KiB, valid UTF-8). */
export function isTextBuffer(buffer: Buffer): boolean {
  const head = buffer.subarray(0, 8192);
  if (head.includes(0)) return false;
  try {
    new TextDecoder("utf-8", { fatal: true }).decode(buffer.length > 1024 * 1024 ? buffer.subarray(0, 1024 * 1024 - 4) : buffer);
    return true;
  } catch {
    return buffer.length > 1024 * 1024 - 4;
  }
}

/** A key that names a credential: its value is never recorded. */
export const SECRET_KEY = /(?:^|[_.\-:\s/]|(?<=[a-z]))(?:_?auth|authtoken|auth[_-]?token|token|password|passwd|pass|pwd|secret|credential|credentials|apikey|api[_-]?key|private[_-]?key|privatekey|passphrase|cert|certfile|keyfile|signing|session|cookie|bearer|client[_-]?secret)(?:$|[_.\-:\s/]|(?=[A-Z]))/i;

/** Whether a config key names a credential (`_auth`, `//registry/:_authToken`, `npmAuthToken`, `password`…). */
export function isSecretKey(key: string): boolean {
  const lower = key.toLowerCase();
  if (/_auth|authtoken|authident|token|password|passwd|secret|credential|apikey|api_key|api-key|privatekey|private_key|private-key|passphrase|cookie|bearer|signing\.|signing_|keyfile|certfile|\bcert\b|clientsecret|client_secret/.test(lower)) return true;
  if (/(^|[._:\-/])(auth|key|pass|pwd|username|user|email|login)$/.test(lower)) return true;
  return SECRET_KEY.test(key);
}

export type AddressClass = "loopback" | "any" | "private" | "link-local" | "public";

/**
 * The kind of an IP address. Raw addresses are never recorded (the secret
 * scrub treats every IP literal as personal data); the class says what a
 * port is bound to or where a connection went.
 */
export function addressClass(address: string): AddressClass {
  const ip = address.replace(/^\[|\]$/g, "").replace(/%.*$/, "").toLowerCase();
  const v4 = /^(?:::ffff:)?(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip);
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])];
    if (a === 127) return "loopback";
    if (a === 0) return "any";
    if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127)) return "private";
    if (a === 169 && b === 254) return "link-local";
    return "public";
  }
  if (ip === "::1") return "loopback";
  if (ip === "::" || ip === "*" || ip === "") return "any";
  if (/^fe[89ab]/.test(ip)) return "link-local";
  if (/^f[cd]/.test(ip)) return "private";
  return "public";
}

// --- credential files, wherever they sit ------------------------------------------------

/** File names that hold credentials or browser/OS secrets (compared case-insensitively). */
const SECRET_FILE_NAMES = new Set([
  "cookies", "cookies-journal", "login data", "login data-journal", "login data for account", "web data", "web data-journal",
  "local state", "key3.db", "key4.db", "logins.json", "logins-backup.json", "cookies.sqlite", "cookies.sqlite-wal", "cookies.sqlite-shm",
  ".netrc", "_netrc", ".pgpass", "pgpass.conf", ".npmrc", ".pypirc", ".git-credentials", ".my.cnf", ".htpasswd", "kubeconfig",
]);
/** Path endings (portable `/`) that hold credentials. */
const SECRET_PATH_SUFFIXES = ["gh/hosts.yml", ".docker/config.json", ".kube/config", ".config/hub", ".aws/config", ".azure/accesstokens.json", "gcloud/credentials.db", "gcloud/access_tokens.db"];

/**
 * Whether an absolute or relative path names a credential file: browser
 * cookie and password stores, keychains, netrc/pgpass/npmrc/pypirc,
 * `credentials*`, private keys and certificates (`*.pem`, `*.key`, `id_*`),
 * the gh, docker and kube configs and git's credential store. Such a file
 * is never captured outside the project, whatever folder it is in.
 */
export function isSecretFile(path: string): boolean {
  const portable = path.replaceAll("\\", "/");
  const name = (portable.split("/").at(-1) ?? "").toLowerCase();
  if (!name) return false;
  if (SECRET_FILE_NAMES.has(name)) return true;
  if (name.startsWith("credentials") || name.startsWith("id_") || name.includes(".keychain")) return true;
  if (/\.(?:pem|key|p12|pfx|jks|keystore|kdbx|gpg|asc|ovpn)$/.test(name) || name.endsWith(".kubeconfig")) return true;
  const lower = portable.toLowerCase();
  return SECRET_PATH_SUFFIXES.some((suffix) => lower === suffix || lower.endsWith(`/${suffix}`));
}

/** Browser profile, password-manager and keychain folders (any path component, case-insensitive). */
const SECRET_FOLDER_COMPONENTS = [
  /^google$/, /^chrome(?:-beta|-canary| beta| canary)?$/, /^chromium$/, /^bravesoftware$/, /^brave-browser$/, /^microsoft edge$/, /^microsoft-edge$/, /^vivaldi$/,
  /^opera(?: software)?$/, /^mozilla$/, /^firefox$/, /^thunderbird$/, /^safari$/, /^arc$/, /^1password(?: \d+)?$/, /^bitwarden$/,
  /^keepass(?:xc)?$/, /^lastpass$/, /^dashlane$/, /^enpass$/, /^keychains?$/, /^keyrings?$/, /^password-store$/, /^\.password-store$/,
  /^\.gnupg$/, /^\.ssh$/, /^credentials$/, /^cookies$/,
];

export function isSecretFolder(path: string): boolean {
  return path.replaceAll("\\", "/").split("/").some((part) => SECRET_FOLDER_COMPONENTS.some((pattern) => pattern.test(part.toLowerCase())));
}

/**
 * Whether a folder under the home directory is the user's settings or app
 * data rather than a work folder: any home dot-folder (`~/.config`,
 * `~/.local`, `~/.ssh`, …), `~/Library`, `~/AppData`, `~/snap`.
 */
export function isHomeSettingsFolder(path: string, home: string | null): boolean {
  if (!home) return false;
  const portableHome = home.replaceAll("\\", "/").replace(/\/+$/, "");
  const portable = path.replaceAll("\\", "/");
  const windows = /^[A-Za-z]:/.test(portableHome);
  const a = windows ? portable.toLowerCase() : portable;
  const b = windows ? portableHome.toLowerCase() : portableHome;
  if (!a.startsWith(`${b}/`)) return false;
  const first = portable.slice(portableHome.length + 1).split("/")[0] ?? "";
  return first.startsWith(".") || /^(?:library|appdata|snap|application data|local settings)$/i.test(first);
}
