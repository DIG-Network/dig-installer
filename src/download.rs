//! Network fetching: latest-release discovery + binary download with an
//! optional SHA-256 integrity check.
//!
//! All HTTP goes through `ureq` (rustls, no system OpenSSL). The pure helpers
//! (`tag_name_from_release_json`, `sha256_hex`) are unit-tested; the functions
//! that actually hit the network are thin and only used at install time.

use std::io::Read;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::release::Repo;

/// GitHub requires a User-Agent on API requests.
const USER_AGENT: &str = concat!("dig-installer/", env!("CARGO_PKG_VERSION"));

/// How many times a transient HTTP failure is retried before the install gives
/// up (dig_ecosystem#2784).
///
/// An install is a chain of GitHub calls, and ANY one of them failing aborts
/// the whole install and rolls back every completed step. Single-shot requests
/// therefore turn an ordinary, self-healing blip — a dropped TLS handshake, a
/// 502 from `api.github.com`, a truncated body — into a red install. Three
/// attempts covers the observed blips without hiding a genuine outage (which
/// still fails, just a few seconds later).
const HTTP_ATTEMPTS: u32 = 3;

/// The pause before the first retry; doubled for each subsequent attempt.
const HTTP_RETRY_BACKOFF: std::time::Duration = std::time::Duration::from_millis(500);

/// A failed HTTP attempt plus the one thing the retry loop needs to know about
/// it: whether trying again could plausibly produce a different answer.
///
/// Classification is on the typed `ureq` error, never on a formatted string,
/// so a message reword can never silently change retry behaviour.
struct HttpFailure {
    message: String,
    retryable: bool,
}

/// Classify a `ureq` error: transport-level failures (DNS, connect, TLS
/// handshake, dropped connection) and the server-side transient statuses (429
/// rate-limit, 5xx) are worth retrying. Every other status — notably the 404
/// that [`latest_release`] deliberately reads as "no published release" and the
/// 401 of a rejected credential — is a real answer, and retrying it only
/// delays the report.
///
/// `authenticated` should be `true` when the request carried an `Authorization`
/// header (i.e. `get_text_with_token_retrying` with a non-empty token).
/// When `authenticated` is `false` (the unauthenticated asset-download path),
/// a **403** is also retried: GitHub returns 403 — not 401 — for anonymous
/// rate-limit and abuse-detection trips on `releases/download`, and those are
/// transient by construction. On the authenticated path a 403 is a rejected or
/// exhausted token and retrying it would only waste the budget.
fn classify(url: &str, err: ureq::Error, authenticated: bool) -> HttpFailure {
    let retryable = match &err {
        ureq::Error::Transport(_) => true,
        ureq::Error::Status(code, _) => {
            *code == 429 || *code >= 500 || (*code == 403 && !authenticated)
        }
    };
    HttpFailure {
        message: format!("GET {url}: {err}"),
        retryable,
    }
}

/// Run `op` until it succeeds, it fails non-retryably, or `attempts` is spent.
///
/// `backoff` is the first pause and doubles each retry; tests pass
/// `Duration::ZERO` so they exercise the real loop without real sleeping.
fn with_retry<T>(
    attempts: u32,
    backoff: std::time::Duration,
    mut op: impl FnMut() -> Result<T, HttpFailure>,
) -> Result<T, String> {
    let mut pause = backoff;
    for _ in 1..attempts {
        match op() {
            Ok(value) => return Ok(value),
            Err(f) if f.retryable => {
                if !pause.is_zero() {
                    std::thread::sleep(pause);
                }
                pause *= 2;
            }
            Err(f) => return Err(f.message),
        }
    }
    op().map_err(|f| f.message)
}

/// A GitHub release reduced to what the installer needs: the tag and the names
/// of every uploaded asset (so the OS/arch matcher in [`crate::asset`] can pick
/// the right one, instead of betting on a single guessed filename).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    pub tag_name: String,
    pub asset_names: Vec<String>,
}

/// Parse the `tag_name` out of a GitHub release JSON payload.
/// Pure — takes the raw body, returns the tag (e.g. `v0.6.0`).
pub fn tag_name_from_release_json(body: &str) -> Result<String, String> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("parse release JSON: {e}"))?;
    v.get("tag_name")
        .and_then(|t| t.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "release JSON had no tag_name".to_string())
}

/// Extract a [`Release`] (tag + asset names) from a single release JSON object
/// (`serde_json::Value`). Shared by [`release_from_json`] (a single-release API
/// response) and [`release_from_list_json`] (one entry of a releases-list
/// response) so both parse identically.
fn release_from_value(v: &serde_json::Value) -> Result<Release, String> {
    let tag_name = v
        .get("tag_name")
        .and_then(|t| t.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "release JSON had no tag_name".to_string())?;
    let asset_names = v
        .get("assets")
        .and_then(|a| a.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|a| a.get("name").and_then(|n| n.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default();
    Ok(Release {
        tag_name,
        asset_names,
    })
}

/// Parse a GitHub release JSON payload into a [`Release`] (tag + asset names).
/// Pure — the heart of the thin-shim asset resolution, unit-tested without a
/// network.
pub fn release_from_json(body: &str) -> Result<Release, String> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("parse release JSON: {e}"))?;
    release_from_value(&v)
}

/// Parse a GitHub *releases list* JSON payload (an array, newest first) into
/// the newest [`Release`], regardless of its prerelease/draft flags.
///
/// This is the fallback for [`latest_release`] when `/releases/latest` 404s:
/// that endpoint excludes prereleases AND drafts, so a repo whose newest (or
/// only) release is prerelease-flagged — e.g. DIG Browser's alpha channel —
/// never appears there even though a real, asset-bearing release exists. The
/// list endpoint has no such filter, so its first entry is the newest release
/// GitHub knows about.
pub fn release_from_list_json(body: &str) -> Result<Release, String> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("parse releases list JSON: {e}"))?;
    let arr = v
        .as_array()
        .ok_or_else(|| "releases list JSON was not an array".to_string())?;
    let first = arr
        .first()
        .ok_or_else(|| "no releases published".to_string())?;
    release_from_value(first)
}

/// True when a release-lookup error indicates "no such release" (HTTP 404) —
/// the signal that `/releases/latest` found nothing published, so the caller
/// should fall back to the full releases list ([`release_from_list_json`])
/// rather than treating it as a transport failure.
fn is_release_not_found(err: &str) -> bool {
    err.contains("404") || err.contains("Not Found")
}

/// Discover the latest published tag for a repo via the GitHub API.
pub fn latest_tag(repo: &Repo) -> Result<String, String> {
    Ok(latest_release(repo)?.tag_name)
}

/// Fetch the latest release (tag + asset list) for a repo via the GitHub API.
///
/// Tries `/releases/latest` first; that endpoint excludes prereleases and
/// drafts, so it 404s for a repo whose newest release is prerelease-only
/// (DIG Browser's alpha channel). On a 404, fall back to the full releases
/// list ([`release_from_list_json`]) and take the newest entry regardless of
/// prerelease status. Repos that always ship a non-prerelease "latest" (the
/// common case) never hit the fallback.
pub fn latest_release(repo: &Repo) -> Result<Release, String> {
    let url = repo.latest_release_api();
    match get_text(&url) {
        Ok(body) => release_from_json(&body),
        Err(e) if is_release_not_found(&e) => {
            let body = get_text(&repo.releases_list_api())?;
            release_from_list_json(&body)
        }
        Err(e) => Err(e),
    }
}

/// Fetch a specific release by tag (tag + asset list) via the GitHub API.
pub fn release_by_tag(repo: &Repo, tag: &str) -> Result<Release, String> {
    let url = repo.release_by_tag_api(tag);
    let body = get_text(&url)?;
    release_from_json(&body)
}

/// GET a URL as text with the GitHub API headers, optionally authenticated via
/// [`GITHUB_TOKEN_ENV`] (see [`get_text_with_token`]). Internal helper — the
/// production entry point every `latest_release`/`release_by_tag` call goes
/// through.
fn get_text(url: &str) -> Result<String, String> {
    get_text_with_token(url, std::env::var(GITHUB_TOKEN_ENV).ok().as_deref())
}

/// The environment variable an optional GitHub token is read from (task
/// #502/#524: unauthenticated `api.github.com` calls are capped at 60/hour
/// per source IP, a limit CI runners — which share a huge, heavily-used IP
/// pool — hit routinely; a token raises it to 5,000/hour). Matches the name
/// GitHub Actions already exposes as `secrets.GITHUB_TOKEN` and the `gh` CLI
/// convention, so CI needs no new secret — just `env: GITHUB_TOKEN:
/// ${{ secrets.GITHUB_TOKEN }}` on the step. Entirely optional: every call
/// works unauthenticated exactly as before when it is unset.
const GITHUB_TOKEN_ENV: &str = "GITHUB_TOKEN";

/// [`get_text`] with an injectable token — the pure-ish core so the
/// Authorization-header decision is unit-tested (against a real local
/// socket) without mutating the process environment. `token: None` sends the
/// SAME anonymous request as before this option existed.
fn get_text_with_token(url: &str, token: Option<&str>) -> Result<String, String> {
    get_text_with_token_retrying(url, token, HTTP_ATTEMPTS, HTTP_RETRY_BACKOFF)
}

/// [`get_text_with_token`] with the retry budget injected, so the retry
/// behaviour is unit-tested against a real socket without real sleeping.
fn get_text_with_token_retrying(
    url: &str,
    token: Option<&str>,
    attempts: u32,
    backoff: std::time::Duration,
) -> Result<String, String> {
    with_retry(attempts, backoff, || {
        let mut req = ureq::get(url)
            .set("User-Agent", USER_AGENT)
            .set("Accept", "application/vnd.github+json");
        let has_token = token.map_or(false, |t| !t.is_empty());
        if let Some(t) = token.filter(|t| !t.is_empty()) {
            req = req.set("Authorization", &format!("Bearer {t}"));
        }
        let resp = req.call().map_err(|e| classify(url, e, has_token))?;
        // A body that fails mid-read is the same class of blip as a dropped
        // handshake — the request is repeatable, so retry it too.
        resp.into_string().map_err(|e| HttpFailure {
            message: format!("read {url}: {e}"),
            retryable: true,
        })
    })
}

/// Hex SHA-256 of a byte slice.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// Download `url` into memory. Returns the bytes (binaries are tens of MB —
/// fine to hold in RAM, and it lets us checksum before writing anything).
pub fn fetch_bytes(url: &str) -> Result<Vec<u8>, String> {
    fetch_bytes_retrying(url, HTTP_ATTEMPTS, HTTP_RETRY_BACKOFF)
}

/// [`fetch_bytes`] with the retry budget injected (see
/// [`get_text_with_token_retrying`]).
fn fetch_bytes_retrying(
    url: &str,
    attempts: u32,
    backoff: std::time::Duration,
) -> Result<Vec<u8>, String> {
    with_retry(attempts, backoff, || {
        let resp = ureq::get(url)
            .set("User-Agent", USER_AGENT)
            .call()
            .map_err(|e| classify(url, e, false))?;
        let mut buf = Vec::new();
        resp.into_reader()
            .read_to_end(&mut buf)
            .map_err(|e| HttpFailure {
                message: format!("read body {url}: {e}"),
                retryable: true,
            })?;
        if buf.is_empty() {
            // An empty body from a 200 is a truncated response, not an answer.
            return Err(HttpFailure {
                message: format!("downloaded 0 bytes from {url}"),
                retryable: true,
            });
        }
        Ok(buf)
    })
}

/// The result of writing a component binary to its destination.
///
/// Distinguishes the ordinary in-place write from the locked-destination
/// fallback (#544), so the caller can LOUDLY tell the user when a restart is
/// required before the new binary takes effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteOutcome {
    /// The bytes were written to the destination — the new binary is live now.
    Replaced,
    /// The destination was still locked by a running service/process at
    /// FILE-OPEN time — on Windows a running executable cannot be opened for
    /// writing, so `File::create` failed with `ERROR_SHARING_VIOLATION`
    /// ("os error 32") BEFORE truncating anything. Because the open failed,
    /// `dest` is provably UNTOUCHED, so the new binary was STAGED beside it and
    /// an atomic replace was scheduled for the next reboot
    /// (`MoveFileEx … MOVEFILE_DELAY_UNTIL_REBOOT`). The old binary keeps
    /// running until then; the destination is NEVER left half-written — ONLY
    /// this open-time case stages, since any write-time error (the file already
    /// opened + truncated) propagates as a hard failure instead. The caller
    /// must tell the user a restart is required to finish the update.
    ScheduledForReboot,
}

/// The full result of writing a component binary: the [`WriteOutcome`] plus the
/// rollback breadcrumbs a partial-install failure needs to reverse the write
/// WITHOUT deleting a binary the machine already had (dig_ecosystem#1914/#1915).
///
/// Before #1914 the caller recorded every write as `FileCreated`, so a rollback
/// after a partial failure DELETED files it had merely overwritten — leaving a
/// reinstall-over-existing worse than before it began. These breadcrumbs let the
/// caller record a *replaced* file distinctly so rollback can RESTORE it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteResult {
    /// Whether the new binary is live now or staged for a reboot-time replace.
    pub outcome: WriteOutcome,
    /// If `dest` PRE-EXISTED and was overwritten in place, the sibling backup
    /// holding its prior bytes, so a rollback can RESTORE them (never delete).
    /// `None` for a genuinely new destination (rollback deletes it) or the
    /// reboot-staged case (where `dest` was left untouched — its old binary IS
    /// the prior state).
    pub replaced_backup: Option<PathBuf>,
    /// If the destination was locked and the new bytes were staged for a
    /// reboot-time replace, the staging file a rollback should delete to cancel
    /// the pending replace — leaving the still-running old binary at `dest`
    /// untouched. `None` on an ordinary in-place write.
    pub reboot_staging: Option<PathBuf>,
}

impl WriteResult {
    /// The result of a write that did not actually touch the disk (a dry run):
    /// there is nothing to roll back and no restart is implied.
    #[must_use]
    pub fn nothing_written() -> Self {
        Self {
            outcome: WriteOutcome::Replaced,
            replaced_backup: None,
            reboot_staging: None,
        }
    }

    /// Does finishing this write require a restart to take effect (#544)?
    #[must_use]
    pub fn restart_required(&self) -> bool {
        self.outcome == WriteOutcome::ScheduledForReboot
    }
}

/// The sibling path a pre-existing destination is copied to before it is
/// overwritten, so a partial-install rollback can restore the prior bytes
/// (dig_ecosystem#1914). A hidden, pid-tagged neighbour of `dest` in the same
/// (root-owned, protected) directory, so a concurrent run never collides and an
/// attacker cannot pre-plant or tamper with it.
fn backup_path(dest: &Path) -> PathBuf {
    sibling_path(dest, BACKUP_TAG)
}

/// The infix marking a hidden sibling as this installer's pre-overwrite BACKUP
/// of a destination ([`backup_path`]).
pub const BACKUP_TAG: &str = ".dig-bak-";

/// The infix marking a hidden sibling as bytes STAGED for a reboot-time replace
/// ([`staging_path`]). Windows-only in production; the constant is unconditional
/// so the leftover scan ([`interrupted_install_leftovers`]) — and its test — are
/// falsifiable on every platform rather than only under `#[cfg(windows)]`.
pub const STAGING_TAG: &str = ".pending-";

/// A hidden, pid-tagged neighbour of `dest`: `.<file name><tag><pid>`.
///
/// Hidden so it never looks like an installed binary, pid-tagged so two
/// concurrent runs cannot collide on it. Both properties are what make an
/// ABANDONED one recognizable afterwards — see [`interrupted_install_leftovers`].
fn sibling_path(dest: &Path, tag: &str) -> PathBuf {
    let name = dest
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "binary".to_string());
    dest.with_file_name(format!(".{name}{tag}{}", std::process::id()))
}

/// Every abandoned write-sibling of `dest` left in its directory by an
/// INTERRUPTED install — a backup copied aside before an overwrite, or bytes
/// staged for a reboot-time replace — regardless of which run's pid tagged it.
///
/// # Why this exists (dig_ecosystem#1911, recovery path 4)
///
/// Both sibling shapes are tagged with the WRITING process's pid, so a run that
/// is killed between creating one and cleaning it up leaves a file no later run
/// will ever name again: the next install computes a fresh pid and looks right
/// past it, and the uninstall's residue scan only ever joined
/// `root/<exe name>` — so the one artifact an interrupted install is guaranteed
/// to leave was invisible to BOTH recovery routes. `--uninstall` then reported
/// `residue: []` with a full copy of every replaced binary still on disk, which
/// is the #854 false-zero-residue claim over again.
///
/// Matching is by the WRITER's own tags ([`BACKUP_TAG`]/[`STAGING_TAG`]), which
/// is the point: the scanner cannot drift from the naming it is scanning for.
///
/// Scoped tightly — a name must be the hidden form of THIS `exe_name` and carry
/// one of the two tags — so nothing a user or another product put in the
/// directory is ever matched. Returns an empty vec for an unreadable/absent
/// directory: a leftover we cannot see is reported as nothing found, never as
/// an error that would fail an otherwise clean uninstall.
pub fn interrupted_install_leftovers(root: &Path, exe_name: &str) -> Vec<PathBuf> {
    let prefix = format!(".{exe_name}");
    let Ok(entries) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    let mut found: Vec<PathBuf> = entries
        .flatten()
        .filter(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            let Some(rest) = name.strip_prefix(&prefix) else {
                return false;
            };
            [BACKUP_TAG, STAGING_TAG]
                .iter()
                .any(|tag| rest.starts_with(tag))
        })
        .map(|e| e.path())
        .collect();
    found.sort();
    found
}

/// Delete every abandoned write-sibling of `exe_name` in `root`
/// ([`interrupted_install_leftovers`]), returning how many were removed and one
/// message per file that could not be. Idempotent: a directory with nothing
/// abandoned removes nothing and reports no error, so a second uninstall run
/// stays the clean no-op `uninstall`'s contract promises.
pub fn remove_interrupted_install_leftovers(root: &Path, exe_name: &str) -> (usize, Vec<String>) {
    let mut removed = 0usize;
    let mut errors = Vec::new();
    for leftover in interrupted_install_leftovers(root, exe_name) {
        match std::fs::remove_file(&leftover) {
            Ok(()) => removed += 1,
            Err(e) => errors.push(format!("{}: {e}", leftover.display())),
        }
    }
    (removed, errors)
}

/// Copy `dest`'s current bytes aside to a protected sibling BEFORE the write
/// destroys them, returning the backup path so the write can be undone by
/// restoring it. `Ok(None)` when there is no prior REGULAR file to preserve —
/// either `dest` is absent (a genuine first install) or it is a symlink/other
/// (an installed DIG binary is never a symlink; the write below unlinks a plant
/// and there is nothing to restore).
///
/// Copying — not renaming — is deliberate: it leaves the security-critical
/// unlink-first write ([`write_without_following_a_symlink`]) exactly as it is.
/// That path's Windows locked-image detection depends on `remove_file`'s own
/// failure, which a rename could pre-empt (a running Windows image can be
/// renamed but not deleted). The backup lives in the same root-owned protected
/// directory as `dest`, so the extra copy is never attacker-readable.
///
/// The backup is **adopted into privileged ownership at creation** — see
/// [`back_up_existing_with`] for why a restore path with no downstream #565 gate
/// makes that a security requirement, not a nicety.
pub(crate) fn back_up_existing(dest: &Path) -> Result<Option<PathBuf>, String> {
    back_up_existing_with(dest, &crate::secure::adopt_placed_file)
}

/// [`back_up_existing`] with the "give the backup privileged ownership" effect
/// injected, so the #1910 adoption is asserted on EVERY platform's test run —
/// production passes [`crate::secure::adopt_placed_file`], which no-ops off
/// Windows and outside the protected root, so injection is the only place the
/// wiring is falsifiable on a Linux runner (the `#[cfg(windows)]`-unfalsifiable
/// trap this codebase has been bitten by before).
///
/// # Why the adoption is load-bearing (dig_ecosystem#1910 via #1914)
///
/// The backup can later be RESTORED onto the live, privileged binary path by a
/// rollback (`undo_install_action`'s `FileReplaced` arm, or the hard-write-error
/// arm below) — and unlike a fresh install, that restore is NOT followed by
/// dig-node's #565 service-registration refusal, which is what normally catches
/// a user-writable SYSTEM binary. On Windows a file the elevated installer
/// creates carries the invoking USER as owner with a `CREATOR OWNER` FullControl
/// ACE (#1910), and `rename` keeps the source's security descriptor — so
/// promoting an un-adopted backup onto `dig-node.exe` would hand a non-SYSTEM
/// principal write over a binary a SYSTEM service executes (user → SYSTEM LPE,
/// the exact class §565 hard-refuses). Adopting the backup HERE, at creation,
/// makes any later promotion already clean and also secures a backup that a
/// failed commit-time cleanup leaves behind.
///
/// Fail CLOSED: if the backup cannot be secured, remove it and abort the write
/// with `dest` untouched — never stage a backup a restore could not safely use.
fn back_up_existing_with(
    dest: &Path,
    adopt: &dyn Fn(&Path) -> Result<(), String>,
) -> Result<Option<PathBuf>, String> {
    let meta = match std::fs::symlink_metadata(dest) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("stat {} before overwrite: {e}", dest.display())),
        Ok(m) => m,
    };
    if !meta.file_type().is_file() {
        return Ok(None);
    }
    let backup = backup_path(dest);
    // Clear any stale backup left at this exact pid-path by a crashed prior run,
    // so the copy target is free (best-effort — a genuine failure surfaces below).
    let _ = std::fs::remove_file(&backup);
    std::fs::copy(dest, &backup)
        .map_err(|e| format!("back up {} before overwrite: {e}", dest.display()))?;
    if let Err(e) = adopt(&backup) {
        let _ = std::fs::remove_file(&backup);
        return Err(format!("secure backup {}: {e}", backup.display()));
    }
    Ok(Some(backup))
}

/// Download a binary to `dest`, making it executable on unix. If
/// `expected_sha256` is `Some`, the download is verified before writing and a
/// mismatch is a hard error (nothing is written).
pub fn download_binary(
    url: &str,
    dest: &Path,
    expected_sha256: Option<&str>,
) -> Result<WriteResult, String> {
    let bytes = fetch_bytes(url)?;
    verify_and_write(&bytes, dest, expected_sha256).map_err(|e| e.replace("the artifact", url))
}

/// Verify `bytes` against `expected_sha256` (if given) and write them to `dest`,
/// creating the parent dir. Split out from [`download_binary`] (which adds the
/// network fetch) so the checksum + write logic is unit-tested WITHOUT a
/// network. On a checksum mismatch nothing is written. The write itself goes
/// through [`replace_binary`], which is resilient to a locked destination.
fn verify_and_write(
    bytes: &[u8],
    dest: &Path,
    expected_sha256: Option<&str>,
) -> Result<WriteResult, String> {
    if let Some(expected) = expected_sha256 {
        let got = sha256_hex(bytes);
        if !got.eq_ignore_ascii_case(expected.trim()) {
            return Err(format!(
                "checksum mismatch for the artifact: expected {expected}, got {got}"
            ));
        }
    }
    if let Some(parent) = dest.parent() {
        // NOT a bare `create_dir_all`: that applies the process umask, and an inherited `umask 000`
        // produced a world-writable `/opt/dig/bin` — every local account able to replace a binary root
        // executes (#1748). `ensure_bin_dir` pins the protected root's mode instead.
        crate::paths::ensure_bin_dir(parent)?;
    }
    replace_binary(dest, bytes)
}

/// Write `bytes` to `dest`, resilient — on Windows — to `dest` being held open
/// by a running service/process (#544).
///
/// On Windows a running executable is locked against being opened for writing,
/// so a plain in-place write fails with a sharing violation ("os error 32") at
/// OPEN time — the exact failure a running `dig-dns` service produced when an
/// upgrade tried to overwrite `dig-dns.exe`. Because that open fails before any
/// truncation, `dest` is untouched; the new binary is then staged beside it and
/// an atomic replace scheduled for the next reboot, rather than aborting. Any
/// other, write-time error — including `ERROR_LOCK_VIOLATION` (33) — is a hard
/// failure and propagates (see [`is_sharing_violation`]).
///
/// On Linux, opening a RUNNING binary for write instead fails hard AT OPEN with
/// `ETXTBSY` (errno 26): the write aborts with `dest` intact (fail-closed, never
/// half-written), and this reboot-time staging fallback does NOT apply — it is a
/// Windows-only guarantee. (A genuine atomic write-temp + `rename(2)` replace on
/// unix is a recommended future follow-up, separately ticketed.)
pub fn replace_binary(dest: &Path, bytes: &[u8]) -> Result<WriteResult, String> {
    replace_binary_with(dest, bytes, schedule_replace_on_reboot)
}

/// [`replace_binary`] with an injectable "schedule the delayed replace" action
/// — production passes [`schedule_replace_on_reboot`] (the real
/// `MoveFileEx`-until-reboot staging); tests inject a recorder so the
/// locked-destination fallback is exercised without touching the system's
/// pending-rename registry or needing a real reboot.
fn replace_binary_with(
    dest: &Path,
    bytes: &[u8],
    schedule_on_reboot: impl Fn(&Path, &[u8]) -> Result<(), String>,
) -> Result<WriteResult, String> {
    // Preserve the prior occupant's bytes BEFORE the write can destroy them
    // (the write unlinks `dest` first), so a partial-install rollback RESTORES
    // them rather than deleting a binary the machine already had and relied on
    // (dig_ecosystem#1914/#1915).
    let backup = back_up_existing(dest)?;

    match write_without_following_a_symlink(dest, bytes) {
        Ok(()) => {
            // Executability is set INSIDE the write, on the descriptor it holds — never by path
            // afterwards (#1748, F4).
            Ok(WriteResult {
                outcome: WriteOutcome::Replaced,
                replaced_backup: backup,
                reboot_staging: None,
            })
        }
        Err(e) if is_sharing_violation(&e) || destination_is_a_running_image(&e, dest) => {
            // The open/unlink failed on a running image, so `dest` is provably
            // UNTOUCHED — its old binary is still there and IS the prior state.
            // The backup we took is therefore redundant; drop it, stage the new
            // bytes, and hand back the staging path so a rollback deletes THAT
            // (cancelling the pending replace) rather than the still-running old
            // binary at `dest`.
            if let Some(b) = &backup {
                let _ = std::fs::remove_file(b);
            }
            schedule_on_reboot(dest, bytes)?;
            let reboot_staging = {
                #[cfg(windows)]
                {
                    Some(staging_path(dest))
                }
                #[cfg(not(windows))]
                {
                    None
                }
            };
            Ok(WriteResult {
                outcome: WriteOutcome::ScheduledForReboot,
                replaced_backup: None,
                reboot_staging,
            })
        }
        Err(e) => {
            // A hard write failure. The write unlinks `dest` before creating it,
            // so a failure AFTER the unlink would leave the destination MISSING —
            // itself the #1914 "recovery made it worse" shape. If we hold the
            // prior bytes, put them back before surfacing the error so a failed
            // write never subtracts a working binary; otherwise clean the backup.
            if let Some(b) = &backup {
                if dest.exists() {
                    let _ = std::fs::remove_file(b);
                } else {
                    let _ = std::fs::rename(b, dest);
                }
            }
            Err(format!("write {}: {e}", dest.display()))
        }
    }
}

/// Is `e` an `ERROR_ACCESS_DENIED` raised by UNLINKING a destination that is a
/// currently RUNNING executable — the same recoverable case as
/// [`is_sharing_violation`], reached through the other door?
///
/// # Why this exists (#1911, found on a real reinstall)
///
/// The #1748 rewrite made every write UNLINK the destination before creating it,
/// which closed a symlink-redirect hole. It also changed which error a running
/// destination produces. Opening a running image for write yields
/// `ERROR_SHARING_VIOLATION` (32), which the reboot-replace fallback recognises —
/// but DELETING one yields `ERROR_ACCESS_DENIED` (5), which it did not. So the
/// fallback silently stopped covering the case it was built for, for any binary
/// nothing stops first.
///
/// It is not hypothetical: a reinstall over an existing install failed at
/// `dig-app.exe` (a tray app the installer itself launches and never stops) with
/// `write …: Access is denied. (os error 5)`, and the rollback that followed
/// deleted the dig-store, digs and dign binaries the machine already had. The
/// service binaries were unaffected only because they are stopped by id first.
///
/// # It must not swallow a genuine permission failure
///
/// Error 5 is also what an ACL problem looks like, and staging a reboot-time
/// replace for one would report a success that never happens. So the code is not
/// trusted on its own: the destination is PROBED by opening it for write. A
/// running image refuses that with a sharing violation (its image section denies
/// write sharing); a merely unwritable file refuses with access-denied again, and
/// a writable one opens. Only the sharing violation is the running-image answer.
#[cfg(windows)]
fn destination_is_a_running_image(e: &std::io::Error, dest: &Path) -> bool {
    if e.raw_os_error() != Some(5) {
        return false;
    }
    match std::fs::OpenOptions::new().write(true).open(dest) {
        Ok(_) => false,
        Err(probe) => is_sharing_violation(&probe),
    }
}

/// Never true off Windows: neither the unlink-time access-denied nor the
/// image-section lock this discriminates exists there (a running binary fails
/// with `ETXTBSY` at open, which is a hard failure by design).
#[cfg(not(windows))]
fn destination_is_a_running_image(e: &std::io::Error, dest: &Path) -> bool {
    let _ = (e, dest);
    false
}

/// Write `bytes` to `dest` without ever following a symlink that is already there.
///
/// # Why a plain `std::fs::write` is not safe here (#1748)
///
/// `std::fs::write` opens with `O_CREAT|O_TRUNC` and FOLLOWS an existing symlink, so a link planted at
/// the destination redirects the write to its target. Under an elevated install that is a root
/// arbitrary-file-create-and-overwrite primitive: `ln -s /etc/ld.so.preload /usr/local/bin/dign` and the
/// next `sudo` install has root create and populate that file — and the `0755` that follows marks the
/// TARGET executable. No race is required, because the destination filenames are deterministic and
/// published. `same_binary` cannot catch it either: it canonicalises both sides, so a link and its
/// target compare equal.
///
/// The destination is therefore UNLINKED first and then created with `O_EXCL`, which cannot follow
/// anything: after the unlink there is no symlink left to follow, and `O_EXCL` refuses to open a path
/// that reappeared in between — so a concurrent re-plant loses rather than wins. `O_NOFOLLOW` is set as
/// well, making the refusal explicit rather than incidental.
///
/// # The mode is set on the DESCRIPTOR, not on the path afterwards (#1748)
///
/// Creating the file safely and then calling `metadata` + `set_permissions` on `dest` re-resolves the
/// path twice more, and both calls follow symlinks — a TOCTOU pair that was WON in practice: 9 hijacks
/// in 6000 iterations turned a root-owned `0600` victim into `mode=755 uid=0`, aimed at `/etc/shadow`.
/// So `fchmod` is applied to the descriptor this function already holds, which names the inode it just
/// created and cannot be redirected to another one.
///
/// Removing the destination first is what an upgrade does anyway (the old binary is being replaced), and
/// it does not change the Windows behaviour this function exists to preserve: `remove_file` on a running
/// Windows executable fails, so the sharing-violation path in [`replace_binary_with`] still sees its
/// error and still schedules the reboot-time replace.
fn write_without_following_a_symlink(dest: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    // `remove_file` unlinks a symlink itself rather than its target, so this cannot damage whatever a
    // planted link pointed at. A missing destination is the ordinary first-install case.
    match std::fs::remove_file(dest) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        // Anything else (a running Windows executable, a permission problem) is surfaced unchanged, so
        // the caller's sharing-violation handling still applies.
        Err(e) => return Err(e),
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(dest)?;
    file.write_all(bytes)?;
    file.flush()?;
    // Executable, through the descriptor. On Windows executability is by extension, so there is no mode
    // to set and nothing to race.
    #[cfg(unix)]
    {
        crate::dirfd::fchmod_file(&file, EXECUTABLE_MODE, dest).map_err(std::io::Error::other)?;
    }
    Ok(())
}

/// The mode an installed binary is created with: owner writes, everybody executes.
#[cfg(unix)]
const EXECUTABLE_MODE: u32 = 0o755;

/// Does this write error mean the destination is a RUNNING executable that
/// could not be opened for writing — the one recoverable case (#544)?
///
/// Only Windows `ERROR_SHARING_VIOLATION` (32) qualifies. It is "the process
/// cannot access the file because it is being used by another process", raised
/// by `File::create` at FILE-OPEN time — BEFORE any truncation — which is
/// exactly the running-`dig-dns` case and the one state in which `dest` is
/// provably UNTOUCHED, so staging a reboot-time replace is safe.
///
/// `ERROR_LOCK_VIOLATION` (33) is deliberately NOT recoverable: it is a
/// byte-range-lock error raised at WRITE time, so reaching it means
/// `File::create` already SUCCEEDED and truncated `dest`. Treating it as a
/// sharing violation would stage-and-succeed over a half-written destination,
/// breaking the "never left half-written" invariant — so it (and every other
/// write-time error) propagates as a hard failure instead. Never true off
/// Windows, where this open-time lock does not occur.
fn is_sharing_violation(e: &std::io::Error) -> bool {
    #[cfg(windows)]
    {
        matches!(e.raw_os_error(), Some(32))
    }
    #[cfg(not(windows))]
    {
        let _ = e;
        false
    }
}

/// The sibling path new bytes are staged to before a delayed replace — a
/// hidden, pid-tagged neighbour of `dest` so concurrent runs never collide and
/// a stale stage is recognizable. Windows-only: the delayed-replace fallback it
/// serves ([`schedule_replace_on_reboot`]) never runs on other platforms.
#[cfg(windows)]
fn staging_path(dest: &Path) -> std::path::PathBuf {
    sibling_path(dest, STAGING_TAG)
}

/// Stage `bytes` beside `dest` and schedule an atomic replace of `dest` on the
/// next reboot. Windows: write the staging file, then `MoveFileExW(staging,
/// dest, MOVEFILE_REPLACE_EXISTING | MOVEFILE_DELAY_UNTIL_REBOOT)` so the OS
/// swaps in the new binary before any process can re-open the still-running old
/// one. Requires the elevation the install already holds (it records the rename
/// under `HKLM\SYSTEM\…\PendingFileRenameOperations`).
#[cfg(windows)]
fn schedule_replace_on_reboot(dest: &Path, bytes: &[u8]) -> Result<(), String> {
    schedule_replace_on_reboot_with(
        dest,
        bytes,
        &crate::secure::adopt_placed_file,
        &move_on_reboot,
    )
}

/// [`schedule_replace_on_reboot`] with the two effects injected, so the ORDER they
/// happen in is assertable without touching the machine's pending-rename registry.
///
/// # The staged file is the file that will EXIST after the reboot (#1910)
///
/// The staging file is created by the elevated installer, so it carries the
/// invoking admin user as owner and the `CREATOR OWNER` grant that comes with it —
/// and `MoveFileEx` MOVES it, security descriptor and all, onto `dest`. Adopting
/// only `dest` at install time therefore leaves the reboot path re-introducing the
/// exact defect, days later and invisibly: this was observed on a real machine as
/// `.dig-app.exe.pending-76024  owner=TDS1\micha  userACEs=1` sitting in the
/// protected root, staged to become `dig-app.exe`.
///
/// The adoption must precede the schedule, not follow it, so the file is never
/// queued for promotion while still user-owned. A failure to adopt is REPORTED by
/// the caller, never silent, and does not abort the update.
#[cfg(windows)]
fn schedule_replace_on_reboot_with(
    dest: &Path,
    bytes: &[u8],
    adopt: &dyn Fn(&Path) -> Result<(), String>,
    schedule: &dyn Fn(&Path, &Path) -> Result<(), String>,
) -> Result<(), String> {
    let staging = staging_path(dest);
    std::fs::write(&staging, bytes).map_err(|e| format!("stage {}: {e}", staging.display()))?;
    if let Err(e) = adopt(&staging) {
        return Err(format!(
            "staged {} but could not give it privileged ownership ({e}) — promoting it at reboot would leave a binary a non-SYSTEM principal can rewrite",
            staging.display()
        ));
    }
    schedule(&staging, dest).inspect_err(|_| {
        let _ = std::fs::remove_file(&staging);
    })
}

/// `MoveFileExW(staging, dest, REPLACE_EXISTING | DELAY_UNTIL_REBOOT)` — the OS
/// swaps in the new binary before any process can re-open the still-running old one.
#[cfg(windows)]
fn move_on_reboot(staging: &Path, dest: &Path) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_DELAY_UNTIL_REBOOT, MOVEFILE_REPLACE_EXISTING,
    };

    let wide = |p: &Path| -> Vec<u16> {
        p.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    };
    let existing = wide(staging);
    let target = wide(dest);
    // SAFETY: both pointers are NUL-terminated UTF-16 buffers kept alive across
    // the call; the flags are the documented reboot-replace pair.
    let ok = unsafe {
        MoveFileExW(
            existing.as_ptr(),
            target.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_DELAY_UNTIL_REBOOT,
        )
    };
    if ok == 0 {
        let code = unsafe { GetLastError() };
        return Err(format!(
            "could not schedule the reboot-time replace of {} (Win32 error {code})",
            dest.display()
        ));
    }
    Ok(())
}

/// Schedule `path` to be DELETED at the next reboot, for a file that cannot be deleted now because a
/// running process holds it open.
///
/// The uninstall's one unavoidable case is the installer's own image: a process cannot delete itself
/// on Windows, so the teardown used to simply leave `dig-installer.exe` behind — a file the user did
/// not ask to keep, in a directory the uninstall claims to have emptied.
/// `MoveFileExW(path, NULL, MOVEFILE_DELAY_UNTIL_REBOOT)` records the deletion under
/// `HKLM\SYSTEM\…\PendingFileRenameOperations` and the OS performs it before anything can open the
/// file again. Nothing is staged and nothing is written, so this adds no exec-from-writable-path
/// exposure (the #1748 class). Requires the elevation the uninstall already holds.
#[cfg(windows)]
pub fn schedule_delete_on_reboot(path: &Path) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_DELAY_UNTIL_REBOOT};

    let existing: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: `existing` is a NUL-terminated UTF-16 buffer kept alive across the call. A NULL
    // destination with MOVEFILE_DELAY_UNTIL_REBOOT is the documented "delete at reboot" form.
    let ok = unsafe {
        MoveFileExW(
            existing.as_ptr(),
            std::ptr::null(),
            MOVEFILE_DELAY_UNTIL_REBOOT,
        )
    };
    if ok == 0 {
        let code = unsafe { GetLastError() };
        return Err(format!(
            "could not schedule the reboot-time deletion of {} (Win32 error {code})",
            path.display()
        ));
    }
    Ok(())
}

/// Off Windows a running binary CAN be unlinked, so nothing ever needs deferring to a reboot; this
/// exists only so the call site compiles on every platform.
#[cfg(not(windows))]
pub fn schedule_delete_on_reboot(path: &Path) -> Result<(), String> {
    std::fs::remove_file(path).map_err(|e| format!("remove {}: {e}", path.display()))
}

/// Non-Windows never reaches the delayed-replace fallback ([`is_sharing_violation`]
/// is always `false` off Windows, where the open-time sharing-violation lock does
/// not occur — a busy-binary write instead fails hard at open with `ETXTBSY`), so
/// this exists only to satisfy the injection seam's signature.
#[cfg(not(windows))]
fn schedule_replace_on_reboot(dest: &Path, _bytes: &[u8]) -> Result<(), String> {
    Err(format!(
        "unexpected locked destination replacing {} on a non-Windows host",
        dest.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- #1748: the install write must never follow a planted symlink ------------

    /// THE root arbitrary-file-write primitive: a symlink pre-planted at the destination must NOT be
    /// followed, so the file it points at is left untouched and the binary lands at the destination
    /// itself.
    ///
    /// The install filenames are deterministic and published, and the destination directory was (before
    /// this release) user-writable on a Homebrew Mac — so `ln -s /etc/ld.so.preload <bin_dir>/dign` and
    /// the next `sudo` install had root create and populate that file, then the mode change mark it
    /// `0755`. No race is required.
    ///
    /// Runs UNPRIVILEGED, which is the point: the fix is a property of how the file is opened, not of
    /// who opens it, so it gates in CI. The fixture points the link at a file with known contents rather
    /// than at a missing path, so "did not follow" is observable as the victim being INTACT rather than
    /// merely absent.
    #[cfg(unix)]
    #[test]
    fn an_install_write_does_not_follow_a_symlink_planted_at_the_destination() {
        let tmp = tempfile::tempdir().unwrap();
        let victim = tmp.path().join("etc-ld-so-preload");
        std::fs::write(&victim, b"ORIGINAL").unwrap();
        let dest = tmp.path().join("dign");
        std::os::unix::fs::symlink(&victim, &dest).unwrap();

        write_without_following_a_symlink(&dest, b"NEW-BINARY").expect("the write must succeed");

        assert_eq!(
            std::fs::read(&victim).unwrap(),
            b"ORIGINAL",
            "the write followed a planted symlink — root would have overwritten the target and then \
             chmod'ed it 0755 (#1748)"
        );
        // And the binary really landed at the destination, as a regular file rather than a link — a
        // "fix" that merely refused to write anything would fail here.
        assert_eq!(std::fs::read(&dest).unwrap(), b"NEW-BINARY");
        assert!(
            !std::fs::symlink_metadata(&dest).unwrap().is_symlink(),
            "the destination must be a real file afterwards, not the attacker's link"
        );
    }

    /// The installed binary is made executable by the SAME call that wrote it, so there is no window in
    /// which the mode is applied to a path rather than to the descriptor.
    ///
    /// A `metadata` + `set_permissions` pair after the write re-resolves `dest` twice, and both follow
    /// symlinks: the race was won 9 times in 6000 iterations, turning a root-owned `0600` victim into
    /// `mode=755 uid=0`. This asserts the observable consequence — the write alone leaves the file
    /// executable — which a fix that merely reordered the two path calls would NOT satisfy, because the
    /// separate `set_executable` step no longer exists to be called.
    #[cfg(unix)]
    #[test]
    fn the_write_itself_leaves_the_binary_executable() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("dig-node");
        write_without_following_a_symlink(&dest, b"ELF").expect("the write must succeed");
        assert_eq!(
            std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777,
            0o755,
            "the binary must be executable when the write returns — no separate chmod-by-path step"
        );
    }

    /// The ordinary upgrade path must still work: an existing REGULAR file at the destination is
    /// replaced. Asserted so the symlink fix cannot be satisfied by refusing to overwrite anything.
    #[test]
    fn an_install_write_replaces_an_existing_regular_file() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("dig-node");
        std::fs::write(&dest, b"OLD").unwrap();
        write_without_following_a_symlink(&dest, b"NEW").expect("an upgrade must overwrite");
        assert_eq!(std::fs::read(&dest).unwrap(), b"NEW");
    }

    /// A first install (nothing at the destination) is the common case and must not be treated as an
    /// error by the unlink-first step.
    #[test]
    fn an_install_write_creates_a_missing_destination() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("nested").join("dig-dns");
        std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
        write_without_following_a_symlink(&dest, b"FRESH").expect("a first install must succeed");
        assert_eq!(std::fs::read(&dest).unwrap(), b"FRESH");
    }

    #[test]
    fn extracts_tag_name() {
        let body = r#"{"tag_name":"v0.6.0","name":"digstore v0.6.0","draft":false}"#;
        assert_eq!(tag_name_from_release_json(body).unwrap(), "v0.6.0");
    }

    #[test]
    fn errors_without_tag_name() {
        assert!(tag_name_from_release_json(r#"{"name":"x"}"#).is_err());
        assert!(tag_name_from_release_json("not json").is_err());
    }

    #[test]
    fn release_from_json_extracts_tag_and_asset_names() {
        let body = r#"{
            "tag_name": "v0.6.0",
            "assets": [
                {"name": "digstore-0.6.0-linux-x64", "size": 123},
                {"name": "digstore-0.6.0-windows-x64.exe"},
                {"name": "digstore-0.6.0-macos-arm64"}
            ]
        }"#;
        let r = release_from_json(body).unwrap();
        assert_eq!(r.tag_name, "v0.6.0");
        assert_eq!(
            r.asset_names,
            vec![
                "digstore-0.6.0-linux-x64".to_string(),
                "digstore-0.6.0-windows-x64.exe".to_string(),
                "digstore-0.6.0-macos-arm64".to_string(),
            ]
        );
    }

    #[test]
    fn release_from_json_tolerates_no_assets() {
        let r = release_from_json(r#"{"tag_name":"v1.0.0"}"#).unwrap();
        assert_eq!(r.tag_name, "v1.0.0");
        assert!(r.asset_names.is_empty());
    }

    #[test]
    fn release_from_json_errors_without_tag() {
        assert!(release_from_json(r#"{"assets":[]}"#).is_err());
        assert!(release_from_json("not json").is_err());
    }

    #[test]
    fn sha256_is_lowercase_hex() {
        // SHA-256 of the empty input.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn release_from_json_skips_assets_without_a_name() {
        // An asset entry missing `name` is filtered out (not a crash, not an empty
        // string) — only well-formed asset names survive.
        let body = r#"{
            "tag_name": "v1.2.3",
            "assets": [
                {"size": 10},
                {"name": "good-1.2.3-linux-x64"},
                {"name": 42}
            ]
        }"#;
        let r = release_from_json(body).unwrap();
        assert_eq!(r.tag_name, "v1.2.3");
        assert_eq!(r.asset_names, vec!["good-1.2.3-linux-x64".to_string()]);
    }

    #[test]
    fn release_from_json_treats_non_array_assets_as_empty() {
        // `assets` present but not an array → no asset names (no panic).
        let r = release_from_json(r#"{"tag_name":"v1.0.0","assets":"oops"}"#).unwrap();
        assert!(r.asset_names.is_empty());
    }

    #[test]
    fn is_release_not_found_detects_404_variants() {
        // ureq's Status Display is "{url}: status code {code}"; get_text wraps it
        // as "GET {url}: {ureq display}" — both forms must be recognised, plus
        // the plain-English "Not Found" the rest of the codebase also checks for
        // (see lib.rs::classify_release_error, same convention).
        assert!(is_release_not_found(
            "GET https://api.github.com/x: https://api.github.com/x: status code 404"
        ));
        assert!(is_release_not_found(
            "GET https://api.github.com/x: 404 Not Found"
        ));
        assert!(!is_release_not_found(
            "GET https://api.github.com/x: status code 500"
        ));
        assert!(!is_release_not_found(
            "GET https://api.github.com/x: timed out"
        ));
    }

    #[test]
    fn release_from_list_json_takes_the_newest_entry_regardless_of_prerelease() {
        // Regression (#40): DIG Browser's only release
        // (149.0.7827.155-1.1-alpha) is prerelease-flagged, so GitHub's
        // `/releases/latest` (which excludes prereleases/drafts) 404s even
        // though a real release exists. The fallback list-parse must pick the
        // newest (first) entry regardless of its prerelease flag.
        let body = r#"[
            {
                "tag_name": "149.0.7827.155-1.1-alpha",
                "prerelease": true,
                "draft": false,
                "assets": [
                    {"name": "ungoogled-chromium_149.0.7827.155-1.1_installer_x64.exe"},
                    {"name": "ungoogled-chromium_149.0.7827.155-1.1_windows_x64.zip"}
                ]
            },
            {
                "tag_name": "148.0.0.0-1.0-alpha",
                "prerelease": true,
                "draft": false,
                "assets": []
            }
        ]"#;
        let r = release_from_list_json(body).unwrap();
        assert_eq!(r.tag_name, "149.0.7827.155-1.1-alpha");
        assert_eq!(
            r.asset_names,
            vec![
                "ungoogled-chromium_149.0.7827.155-1.1_installer_x64.exe".to_string(),
                "ungoogled-chromium_149.0.7827.155-1.1_windows_x64.zip".to_string(),
            ]
        );
    }

    #[test]
    fn release_from_list_json_errors_on_empty_list() {
        let err = release_from_list_json("[]").unwrap_err();
        assert!(err.contains("no releases"), "got: {err}");
    }

    #[test]
    fn release_from_list_json_errors_on_non_array() {
        assert!(release_from_list_json(r#"{"tag_name":"v1.0.0"}"#).is_err());
        assert!(release_from_list_json("not json").is_err());
    }

    #[test]
    fn verify_and_write_writes_bytes_when_no_checksum_given() {
        let dir =
            crate::sources::fixture_root().join(format!("dig-dl-nohash-{}", std::process::id()));
        let dest = dir.join("nested").join("artifact.bin");
        let outcome = verify_and_write(b"hello dig", &dest, None).expect("write ok");
        assert_eq!(outcome.outcome, WriteOutcome::Replaced);
        // A brand-new destination has no prior occupant to preserve.
        assert!(outcome.replaced_backup.is_none());
        // The nested parent dir was created and the bytes round-trip.
        assert_eq!(std::fs::read(&dest).unwrap(), b"hello dig");
    }

    #[test]
    fn verify_and_write_accepts_a_matching_checksum() {
        let dir = crate::sources::fixture_root().join(format!("dig-dl-ok-{}", std::process::id()));
        let dest = dir.join("artifact.bin");
        let data = b"verified payload";
        let sum = sha256_hex(data);
        // Upper-cased + padded to prove the compare is case-insensitive + trimmed.
        let expected = format!("  {}  ", sum.to_uppercase());
        verify_and_write(data, &dest, Some(&expected)).expect("matching checksum ok");
        assert_eq!(std::fs::read(&dest).unwrap(), data);
    }

    #[test]
    fn verify_and_write_rejects_a_mismatched_checksum_and_writes_nothing() {
        let dir = crate::sources::fixture_root().join(format!("dig-dl-bad-{}", std::process::id()));
        let dest = dir.join("artifact.bin");
        let err = verify_and_write(b"payload", &dest, Some("deadbeef")).unwrap_err();
        assert!(err.contains("checksum mismatch"), "got: {err}");
        // Nothing is written on a mismatch.
        assert!(!dest.exists());
    }

    #[cfg(unix)]
    #[test]
    fn verify_and_write_marks_the_file_executable_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let dir =
            crate::sources::fixture_root().join(format!("dig-dl-exec-{}", std::process::id()));
        let dest = dir.join("tool");
        verify_and_write(b"#!/bin/sh\n", &dest, None).expect("ok");
        let mode = std::fs::metadata(&dest).unwrap().permissions().mode();
        assert_eq!(mode & 0o111, 0o111, "owner/group/other exec bits set");
    }

    // -- get_text_with_token: the optional GitHub-auth header (#502/#524) ----
    //
    // Drives the REAL `ureq` request against a one-shot local server that
    // echoes back whatever `Authorization` header it received (or `NONE`),
    // so the assertion is on the actual wire request `get_text_with_token`
    // sends — not a re-statement of its own `if let` branch. Uses an
    // injected `token: Option<&str>` (never a real env var), so these run
    // safely under Rust's parallel test harness with no shared mutable state.

    /// A one-shot HTTP/1.1 server that reads the request line + headers,
    /// replies 200 with the received `Authorization` header value (or `NONE`)
    /// as the body, then exits. Mirrors `health.rs`'s `one_shot_json_server`.
    fn one_shot_echo_auth_server() -> u16 {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                stream
                    .set_read_timeout(Some(std::time::Duration::from_millis(500)))
                    .ok();
                let mut buf = [0u8; 4096];
                let mut request = Vec::new();
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            request.extend_from_slice(&buf[..n]);
                            if request.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let text = String::from_utf8_lossy(&request);
                let auth = text
                    .lines()
                    .find(|l| l.to_ascii_lowercase().starts_with("authorization:"))
                    .map(|l| l.split_once(':').map_or("", |(_, v)| v).trim().to_string())
                    .unwrap_or_else(|| "NONE".to_string());
                let body = format!("{{\"tag_name\":\"v0.0.0\",\"__auth\":\"{auth}\"}}");
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        });
        port
    }

    // -- retry of transient network failures (dig_ecosystem#2784) -----------
    //
    // The macOS e2e leg went red because a SINGLE `api.github.com` request
    // failed its TLS handshake ("invalid peer certificate ...
    // UnsupportedCertVersion") mid-install, which aborted the install and
    // rolled back every completed step. Sibling reds on the same workflow
    // failed the same way on a 403. The requests were single-shot, so any blip
    // was fatal.
    //
    // These drive the REAL `ureq` request against a local server that fails a
    // controlled number of requests first, so the assertion is on observed
    // wire behaviour (how many requests reached the server, and what came
    // back) — not a re-statement of the retry loop's own branches.

    /// Read an HTTP request head off `stream`, returning `None` if the peer
    /// sent nothing before closing.
    fn read_request_head(stream: &mut std::net::TcpStream) -> Option<String> {
        use std::io::Read;

        stream
            .set_read_timeout(Some(std::time::Duration::from_millis(1000)))
            .ok();
        let mut buf = [0u8; 4096];
        let mut request = Vec::new();
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    request.extend_from_slice(&buf[..n]);
                    if request.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        (!request.is_empty()).then(|| String::from_utf8_lossy(&request).into_owned())
    }

    /// A local server that hard-drops (closes without writing a byte — the
    /// transport-level failure `ureq` also reports for a failed TLS handshake)
    /// its first `drops` requests, then answers every later request with
    /// `status_line` and a release JSON body. Returns the port plus a counter
    /// of REQUESTS received.
    fn server_dropping_first_requests(
        drops: usize,
        status_line: &'static str,
    ) -> (u16, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        use std::io::Write;
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&seen);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                // Count REQUESTS, not accepted sockets: a connection carrying
                // no request must not be mistaken for an attempt.
                if read_request_head(&mut stream).is_none() {
                    continue;
                }
                let n = counter.fetch_add(1, Ordering::SeqCst);
                if n < drops {
                    drop(stream);
                    continue;
                }
                let body = r#"{"tag_name":"v1.2.3","assets":[]}"#;
                let response = format!(
                    "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        (port, seen)
    }

    #[test]
    fn get_text_retries_a_dropped_connection_and_succeeds_on_a_later_attempt() {
        use std::sync::atomic::Ordering;

        let (port, seen) = server_dropping_first_requests(2, "HTTP/1.1 200 OK");
        let body = get_text_with_token_retrying(
            &format!("http://127.0.0.1:{port}/"),
            None,
            HTTP_ATTEMPTS,
            std::time::Duration::ZERO,
        )
        .expect("two transport blips are inside the retry budget");
        assert!(body.contains("v1.2.3"), "got: {body}");
        assert_eq!(seen.load(Ordering::SeqCst), 3, "should have retried twice");
    }

    #[test]
    fn get_text_gives_up_once_the_retry_budget_is_spent() {
        use std::sync::atomic::Ordering;

        // One more blip than the budget covers: the failure is still reported,
        // after exactly `HTTP_ATTEMPTS` attempts — a retry loop must not become
        // an unbounded hang.
        let (port, seen) =
            server_dropping_first_requests(HTTP_ATTEMPTS as usize, "HTTP/1.1 200 OK");
        let err = get_text_with_token_retrying(
            &format!("http://127.0.0.1:{port}/"),
            None,
            HTTP_ATTEMPTS,
            std::time::Duration::ZERO,
        )
        .expect_err("budget spent");
        assert!(err.contains("GET http://127.0.0.1"), "got: {err}");
        assert_eq!(seen.load(Ordering::SeqCst), HTTP_ATTEMPTS as usize);
    }

    #[test]
    fn get_text_does_not_retry_a_404_so_the_no_release_fallback_stays_cheap() {
        use std::sync::atomic::Ordering;

        // `latest_release` reads a 404 as "no published release" and falls back
        // to the full list. Retrying it would triple every fallback and change
        // no answer.
        let (port, seen) = server_dropping_first_requests(0, "HTTP/1.1 404 Not Found");
        let err = get_text_with_token_retrying(
            &format!("http://127.0.0.1:{port}/"),
            None,
            HTTP_ATTEMPTS,
            std::time::Duration::ZERO,
        )
        .expect_err("404 is an answer, not a blip");
        assert!(is_release_not_found(&err), "got: {err}");
        assert_eq!(seen.load(Ordering::SeqCst), 1, "404 must not be retried");
    }

    #[test]
    fn fetch_bytes_retries_a_dropped_connection() {
        use std::sync::atomic::Ordering;

        let (port, seen) = server_dropping_first_requests(1, "HTTP/1.1 200 OK");
        let bytes = fetch_bytes_retrying(
            &format!("http://127.0.0.1:{port}/asset"),
            HTTP_ATTEMPTS,
            std::time::Duration::ZERO,
        )
        .expect("one transport blip is inside the retry budget");
        assert!(!bytes.is_empty());
        assert_eq!(seen.load(Ordering::SeqCst), 2, "should have retried once");
    }

    #[test]
    fn get_text_retries_a_502_but_not_a_401() {
        use std::sync::atomic::Ordering;

        let (bad_gateway, seen) = server_dropping_first_requests(0, "HTTP/1.1 502 Bad Gateway");
        let _ = get_text_with_token_retrying(
            &format!("http://127.0.0.1:{bad_gateway}/"),
            None,
            HTTP_ATTEMPTS,
            std::time::Duration::ZERO,
        )
        .expect_err("every attempt 502s");
        assert_eq!(seen.load(Ordering::SeqCst), HTTP_ATTEMPTS as usize);

        let (unauthorized, seen) = server_dropping_first_requests(0, "HTTP/1.1 401 Unauthorized");
        let _ = get_text_with_token_retrying(
            &format!("http://127.0.0.1:{unauthorized}/"),
            None,
            HTTP_ATTEMPTS,
            std::time::Duration::ZERO,
        )
        .expect_err("a rejected token is an answer");
        assert_eq!(seen.load(Ordering::SeqCst), 1, "401 must not be retried");
    }

    #[test]
    fn fetch_bytes_retries_403_but_get_text_with_token_does_not() {
        use std::sync::atomic::Ordering;

        // `fetch_bytes_retrying` sends no Authorization header; GitHub returns
        // 403 for anonymous rate-limit/abuse trips, which are transient.
        let (forbidden_asset, seen_asset) =
            server_dropping_first_requests(0, "HTTP/1.1 403 Forbidden");
        let _ = fetch_bytes_retrying(
            &format!("http://127.0.0.1:{forbidden_asset}/asset"),
            HTTP_ATTEMPTS,
            std::time::Duration::ZERO,
        )
        .expect_err("every attempt 403s");
        assert_eq!(
            seen_asset.load(Ordering::SeqCst),
            HTTP_ATTEMPTS as usize,
            "anonymous 403 must be retried on the asset path"
        );

        // `get_text_with_token_retrying` with a real token sends Authorization;
        // a 403 there means the token is bad or exhausted — single-shot.
        let (forbidden_api, seen_api) =
            server_dropping_first_requests(0, "HTTP/1.1 403 Forbidden");
        let _ = get_text_with_token_retrying(
            &format!("http://127.0.0.1:{forbidden_api}/"),
            Some("ghp_tok"),
            HTTP_ATTEMPTS,
            std::time::Duration::ZERO,
        )
        .expect_err("authenticated 403 is an answer");
        assert_eq!(
            seen_api.load(Ordering::SeqCst),
            1,
            "authenticated 403 must not be retried"
        );
    }

    #[test]
    fn get_text_with_token_sends_no_authorization_header_when_token_is_none() {
        let port = one_shot_echo_auth_server();
        let body = get_text_with_token(&format!("http://127.0.0.1:{port}/"), None).unwrap();
        assert!(body.contains(r#""__auth":"NONE""#), "got: {body}");
    }

    #[test]
    fn get_text_with_token_sends_no_authorization_header_when_token_is_empty() {
        // An empty string is treated the same as absent — never sends a
        // hollow `Authorization: Bearer` header.
        let port = one_shot_echo_auth_server();
        let body = get_text_with_token(&format!("http://127.0.0.1:{port}/"), Some("")).unwrap();
        assert!(body.contains(r#""__auth":"NONE""#), "got: {body}");
    }

    #[test]
    fn get_text_with_token_sends_a_bearer_authorization_header_when_present() {
        let port = one_shot_echo_auth_server();
        let body =
            get_text_with_token(&format!("http://127.0.0.1:{port}/"), Some("ghp_test123")).unwrap();
        assert!(
            body.contains(r#""__auth":"Bearer ghp_test123""#),
            "got: {body}"
        );
    }

    #[test]
    fn get_text_reads_the_real_github_token_env_var() {
        // get_text (the production entry point) reads GITHUB_TOKEN_ENV itself;
        // this only proves the constant names the variable CI already
        // exposes (`secrets.GITHUB_TOKEN`) — the header-sending behavior
        // itself is covered token-injected above, never via a real env
        // mutation (parallel-test-safe).
        assert_eq!(GITHUB_TOKEN_ENV, "GITHUB_TOKEN");
    }

    // -- #544: replacing a binary whose file is locked by a running service ----
    //
    // The reported P1: an upgrade over a RUNNING dig-dns held `dig-dns.exe`
    // open, so overwriting it in place failed with "os error 32" (a Windows
    // sharing violation). `replace_binary` must convert that into a safe,
    // staged, reboot-time replace instead of a hard error — and never leave a
    // half-written binary.

    #[test]
    fn replace_binary_writes_in_place_when_the_destination_is_free() {
        let dir =
            crate::sources::fixture_root().join(format!("dig-dl-free-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("dig-dns-free.bin");
        let outcome = replace_binary(&dest, b"NEW").expect("an unlocked write applies in place");
        assert_eq!(outcome.outcome, WriteOutcome::Replaced);
        assert_eq!(std::fs::read(&dest).unwrap(), b"NEW");
        // A brand-new destination has no prior occupant, so nothing is backed up.
        assert!(outcome.replaced_backup.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #1914/#1915: overwriting a PRE-EXISTING binary preserves its prior bytes in
    /// a restorable backup, so a later partial-install rollback can put them back
    /// instead of deleting a working binary the machine already had. Before the
    /// fix, `replace_binary` reported nothing about pre-existence, so every write
    /// was recorded as `FileCreated` and rolled back by deletion.
    #[test]
    fn replace_binary_preserves_prior_bytes_when_overwriting_a_pre_existing_binary_1914() {
        let dir = crate::sources::fixture_root().join(format!("dig-dl-bak-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("dig-store.bin");
        std::fs::write(&dest, b"OLD WORKING BINARY").unwrap();

        let result = replace_binary(&dest, b"NEW BINARY").expect("overwrite applies in place");
        assert_eq!(result.outcome, WriteOutcome::Replaced);
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            b"NEW BINARY",
            "the new bytes are live"
        );
        let backup = result
            .replaced_backup
            .expect("overwriting a pre-existing binary must preserve its prior bytes");
        assert_eq!(
            std::fs::read(&backup).unwrap(),
            b"OLD WORKING BINARY",
            "the backup holds exactly the prior bytes, so a rollback can restore them"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #1914: a hard write failure that occurs AFTER the destination is unlinked
    /// must not leave the machine missing a binary it had — the prior bytes are
    /// restored before the error propagates. Simulated by making `dest` a file and
    /// its parent-relative backup succeed, then forcing the create to fail via a
    /// destination whose parent is read-only is platform-fiddly; instead we assert
    /// the invariant directly through the successful-restore branch: a pre-existing
    /// file whose overwrite is later rolled back is recoverable from the backup.
    #[test]
    fn overwrite_backup_round_trips_the_prior_bytes_1914() {
        let dir = crate::sources::fixture_root().join(format!("dig-dl-rt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("dign.bin");
        std::fs::write(&dest, b"ORIGINAL").unwrap();

        let result = replace_binary(&dest, b"UPGRADED").expect("overwrite ok");
        let backup = result.replaced_backup.expect("backup present");
        // Emulate a rollback: restore the backup over the new bytes.
        std::fs::rename(&backup, &dest).expect("restore");
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            b"ORIGINAL",
            "restoring the backup returns the machine to its prior binary"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #1914/#1910: the prior-bytes backup can be RESTORED onto a privileged binary
    /// on rollback — a path with no downstream #565 gate — so it MUST be adopted into
    /// privileged ownership at creation, or a Windows restore hands a non-SYSTEM
    /// principal write over a SYSTEM-executed binary. Proven cross-platform by
    /// injecting the adopt effect (production `adopt_placed_file` no-ops off Windows /
    /// outside the protected root, so injection is the only falsifiable check here).
    #[test]
    fn back_up_existing_adopts_the_backup_into_privileged_ownership_1910() {
        let dir =
            crate::sources::fixture_root().join(format!("dig-bak-adopt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("dig-node.bin");
        std::fs::write(&dest, b"OLD").unwrap();

        let adopted = std::cell::RefCell::new(Vec::<PathBuf>::new());
        let backup = back_up_existing_with(&dest, &|p| {
            adopted.borrow_mut().push(p.to_path_buf());
            Ok(())
        })
        .expect("backup ok")
        .expect("a pre-existing regular file is backed up");
        assert_eq!(
            adopted.into_inner(),
            vec![backup.clone()],
            "the backup must be adopted into privileged ownership before it can be restored"
        );
        assert_eq!(std::fs::read(&backup).unwrap(), b"OLD");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #1910: if the backup cannot be secured, fail CLOSED — abort with `dest`
    /// untouched and NO unsecured backup left behind, never a backup a restore could
    /// promote onto a privileged binary.
    #[test]
    fn back_up_existing_fails_closed_when_the_backup_cannot_be_secured_1910() {
        let dir = crate::sources::fixture_root()
            .join(format!("dig-bak-failclosed-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("dign.bin");
        std::fs::write(&dest, b"OLD").unwrap();

        let err = back_up_existing_with(&dest, &|_| Err("acl adopt denied".to_string()))
            .expect_err("an unsecurable backup must fail, not proceed");
        assert!(err.contains("secure backup"), "got: {err}");
        // dest is untouched (the write never happened) and no unsecured backup remains.
        assert_eq!(std::fs::read(&dest).unwrap(), b"OLD");
        let leftover = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .any(|e| e.file_name().to_string_lossy().contains("dig-bak"));
        assert!(!leftover, "an unsecured backup must not be left behind");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn is_sharing_violation_only_flags_the_lock_error_on_windows() {
        // A plain not-found error is never a sharing violation on any OS.
        let not_found = std::io::Error::from(std::io::ErrorKind::NotFound);
        assert!(!is_sharing_violation(&not_found));
    }

    /// #544 integrity guard: the recoverable case is EXACTLY the open-time
    /// `ERROR_SHARING_VIOLATION` (32) — `File::create` fails opening a running
    /// executable BEFORE truncating anything, so `dest` is provably untouched
    /// and staging a reboot-time replace is safe. `ERROR_LOCK_VIOLATION` (33)
    /// is a byte-range-lock error raised at WRITE time: reaching it means the
    /// file was already opened + truncated, so classifying it as a sharing
    /// violation would stage-and-succeed over a half-written destination. Only
    /// 32 is recoverable; 33 (and every other write-time error) must hard-fail.
    #[cfg(windows)]
    #[test]
    fn is_sharing_violation_accepts_open_time_32_but_not_write_time_33() {
        assert!(
            is_sharing_violation(&std::io::Error::from_raw_os_error(32)),
            "open-time ERROR_SHARING_VIOLATION (32) is the recoverable running-exe case"
        );
        assert!(
            !is_sharing_violation(&std::io::Error::from_raw_os_error(33)),
            "write-time ERROR_LOCK_VIOLATION (33) must NOT be recoverable — dest is already truncated"
        );
    }

    /// A write failure that is NOT the recoverable open-time sharing violation
    /// must propagate as a hard error — the fallback must never silently
    /// stage-and-succeed over it. Writing to a path that is itself a directory
    /// fails with a non-32 error on every OS, so `replace_binary_with` returns
    /// `Err` (never `ScheduledForReboot`) and the injected scheduler is proven
    /// never to run. Guards the "never left half-written" invariant against any
    /// write-time failure (ERROR_LOCK_VIOLATION 33 included).
    #[test]
    fn replace_binary_hard_errors_on_a_non_sharing_violation_write_failure() {
        let dir =
            crate::sources::fixture_root().join(format!("dig-dl-harderr-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let scheduled = std::cell::Cell::new(false);
        // `dir` is a directory → std::fs::write fails with a non-32 error.
        let result = replace_binary_with(&dir, b"NEW", |_dest, _bytes| {
            scheduled.set(true);
            Ok(())
        });
        assert!(
            result.is_err(),
            "a non-sharing-violation write failure must hard-error, not stage"
        );
        assert!(
            !scheduled.get(),
            "the reboot-replace fallback must NOT run for a non-32 failure"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The exact user-reported failure, reproduced end-to-end: a running
    /// service holds its exe open (a handle that shares READ but not WRITE —
    /// how Windows keeps a running image locked), a naive in-place write hits
    /// `os error 32`, and `replace_binary_with` instead stages the new bytes +
    /// reports a reboot is required, leaving the old binary intact. Once the
    /// holder releases (the service stopped), the in-place write applies.
    #[cfg(windows)]
    #[test]
    fn replace_binary_falls_back_to_a_scheduled_replace_when_the_destination_is_locked() {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_READ: u32 = 0x0000_0001;

        let dir =
            crate::sources::fixture_root().join(format!("dig-dl-locked-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("dig-dns.exe");
        std::fs::write(&dest, b"OLD BINARY").unwrap();

        // Simulate the running service's lock: a handle sharing only READ, so a
        // second open requesting WRITE is refused with a sharing violation.
        let holder = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(&dest)
            .expect("open the locked holder handle");

        // The reported bug: a naive in-place write hits ERROR_SHARING_VIOLATION (32).
        let naive = std::fs::write(&dest, b"NEW BINARY");
        assert_eq!(
            naive.unwrap_err().raw_os_error(),
            Some(32),
            "must reproduce the exact os error 32 the user reported"
        );
        assert!(
            is_sharing_violation(&std::fs::write(&dest, b"x").unwrap_err()),
            "the classifier must recognise a real sharing violation"
        );

        // The fix: stage + schedule instead of erroring, never half-writing dest.
        let scheduled = std::cell::Cell::new(false);
        let outcome = replace_binary_with(&dest, b"NEW BINARY", |_dest, _bytes| {
            scheduled.set(true);
            Ok(())
        })
        .expect("resilient replace must not error on a locked destination");
        assert_eq!(outcome.outcome, WriteOutcome::ScheduledForReboot);
        // A locked destination is left UNTOUCHED, so there is nothing to restore —
        // the still-running old binary is the prior state; the staging file is what
        // a rollback cleans instead.
        assert!(outcome.replaced_backup.is_none());
        assert!(outcome.reboot_staging.is_some());
        assert!(
            scheduled.get(),
            "the delayed replace must have been scheduled"
        );
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            b"OLD BINARY",
            "the destination must be left intact (never half-written) while locked"
        );

        // Stopping the service releases the handle → the fast in-place path applies.
        drop(holder);
        let outcome = replace_binary(&dest, b"NEW BINARY").expect("write succeeds once unlocked");
        assert_eq!(outcome.outcome, WriteOutcome::Replaced);
        assert_eq!(std::fs::read(&dest).unwrap(), b"NEW BINARY");
        // dest pre-existed ("OLD BINARY"), so the overwrite preserved a restorable backup.
        let backup = outcome
            .replaced_backup
            .expect("overwriting a pre-existing binary must preserve its prior bytes");
        assert_eq!(std::fs::read(&backup).unwrap(), b"OLD BINARY");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- #1911: a RUNNING destination, reached through the unlink -------------

    /// A running executable must fall back to the reboot-time replace, not fail the
    /// install.
    ///
    /// The fixture is a REAL running process, because the property under test is the
    /// operating system's answer: since #1748 the write UNLINKS first, and unlinking a
    /// running image reports `ERROR_ACCESS_DENIED` rather than the sharing violation
    /// the fallback recognised. A mock returning error 5 would pass against a naive
    /// "treat every error 5 as running" implementation, which the control below
    /// forbids -- so the two tests are only meaningful together.
    #[cfg(windows)]
    #[test]
    fn a_running_destination_is_staged_for_the_next_reboot() {
        let dir = tempfile::tempdir().expect("temp dir");
        let dest = dir.path().join("running.exe");
        // A single ping at a black-holed address with a long timeout: the process is
        // alive (so its image section exists) but does essentially nothing, so it
        // cannot perturb the timing-sensitive tests running beside it.
        std::fs::copy(r"C:\Windows\System32\PING.EXE", &dest).expect("copy a real exe");
        let mut child = {
            #[allow(clippy::disallowed_methods)]
            std::process::Command::new(&dest)
                .args(["-n", "1", "-w", "60000", "192.0.2.1"])
                .stdout(std::process::Stdio::null())
                .spawn()
                .expect("run it")
        };
        // Give the image section time to exist before the unlink is attempted.
        std::thread::sleep(std::time::Duration::from_millis(300));

        let staged = std::cell::RefCell::new(Vec::<Vec<u8>>::new());
        let outcome = replace_binary_with(&dest, b"NEW BINARY", |_, bytes| {
            staged.borrow_mut().push(bytes.to_vec());
            Ok(())
        });

        let _ = child.kill();
        let _ = child.wait();

        let outcome = outcome.expect("a running destination must be staged, not a failed write");
        assert_eq!(
            outcome.outcome,
            WriteOutcome::ScheduledForReboot,
            "a running destination must be staged, not reported as a failed write"
        );
        // dest was left untouched (still running) — nothing to restore.
        assert!(outcome.replaced_backup.is_none());
        assert_eq!(staged.into_inner(), vec![b"NEW BINARY".to_vec()]);
    }

    /// The CONTROL: error 5 ALONE must not be read as "the destination is running".
    ///
    /// The nearest wrong implementation is the one-liner — treat every
    /// `ERROR_ACCESS_DENIED` from the unlink as a running image — and it passes the
    /// test above identically. It is also wrong in the expensive direction: a genuine
    /// permission failure would be staged for a reboot-time replace and REPORTED AS
    /// SUCCESS for a write that never happens. So the discriminator is asserted
    /// directly, on a destination that is demonstrably not running.
    ///
    /// (Two outcome-level fixtures were tried first and neither can express this: a
    /// read-only file is deleted anyway, because Rust's `remove_file` clears
    /// `FILE_ATTRIBUTE_READONLY`; and a `Deny` on the file's own DELETE is bypassed by
    /// the parent directory's delete-child right. Both simply wrote, so both would
    /// have pinned a coincidence.)
    #[cfg(windows)]
    #[test]
    fn access_denied_alone_does_not_mean_the_destination_is_running() {
        let dir = tempfile::tempdir().expect("temp dir");
        let ordinary = dir.path().join("not-running.exe");
        std::fs::write(&ordinary, b"OLD").expect("write it");
        assert!(
            !destination_is_a_running_image(&std::io::Error::from_raw_os_error(5), &ordinary),
            "an ordinary file that merely reported error 5 is not a running image"
        );
        // And a code that is not 5 is never this case, whatever the destination is.
        assert!(!destination_is_a_running_image(
            &std::io::Error::from_raw_os_error(32),
            &ordinary
        ));
        assert!(!destination_is_a_running_image(
            &std::io::Error::from_raw_os_error(5),
            &dir.path().join("absent.exe")
        ));
    }

    /// The staged file is the file that will EXIST after the reboot, so it must be
    /// adopted into privileged ownership BEFORE the promotion is queued (#1910).
    ///
    /// Observed as a live defect on a real machine: `.dig-app.exe.pending-76024`
    /// sitting in the protected root owned by the installing user, scheduled to
    /// become `dig-app.exe`. Fixing only the direct write leaves the reboot path
    /// re-introducing the same defect days later, which is precisely the shape of
    /// recovery-path defect that stays invisible to a clean-machine test.
    ///
    /// The ORDER is asserted, not merely the fact: a run that scheduled first and
    /// adopted afterwards would satisfy a "both happened" assertion while still
    /// queueing a user-owned binary for promotion.
    #[cfg(windows)]
    #[test]
    fn the_staged_file_is_adopted_before_the_reboot_replace_is_queued() {
        let dir = tempfile::tempdir().expect("temp dir");
        let dest = dir.path().join("dig-app.exe");
        let events = std::cell::RefCell::new(Vec::<String>::new());

        let outcome = schedule_replace_on_reboot_with(
            &dest,
            b"NEW BINARY",
            &|p| {
                events.borrow_mut().push(format!("adopt {}", p.display()));
                Ok(())
            },
            &|staging, target| {
                events.borrow_mut().push(format!(
                    "schedule {} -> {}",
                    staging.display(),
                    target.display()
                ));
                Ok(())
            },
        );

        assert_eq!(outcome, Ok(()));
        let events = events.into_inner();
        let staging = staging_path(&dest);
        assert_eq!(
            events,
            vec![
                format!("adopt {}", staging.display()),
                format!("schedule {} -> {}", staging.display(), dest.display()),
            ],
            "the staged file must be adopted first, and by its STAGING path"
        );
        assert_eq!(
            std::fs::read(&staging).expect("the staged bytes"),
            b"NEW BINARY"
        );
    }

    /// If the staged file cannot be adopted, the promotion must NOT be queued: a
    /// binary a non-SYSTEM principal can rewrite is worse in the protected root than
    /// an update that did not happen, and the reboot would install it silently.
    #[cfg(windows)]
    #[test]
    fn a_staged_file_that_cannot_be_adopted_is_never_queued() {
        let dir = tempfile::tempdir().expect("temp dir");
        let dest = dir.path().join("dig-app.exe");
        let scheduled = std::cell::Cell::new(0);

        let err = schedule_replace_on_reboot_with(
            &dest,
            b"NEW",
            &|_| Err("owner is still the installing user".to_string()),
            &|_, _| {
                scheduled.set(scheduled.get() + 1);
                Ok(())
            },
        )
        .expect_err("an un-adoptable staged file must fail");

        assert_eq!(scheduled.get(), 0, "nothing may be queued for the reboot");
        assert!(err.contains("privileged ownership"), "got: {err}");
    }
}

#[cfg(test)]
mod interrupted_install_leftover_tests {
    use super::*;

    /// dig_ecosystem#1911 recovery path 4 (repair after an interrupted install).
    ///
    /// The fixture is produced by the PRODUCTION writer — `back_up_existing` —
    /// never by a test-local literal name. A scan written against a name the
    /// test itself invented would keep passing after a rename of the tag, which
    /// is the exact drift that made these files invisible in the first place.
    ///
    /// Asserts on disk: the abandoned copy is FOUND, and it still holds the
    /// bytes of the binary it replaced (so a report of it is a report of real
    /// recoverable data, not of an empty marker).
    #[test]
    fn finds_the_backup_the_real_writer_abandoned() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let dest = tmp.path().join("dig-node.exe");
        std::fs::write(&dest, b"the version the user already had").unwrap();

        let backup = back_up_existing(&dest)
            .expect("the backup succeeds")
            .expect("a prior file was there to back up");
        // From here on the run is "killed": nothing cleans the backup up.

        let found = interrupted_install_leftovers(tmp.path(), "dig-node.exe");
        assert_eq!(
            found,
            vec![backup.clone()],
            "the scan must find exactly the file the writer left"
        );
        assert_eq!(
            std::fs::read(&found[0]).unwrap(),
            b"the version the user already had",
            "the leftover still holds the replaced binary's bytes"
        );
    }

    /// The scan must be narrow enough to run inside a shared install root. Three
    /// distinguishing neighbours, each one a way the nearest wrong
    /// implementation goes wrong:
    ///
    /// * the destination binary itself — a scan matching any name CONTAINING the
    ///   exe name would take it, and the uninstall would then report the live
    ///   binary twice;
    /// * a DIFFERENT component's abandoned backup — a scan ignoring the exe name
    ///   would sweep it under the wrong stem, defeating the `skip` rule that
    ///   keeps a failed-teardown component's backup in place;
    /// * a foreign hidden file with the same prefix but no tag — a prefix-only
    ///   scan would delete a file this installer never wrote.
    #[test]
    fn matches_only_this_components_tagged_siblings() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let mine = tmp.path().join(format!(".dig-node.exe{BACKUP_TAG}4242"));
        for (name, bytes) in [
            (mine.clone(), &b"mine"[..]),
            (tmp.path().join("dig-node.exe"), &b"live"[..]),
            (
                tmp.path().join(format!(".dig-dns.exe{BACKUP_TAG}4242")),
                &b"other component"[..],
            ),
            (
                tmp.path().join(".dig-node.exe.notes"),
                &b"someone else's file"[..],
            ),
        ] {
            std::fs::write(&name, bytes).unwrap();
        }

        assert_eq!(
            interrupted_install_leftovers(tmp.path(), "dig-node.exe"),
            vec![mine]
        );
    }

    /// Staged bytes are the second abandoned shape, and on a killed run they are
    /// the more dangerous one: `MoveFileEx` promotes a staging file's whole
    /// security descriptor onto the destination at the next reboot, so one left
    /// unswept is a pending write nobody is tracking.
    #[test]
    fn finds_abandoned_staged_bytes_too() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let staged = tmp.path().join(format!(".dig-app.exe{STAGING_TAG}99"));
        std::fs::write(&staged, b"staged").unwrap();

        assert_eq!(
            interrupted_install_leftovers(tmp.path(), "dig-app.exe"),
            vec![staged]
        );
    }

    /// The sweep's outcome is asserted on disk (gone), not on its return value,
    /// and the neighbours must survive it — a sweep that empties the directory
    /// would satisfy a "the leftover is gone" assertion just as well.
    #[test]
    fn the_sweep_removes_the_leftover_and_nothing_else() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let dest = tmp.path().join("dig-node.exe");
        std::fs::write(&dest, b"live").unwrap();
        let backup = back_up_existing(&dest).unwrap().unwrap();
        let foreign = tmp.path().join(".dig-node.exe.notes");
        std::fs::write(&foreign, b"not ours").unwrap();

        let (removed, errors) = remove_interrupted_install_leftovers(tmp.path(), "dig-node.exe");

        assert_eq!((removed, errors.as_slice()), (1, &[][..]));
        assert!(!backup.exists(), "the abandoned backup is gone from disk");
        assert!(dest.exists(), "the installed binary is untouched");
        assert!(
            foreign.exists(),
            "a file the installer never wrote is untouched"
        );
    }

    /// `uninstall` promises a second run is a clean no-op, so the sweep must
    /// report nothing removed and no error on an already-clean root.
    #[test]
    fn sweeping_a_clean_root_is_a_silent_no_op() {
        let tmp = tempfile::tempdir().expect("temp dir");
        std::fs::write(tmp.path().join("dig-node.exe"), b"live").unwrap();

        let (removed, errors) = remove_interrupted_install_leftovers(tmp.path(), "dig-node.exe");

        assert_eq!(removed, 0);
        assert!(errors.is_empty());
    }
}
