# Changelog

This changelog starts on 2026-08-18. Earlier changes weren't tracked in this
repo, so the first entry below is a catch-up covering everything since the
previous public update. Per-release entries begin from here.

## v0.13.0 — 2026-10-04

### Security — self-hosters should upgrade
- A game's API key is now revoked when the game is permanently removed, and registering a game revokes any key left over from an earlier game with the same ID. Previously the key outlived the game, so a re-registered game ID inherited the previous registration's key. Soft-deleted games keep their key, so recovering a game inside the 30-day window restores a working key.
- `validateApiKeyQuery` is now verifier-only. It was a public query that confirmed whether a key was real and which game it belonged to.
- Profiles can no longer be looked up from a bare email address by a direct caller. `getUserProfile` no longer accepts the `email` type at all, and the `email` type on `getGameProfile`, `getPlayerScoreboardRank`, `getPlayerRank`, `getAchievements` and `getPlayerAnalytics` is verifier-only. The `session`, `principal` and `external` types are unchanged.
- Session-token queries now reject expired sessions. `getGameOAuthConfigBySession`, `getDeveloperTierBySession`, `getRemainingGameSlotsBySession`, `getApiKeyBySession`, `hasApiKeyBySession`, `getSessionInfo`, `getGamesBySession`, `getSuspicionLogBySession`, `getDeletedGamesBySession`, `getRemainingDeleteAttemptsBySession` and the `session` type of `getPlayerScoreboardRank` previously read the session without checking its expiry.

### Added
- Admin command `sweepOrphanApiKeys` (super admin, via `adminGate`): reports active API keys, engine tags and websites whose game no longer exists. Pass `confirm` to revoke and clear them. Report-only by default, and safe to run more than once.

### Changed
- Permanently removing a game also clears its engine tag and website.
- The registration success message now lists all three default scoreboards: `all-time`, `weekly`, `daily`.

### Notes for self-hosters
- No Candid interface changes and no migration: a single normal upgrade, with no dfx prompt expected.
- Your proxy must make its **query** calls signed as the verifier identity too, not only its updates. A proxy that calls `validateApiKeyQuery` anonymously will see every API key as invalid after this upgrade.
- After upgrading, run `adminGate("sweepOrphanApiKeys", [])` to see how many keys were left behind by deleted games, then again with `["confirm"]` to revoke them.
- If your proxy looks players up with the `email` type on the queries above, it still works when signed as the verifier. Direct or anonymous callers must use `session` or `external`.

## v0.12.0 — 2026-10-04

### Added
- Engine tag per game: `setGameEngine` / `setGameEngineBySession` (game owner only) and public queries `getGameEngine` / `getGameEngines`. Accepted values are `godot4`, `godot3`, `unity`, `rest` and `other`; an empty value clears the tag.
- Website URL per game, separate from the play link in `gameUrl`: `setGameWebsite` / `setGameWebsiteBySession` (game owner only) and public queries `getGameWebsite` / `getGameWebsites`. Same validation as `gameUrl`; an empty value clears it.
- Optional developer contact email: `setDeveloperContact` / `setDeveloperContactBySession`, readable by its owner through `getMyDeveloperContact` / `getMyDeveloperContactBySession` and by admins through `getDeveloperContact`. It is never exposed by a public query.
- `maxLiveBytes` in `memStats` and `GET /metrics`: the largest live heap the runtime has seen.

### Changed
- `gameUrl` is now validated on all four write paths (both register and both update methods). It must start with `https://`, be at most 200 characters, and contain no spaces, quotes, angle brackets or control characters. Leading and trailing whitespace is trimmed and an empty value clears the URL. Invalid values are rejected with an error; values stored before this release are left as they are until the next edit.
- Expired play sessions are now swept globally whenever the session map passes 500 entries. Previously a player's stale sessions were only cleared when that same player started another session, so one-off players left sessions behind indefinitely.
- `registerGame` (principal path) now uses the developer's tier limit for game slots, matching `registerGameBySession`, instead of a flat limit.
- The error returned when a game with time validation on receives a score without a play session now tells the caller what to do (SDK: `start_play_session()`, REST: `POST /play-sessions/start`) instead of naming an internal method.

### Fixed
- Deleting a scoreboard now also purges that board's archived periods, on both the principal and session paths. Previously the archives were left behind.
- The admin `removeUser` command now also removes that user's login sessions.

### Removed
- `submitScoreToScoreboard`, the legacy targeted-submit method. `submitScoreToBoard` replaces it; the legacy method also never counted towards the submission total.

### Notes for self-hosters
- This release removes one Candid method, so dfx will prompt about a breaking interface change on upgrade and should name only `submitScoreToScoreboard`. Expected; confirm it. If your proxy or any client still calls that method, move it to `submitScoreToBoard` first.
- Single deploy, no migration. The engine, website and contact maps are new stable fields, which EOP accepts on a normal upgrade.
- If you parse the session-required error string, note the new wording.
- Take a snapshot before upgrading and keep one at a time (`dfx canister snapshot create --replace`).

## v0.11.0 — 2026-09-30

### Removed
- The Files module has been removed: `files.mo`, the `stableFiles` stable field, the transient file list and its pre/postupgrade copies, and all 7 public file methods (including `uploadFile` and `deleteFile`). It was unused (0 files stored) and only added interface and attack surface.
- `getSystemInfo` no longer returns `fileCount`.

### Added
- `memStats` query: reports cycles balance, memory usage and internal map sizes, for capacity monitoring.
- `GET /metrics` on the raw domain, served directly by the canister: the same capacity figures as JSON, with warning flags when cycles fall under 5T or memory goes over 1.5 GB.

### Notes for self-hosters
- This release removes Candid methods, so dfx will prompt about a breaking interface change on upgrade. Expected; confirm it. Update any client that calls the file methods or reads `fileCount`.
- **Existing canisters need a two-step upgrade.** EOP will not implicitly drop a stable field (error M0169). First deploy tag `v0.11.0-migration`, which includes a one-shot `migration.mo` applied via `(with migration = Migration.run)` to drop `stableFiles`, then deploy `v0.11.0`, which retires the migration. Deploying `v0.11.0` directly onto a v0.10.0 canister will be rejected. Fresh installs can go straight to `v0.11.0`.
- Take a snapshot before upgrading. Each snapshot is a full copy of the heap, so keep one at a time (`dfx canister snapshot create --replace`) to avoid paying cycles for stale copies.

## v0.10.0 — 2026-09-26

### Security
- External (API-key) player writes are now accepted only from the verifier principal. Score submits, targeted board submits, achievement unlocks and nickname changes on the `external` path can no longer be made by calling the canister directly.
- Proxy-only entry points now require the verifier: `migrateAnonymousAccount`, `startGameSessionByApiKey`, `cancelPlaySession`.
- `getSessionInfo`, `trackEvent` and `validateApiKey` are now verifier-only.
- `getRecentEvents` is now admin-only; analytics events carry player identifiers and should never have been public.
- Session tokens, play-session tokens and API keys are now generated from `raw_rand` (IC randomness) instead of timestamps and counters. Existing sessions and keys remain valid.

### Fixed
- Sessions now survive canister upgrades. `postupgrade` was restoring sessions from a transient variable, so every upgrade signed out all signed-in players and developers.

### Notes for self-hosters
- **Your proxy must make every canister call signed as the verifier identity**, including external score submits. A proxy that calls anonymously for writes will get `Unauthorized` after this upgrade.
- New token formats: sessions are `session_` + 64 hex characters, play tokens `ps_<gameId>_` + 32 hex, API keys `cb_<gameId>_` + 32 hex. Anything that parses the old numeric formats should be updated.
- No Candid interface changes.

## v0.9.0 — 2026-09-24

### Security
- Verifier gate collapsed to a single verifier principal; the previous key is no longer accepted.

### Changed
- Moved from legacy persistence to enhanced orthogonal persistence (EOP).
  **Self-hosters upgrading an existing canister:** this is a one-way switch. Take a snapshot first; dfx.json now builds with `--enhanced-orthogonal-persistence`.
- Game ID validation on the principal registration path; name/description length caps; stats fixes for category-board submits; play-count de-duplication.

### Added
- HTTP board reads served directly by the canister: `GET /games/{gameId}/scoreboards/{boardId}?limit=N` on the raw domain, same JSON as the API, CORS-open.
- Deleted board IDs can be reused; the recreated board starts with a clean archive history.
- Expired soft-deleted games are now swept on dashboard deletes too.

## v0.8.1 — 2026-08-29

Sync of the public repo to production. From this release the public repo is
updated via a git-tracked mirror of the private source, one commit per release.

### Changed

- Sessions now last 30 days with sliding renewal on every validated use,
  replacing the fixed 24-hour TTL. Linked players were silently dropping off
  boards a day after signing in because expired sessions rejected submits
  server-side while clients still showed them as logged in.
- Game name capped at 50 characters and description at 200; over-length values
  are clamped on write, not rejected, so existing games keep working.
- `registerGame` (principal path) now enforces the same game-ID rule as
  `registerGameBySession`: lowercase letters, digits, hyphens, 3–50 characters.
  Existing IDs that predate the rule are grandfathered.
- `dfx.json` now published as used for real builds, including
  `--legacy-persistence`: the live canister still runs classical persistence.
  Migration to enhanced orthogonal persistence is planned.

### Fixed

- Gate error on `socialLoginAndGetProfile` no longer echoes the expected
  verifier principal.

### Security

- Score, streak, and play-time validation failures now return a generic
  "rejected by game validation rules" message to clients. Previously the
  error echoed the configured cap or minimum duration, which let anyone
  binary-search a game's limits. Full detail, including actual play duration,
  is still logged owner-side in the suspicion log.

### Added

- `unlockAchievementBatch`: unlock many achievements for a player in a single
  update call, returning per-ID outcomes. Replaces per-achievement calls that
  timed out on large batches.

### Docs

- README: device-code login is implemented in the proxy layer, not the
  canister. Removed reference to `anonymousLoginAndGetProfile`; documented the
  account-linking migration functions.

## v0.8.0 — 2026-08-18

### Security — self-hosters should upgrade

- `socialLoginAndGetProfile` is now gated on the verifier principal. Previously
  it could be called directly on the canister, bypassing OAuth token
  verification entirely. If you run your own instance, upgrade to this version
  and set `VERIFIER_PRINCIPAL` to your own verifier's signing principal (see
  README). Until you do, treat OAuth-based sessions on older deployments as
  untrusted.
- The verifier principal is now single-sourced (`VERIFIER_PRINCIPAL`) and
  force-reassigned in `postupgrade()`. This matters because the actor is
  `persistent`: top-level variables are implicitly stable and survive upgrades,
  so editing a literal alone does not change the running value. The same
  applies to `CONTROLLER` — set it before your first deploy.

### Added

- Moderation endpoints for game owners: view a board in admin mode, delete a
  single score entry, or wipe a player's scores across all of a game's boards
  (optionally including archives). Available in both session-auth and
  principal-auth variants.
- Deletion audit log (`getEntryDeletionLog`): capped, stable record of every
  moderation action. Player identifiers are stored as hashes, never raw
  emails or principals.
- Submission stats: `getSubmissionStats` and `getSystemInfo` now expose the
  running submission total; `getSystemInfo` game count now reflects active
  games only.

### Fixed

- Nickname validation unified to a single rule (3–16 characters, restricted
  charset) across registration and score-submission paths. Previously
  different entry points enforced different lengths. Existing out-of-range
  nicknames are grandfathered; the rule is enforced on write only.
- Deleted games no longer linger: soft-deleted games are now filtered from
  all owner-facing game lists, and expired soft-deletes are actually purged
  (cleanup previously never ran and left records behind, inflating counts).
- Score wipes reset the player's per-game profile (score, streak, play count)
  while leaving achievements intact, and touched boards bust their caches so
  clients see the change promptly.

### Changed

- Moderation read endpoints are query calls (faster, no consensus round).
- Unauthorized calls to gated auth methods return a plain error message.