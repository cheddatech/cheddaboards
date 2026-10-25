# Changelog

All notable changes to the CheddaBoards Godot 4 SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This repo is the standalone home of the SDK from v2.2.5 onwards. History for v2.2.4 and earlier lives in the [cheddaboards-godot changelog](https://github.com/cheddatech/CheddaBoards-Godot/blob/main/docs/CHANGELOG.md), where the SDK previously shipped as part of the full template.

## [2.2.5] - 2026-09-01

### Leaderboards, Direct from the Canister

Backwards-compatible release. Leaderboard reads now come straight from the CheddaBoards canister over the IC HTTP gateway instead of routing through the API proxy — noticeably faster board loads with no cold-start lag, and an automatic proxy fallback so nothing gets less reliable. Also hardens the SDK's internal request dispatch against a rare race. No breaking changes, no migration required.

### Added

**Direct Canister Reads (`CheddaBoards.gd`)**

- `get_scoreboard()` — and the `get_weekly_leaderboard()` / `get_daily_leaderboard()` / `get_alltime_leaderboard()` / `get_monthly_leaderboard()` helpers built on it — now fetches straight from the CheddaBoards canister (`fdvph-sqaaa-aaaap-qqc4a-cai.raw.icp0.io`), skipping the proxy hop entirely
- The response is byte-for-byte the same shape as the proxy's, so existing `scoreboard_loaded` handlers work unchanged — same JSON, same signals, same everything from your game code's point of view
- Direct reads are keyless and header-free: public board data only, no API key travels on this path, and web exports stay CORS-simple with no preflight
- Writes, ranks, archive readers (`get_scoreboard_archives()`, `get_last_archived_scoreboard()`, `get_last_week_scoreboard()`, and friends), and all authenticated calls stay on the proxy unchanged

**Automatic Proxy Fallback**

- If a direct read can't get through — a network that filters `raw.icp0.io`, a gateway hiccup, a non-JSON gateway error page — the SDK silently retries the identical request via the proxy
- After three consecutive direct failures, the SDK stops trying direct for the rest of the session, so affected players pay the detour cost at most three times and then behave exactly like v2.2.4
- One direct success resets the failure count
- A genuine `"Scoreboard not found"` from the canister is treated as the real answer, not retried — the canister is the source of truth

### Fixed

**Request Dispatch Race**

- Internal retries now route through the SDK's request queue instead of grabbing the `HTTPRequest` node directly, `_process_next_request()` guards against double-dispatch, and a busy node requeues the request for the next idle frame instead of dropping it with an error
- Fixes rare `HTTPRequest is processing a request` errors (and silently lost requests) when completions and queued requests landed in the same frame
