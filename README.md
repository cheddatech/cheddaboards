<p align="center">
  <img src="docs/cheddaboards_logo.png" alt="CheddaBoards" width="420">
</p>

**The open-source backend behind [cheddaboards.com](https://cheddaboards.com). Use the hosted service, or run your own.**

Leaderboards, achievements, player accounts, anti-cheat and moderation for games, running as a single canister on the Internet Computer.

[![Website](https://img.shields.io/badge/website-cheddaboards.com-blue)](https://cheddaboards.com)
[![Docs](https://img.shields.io/badge/docs-docs.cheddaboards.com-blue)](https://docs.cheddaboards.com)
[![Status](https://img.shields.io/badge/status-status.cheddatech.com-brightgreen)](https://status.cheddatech.com)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## What's in this repo

This is the **backend canister**: the on-chain logic and storage behind every CheddaBoards game.

| Path | What it is |
|------|------------|
| `src/cheddaboards_v2_backend/main.mo` | The canister actor: games, scoreboards, sessions, achievements, anti-cheat, moderation, admin |
| `src/cheddaboards_v2_backend/` (`types`, `apikeys`, `players`, `scoreboards`) | Supporting Motoko modules imported by `main.mo` |
| `dfx.json` | Build config, as used for the production canister |
| `CHANGELOG.md` | Per-release notes, including upgrade notes for self-hosters |

The Candid interface is generated from the source when you build (`dfx generate`).

This public repo is a mirror of the private source, published one commit per release, so it can trail the live canister by a release.

**Not in this repo:**

| Looking for | Go to |
|-------------|-------|
| Documentation, quick starts, REST reference | [docs.cheddaboards.com](https://docs.cheddaboards.com) |
| Godot 4 add-on (4.3+) | [cheddaboards-godot-addon](https://github.com/cheddatech/cheddaboards-godot-addon), also on the [Godot Asset Store](https://store.godotengine.org/asset/cheddatech/cheddaboards) |
| Godot 4 full game template | [CheddaBoards-Godot](https://github.com/cheddatech/CheddaBoards-Godot), also on the [Godot Asset Store](https://store.godotengine.org/asset/cheddatech/cheddaboards-template) |
| Godot 3.6 add-on | [cheddaboards-godot3-addon](https://github.com/cheddatech/cheddaboards-godot3-addon) |
| Unity SDK | [CheddaBoards-Unity](https://github.com/cheddatech/CheddaBoards-Unity) |
| A worked example | [Dodge the Creeps × CheddaBoards](https://github.com/cheddatech/cheddaboards-dodge-the-creeps) ([play it](https://cheddagames.itch.io/dodge-the-creeps-x-cheddaboards)) |
| Service status | [status.cheddatech.com](https://status.cheddatech.com) |

Every SDK talks to the same REST API, so anything that can make an HTTP request works too: Unreal, GameMaker, Bevy, native mobile, web, or your own engine.

---

## Architecture

<img src="docs/architecture.svg" alt="Game → REST proxy (verifier) → ICP canister. The proxy verifies OAuth tokens and API keys and signs canister calls; only the verifier principal can mint sessions or write scores for API-key players. The canister is this repo; self-hosters build their own proxy." width="100%">

Games talk plain HTTPS to a thin REST proxy. The proxy checks the game's API key or the player's sign-in, then calls the canister using its own signing identity, the **verifier**. The canister stores everything and enforces the rules.

The trust model, in short:

- **Writes go through the verifier.** Sign-in, session minting, and every score, achievement and nickname change for API-key players are accepted only from the verifier principal. Calling the canister directly for these returns `Unauthorized`.
- **Signed-in developers and players act through sessions.** A session token is checked by the canister on every call, lasts 30 days, and renews on use.
- **Board reads are public and can skip the proxy.** The canister serves scoreboards over HTTP itself (see [Direct HTTP reads](#direct-http-reads)).
- **Lookups that could leak information are closed.** API key validation and lookups by email address are verifier-only.

The hosted proxy at cheddaboards.com is not in this repo. Self-hosters build their own against the Candid interface (see [Self-hosting](#self-hosting)).

---

## Features

- **Leaderboards**: server-validated scores, with all-time, weekly and daily boards created for every game
- **Timed scoreboards**: daily, weekly, monthly and custom-interval boards that reset on calendar boundaries and archive each period
- **Category scoreboards**: per-level, per-mode or per-category boards you submit to by ID, without registering a separate game for each
- **Player accounts**: anonymous players identified by device under the game's API key, plus Google, Apple and Internet Identity sign-in. Device-code login for linking a game client to an account is implemented in the hosted proxy, not in the canister
- **Account linking**: an anonymous profile merges into a signed-in account without losing progress. Scores and streaks merge by maximum, achievements are combined, play counts are summed
- **Cross-game profiles**: a signed-in player keeps one identity across every CheddaBoards game
- **Achievements**: per-player unlocks, with a batch call for unlocking many at once
- **Anti-cheat**: per-player rate limiting, per-round and absolute score caps, optional play-session time validation, and a suspicion log the game owner can read
- **Moderation**: game owners can delete a single score entry or wipe a player from their boards, with a capped audit log that stores player identifiers as hashes
- **Game metadata**: play URL, website, engine tag and an optional developer contact email
- **API keys**: one key per game, generated from IC randomness, revoked automatically when a game is removed
- **Per-game OAuth**: developers can register their own Google and Apple credentials
- **Safe deletion**: deleted games can be recovered for 30 days before they are removed for good
- **Operations**: a `memStats` query and a `GET /metrics` endpoint for capacity monitoring, and an admin command set for support and recovery

---

## Using the hosted service

You don't need to run anything. Register a game at [cheddaboards.com/developers](https://cheddaboards.com/developers), copy its API key, and submit a score:

```bash
curl -X POST https://api.cheddaboards.com/scores \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "X-Game-ID: your-game-id" \
  -d '{"playerId":"player_123","gameId":"your-game-id","score":1200,"streak":3}'
```

The hosted service is free: 3 game slots to start (more on request from the dashboard), unlimited players, no per-player fees.

For Godot and Unity, use an SDK from the table above. Setup guides, the REST reference and error codes are at [docs.cheddaboards.com](https://docs.cheddaboards.com). AI coding assistants can start from [docs.cheddaboards.com/llms.txt](https://docs.cheddaboards.com/llms.txt).

---

## Self-hosting

The canister is fully open source and you can run your own instance. It is more assembly than a one-click template: you deploy the canister, then build a small API layer in front of it. The [self-hosting guide](https://docs.cheddaboards.com/self-hosting/overview) covers the proxy side in more detail.

### Prerequisites

- [dfx](https://internetcomputer.org/docs/current/developer-docs/setup/install/) (the IC SDK). Production is built with dfx 0.32.0
- Cycles to run a canister on mainnet
- Basic familiarity with Motoko and the Internet Computer

### 1. Clone

```bash
git clone https://github.com/cheddatech/CheddaBoards.git
cd CheddaBoards
```

### 2. Configure principals

Open `src/cheddaboards_v2_backend/main.mo` and replace the placeholder principals (`aaaaa-aa`) with your own:

```motoko
// Your proxy's signing identity: the only principal allowed to make
// privileged calls. REPLACE with your own.
private transient let VERIFIER_PRINCIPAL : Text = "aaaaa-aa";

// Super admin (your dfx identity). REPLACE with your own.
private var CONTROLLER : Principal = Principal.fromText("aaaaa-aa");

// Bootstrap admin in postupgrade() (can be the same as controller). REPLACE.
let firstAdmin = Principal.fromText("aaaaa-aa");
```

Get your principal with `dfx identity get-principal`. A quick check before any deploy: `grep -n "aaaaa-aa" src/cheddaboards_v2_backend/main.mo` should print nothing.

> ⚠️ **Set these before your first deploy.** The actor is `persistent`, so
> top-level variables are stable and survive upgrades. Editing a literal
> afterwards does not change the running value. `VERIFIER_PRINCIPAL` is
> re-applied in `postupgrade()`, so it can be rotated by upgrading.
> `CONTROLLER` is not, so get it right the first time.

### 3. Deploy

```bash
# Local testing
dfx start --background
dfx deploy

# Mainnet, first install
dfx deploy --network ic
```

The canister uses enhanced orthogonal persistence (`--enhanced-orthogonal-persistence` in `dfx.json`).

### 4. Upgrade safely

```bash
dfx canister --network ic stop cheddaboards_v2_backend
dfx canister --network ic snapshot create cheddaboards_v2_backend
dfx canister --network ic start cheddaboards_v2_backend
dfx deploy cheddaboards_v2_backend --network ic --mode upgrade --wasm-memory-persistence keep
```

- **Read the changelog first.** Each release in [CHANGELOG.md](CHANGELOG.md) has notes for self-hosters. Some upgrades need two steps, and removing a stable field needs a one-shot migration.
- **Snapshot before every upgrade.** It is your only rollback. Each snapshot is a full copy of the heap and counts towards memory and cycle burn, so keep one at a time (`snapshot create --replace <id>`) and delete it once the upgrade is proven.
- **Check the module hash afterwards.** `dfx canister --network ic info <name>` should match the `shasum -a 256` of the wasm you built.

### 5. Build your proxy

Generate the Candid bindings your proxy will call:

```bash
dfx generate cheddaboards_v2_backend
```

Your API layer translates HTTP requests into canister calls. It needs:

- **A signing identity** (for example an Ed25519 keypair) whose principal you set as `VERIFIER_PRINCIPAL`. Keep the private key secret: it can mint sessions for any user and write scores for any game
- **To sign every canister call as that identity, queries included.** External score submits, achievement unlocks, play-session starts and API key lookups are all rejected or return nothing for any other caller
- **To validate each game's API key itself**, through `validateApiKeyQuery`, on every request. The canister trusts the proxy to have done this for API-key players, so never accept a key without asking the canister
- **To verify OAuth tokens itself** (for example via JWKS) before calling `socialLoginAndGetProfile`
- **Rate limiting**, since the canister only applies a per-player submit throttle
- **Your canister ID and an IC host** (`https://icp-api.io`, or `http://127.0.0.1:4943` for local dfx)
- **OAuth client IDs** for the providers you support
- **Allowed CORS origins** for the domains your games are served from. Avoid wildcards in production

After upgrading to v0.13.0 or later, run `adminGate("sweepOrphanApiKeys", [])` once to report API keys left behind by deleted games, then again with `["confirm"]` to revoke them.

---

## API reference

The Candid interface is the full contract. Every deployed canister gets the Candid UI for free. Here it is against the [live production canister](https://a4gq6-oaaaa-aaaab-qaa4q-cai.raw.icp0.io/?id=fdvph-sqaaa-aaaap-qqc4a-cai):

<img src="docs/candid-ui.png" alt="Candid UI showing the live CheddaBoards canister's method list" width="100%">

Key methods by area. Most owner-facing methods come in two forms: a principal variant (the caller is the owner) and a `BySession` variant (a session token identifies the owner).

**Sign-in and sessions**: `socialLoginAndGetProfile`, `createSessionForVerifiedUser`, `iiLoginAndGetProfile`, `validateSession`, `destroySession`

**Account linking**: `migrateAnonymousAccount`, `migrateAnonymousToII`

**Games**: `registerGame`, `updateGame`, `deleteGame`, `recoverDeletedGame`, `getGame`, `listGames`

**Game metadata**: `setGameEngine`, `getGameEngines`, `setGameWebsite`, `getGameWebsites`, `setDeveloperContact`, `getMyDeveloperContact`

**API keys**: `generateApiKey`, `getApiKey`, `revokeApiKey`, `validateApiKeyQuery` (verifier-only)

**Scores and leaderboards**: `submitScore`, `submitScoreToBoard`, `getScoreboard`, `getScoreboardsForGame`, `getLeaderboard`, `getPlayerRank`, `getPlayerScoreboardRank`

**Scoreboard management**: `createScoreboard`, `updateScoreboard`, `resetScoreboard`, `deleteScoreboard`

**Archives**: `getScoreboardArchives`, `getLastArchivedScoreboard`, `getArchivedScoreboard`

**Play sessions**: `startGameSessionByApiKey`, `startGameSessionBySession`, `getPlaySessionStatus`, `cancelPlaySession`

**Achievements**: `unlockAchievement`, `unlockAchievementBatch`, `getAchievements`

**Profiles**: `getMyProfileBySession`, `getUserProfile`, `getGameProfile`, `changeNicknameAndGetProfile`, `isNicknameAvailable`

**Moderation**: `getScoreboardAdmin`, `removeScoreEntry`, `removePlayerScores`, `getEntryDeletionLog`, `getSuspicionLogBySession`

**Stats and operations**: `getSubmissionStats`, `getSystemInfo`, `memStats`, `adminGate`

> **Fan-out vs targeted:** `submitScore` writes a score to every standard board on the game (all-time, weekly, daily). `submitScoreToBoard` writes to one board only, which is how per-level and per-category boards work. A board opts in to targeted behaviour in its config.

> **User ID types:** player-facing methods take a type and an ID. Use `session` with a session token, `external` with an API-key player ID, or `principal`. The `email` type is verifier-only.

### Direct HTTP reads

The canister answers plain HTTPS on its raw domain, with open CORS, so game clients can read boards without going through a proxy:

```bash
# A scoreboard, same JSON as the REST API
curl "https://<canister-id>.raw.icp0.io/games/<gameId>/scoreboards/<boardId>?limit=10"

# Capacity figures: cycles, memory and map sizes, with a warn status
curl "https://<canister-id>.raw.icp0.io/metrics"
```

The production canister ID is `fdvph-sqaaa-aaaap-qqc4a-cai`.

---

## Security

Found a vulnerability? Please email [info@cheddaboards.com](mailto:info@cheddaboards.com) instead of opening a public issue. Security fixes are listed under a **Security** heading in the changelog, and self-hosters should upgrade when one appears.

---

## Contributing

Issues and pull requests are welcome. Because this repo is a published mirror, accepted changes are applied to the source and appear here with the next release, with credit.

1. Fork the repo
2. Create a feature branch
3. Make your changes
4. Open a PR describing what it changes and how you tested it

---

## Links

- **Website**: [cheddaboards.com](https://cheddaboards.com)
- **Docs**: [docs.cheddaboards.com](https://docs.cheddaboards.com)
- **Developer dashboard**: [cheddaboards.com/developers](https://cheddaboards.com/developers)
- **Status**: [status.cheddatech.com](https://status.cheddatech.com)
- **Changelog**: [CHANGELOG.md](CHANGELOG.md)
- **Games**: [chedda.games](https://chedda.games)
- **Company**: [cheddatech.com](https://cheddatech.com)
- **X**: [@cheddatech](https://x.com/cheddatech)

---

## License

MIT. See [LICENSE](LICENSE).

---

**Built by [CheddaTech Ltd](https://cheddatech.com) on the Internet Computer.**
