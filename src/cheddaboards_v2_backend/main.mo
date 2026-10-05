// main.mo - CheddaBoards Backend

//     SETUP REQUIRED: Search for "REPLACE WITH YOUR" and set:
//     - VERIFIER: Your OAuth token verifier canister principal
//     - CONTROLLER: Your super admin principal (usually your dfx identity)
//     - firstAdmin: Initial admin principal (can be same as CONTROLLER)
//
// See README for deployment instructions.

import HashMap "mo:base/HashMap";
import Principal "mo:base/Principal";
import List "mo:base/List";
import Array "mo:base/Array";
import Nat "mo:base/Nat";
import Nat64 "mo:base/Nat64";
import Iter "mo:base/Iter";
import Text "mo:base/Text";
import Time "mo:base/Time";
import Blob "mo:base/Blob";
import Result "mo:base/Result";
import Buffer "mo:base/Buffer";
import Option "mo:base/Option";
import Random "mo:base/Random";
import Hash "mo:base/Hash";
import Int "mo:base/Int";
import Nat32 "mo:base/Nat32";
import Nat8 "mo:base/Nat8";
import Error "mo:base/Error";
import Char "mo:base/Char";
import Timer "mo:base/Timer";
import Cycles "mo:base/ExperimentalCycles";
import Prim "mo:prim";

import Types "types";
import ApiKeys "apikeys";
import Players "players";
import Scoreboards "scoreboards";

persistent actor CheddaBoards {

  // ════════════════════════════════════════════════════════════════════════════
  // TYPE ALIASES (from Types module)
  // ════════════════════════════════════════════════════════════════════════════

  // Core Identity
  type UserIdentifier = Types.UserIdentifier;
  type AuthType = Types.AuthType;
  type DeveloperTier = Types.DeveloperTier;

  // Sessions
  type Session = Types.Session;
  type PlaySession = Types.PlaySession;
  type TimeValidationResult = Types.TimeValidationResult;

  // Users / Players
  type GameProfile = Types.GameProfile;
  type UserProfile = Types.UserProfile;
  type PublicUserProfile = Types.PublicUserProfile;

  // Games
  type AccessMode = Types.AccessMode;
  type GameInfo = Types.GameInfo;
  type GameInfoLegacy = Types.GameInfoLegacy;
  type GameInfoV2 = Types.GameInfoV2;
  type DeletedGame = Types.DeletedGame;
  type DeletedGameLegacy = Types.DeletedGameLegacy;
  type DeletedGameV2 = Types.DeletedGameV2;
  type DeletionAttempt = Types.DeletionAttempt;

  // Scoreboards
  type SortBy = Types.SortBy;
  type ScoreboardPeriod = Types.ScoreboardPeriod;
  type ScoreboardConfig = Types.ScoreboardConfig;
  type ScoreEntry = Types.ScoreEntry;
  type PublicScoreEntry = Types.PublicScoreEntry;
  type Scoreboard = Types.Scoreboard;
  type ArchivedScoreboard = Types.ArchivedScoreboard;
  type ArchiveInfo = Types.ArchiveInfo;

  // API Keys
  type ApiKey = Types.ApiKey;

  // Analytics
  type AnalyticsEvent = Types.AnalyticsEvent;
  type DailyStats = Types.DailyStats;
  type PlayerStats = Types.PlayerStats;

  // Admin / Security
  type AdminRole = Types.AdminRole;
  type AdminAction = Types.AdminAction;
  type DeletedUser = Types.DeletedUser;
  type PendingDeletion = Types.PendingDeletion;
  type BackupData = Types.BackupData;

  // HTTP
  type HeaderField = Types.HeaderField;
  type HttpRequest = Types.HttpRequest;
  type HttpResponse = Types.HttpResponse;
  type StreamingStrategy = Types.StreamingStrategy;
  type StreamingCallbackToken = Types.StreamingCallbackToken;
  type StreamingCallbackResponse = Types.StreamingCallbackResponse;

  // Result alias (keep local since it's from base)
  type Result<Ok, Err> = Result.Result<Ok, Err>;

  // ════════════════════════════════════════════════════════════════════════════
  // CONSTANTS
  // ════════════════════════════════════════════════════════════════════════════

  // VERIFIER: principal of your proxy's signing identity.
  // Only this principal may call the privileged auth methods (e.g.
  // socialLoginAndGetProfile) that mint sessions from verified OAuth emails.
  // >>> REPLACE the placeholder below with your proxy's signing principal,
  // >>> deploy the proxy (with its matching signing identity) FIRST, and this
  // >>> canister SECOND. Leaving the placeholder disables OAuth login entirely.
  // NOTE: this actor is `persistent`, so this var is stable and survives
  // upgrades — the value is single-sourced via VERIFIER_PRINCIPAL and
  // force-reassigned in postupgrade(); edit VERIFIER_PRINCIPAL only.
  private transient let VERIFIER_PRINCIPAL : Text = "aaaaa-aa";
  var VERIFIER : Principal = Principal.fromText(VERIFIER_PRINCIPAL);

  private func isVerifier(p : Principal) : Bool {
      p == VERIFIER
  };

  // ── RANDOM TOKENS (v0.10.0) ──────────────────────────────────────────────
  // Session tokens, play-session tokens and API keys used to be built from
  // timestamps + counters, which are guessable (block times are public via
  // submittedAt). They now come from the management canister's raw_rand.
  // A small transient pool keeps minting synchronous in the common case:
  // takeRandomBytes only awaits when the pool is empty (first mint after a
  // deploy), and tops the pool up in the background as it drains.
  private transient let entropyPool = Buffer.Buffer<Nat8>(512);
  private transient let ENTROPY_TARGET : Nat = 512;
  private transient let ENTROPY_LOW_WATER : Nat = 128;
  private transient var entropyRefilling : Bool = false;

  private func topUpEntropy() : async () {
    if (entropyRefilling) { return };
    entropyRefilling := true;
    try {
      var rounds = 0;
      while (entropyPool.size() < ENTROPY_TARGET and rounds < 16) {
        let b = await Random.blob();
        for (byte in b.vals()) { entropyPool.add(byte) };
        rounds += 1;
      };
    } catch (_) {};
    entropyRefilling := false;
  };

  private func takeRandomBytes(n : Nat) : async* [Nat8] {
    while (entropyPool.size() < n) {
      let b = await Random.blob();
      for (byte in b.vals()) { entropyPool.add(byte) };
    };
    let size = entropyPool.size();
    let out = Array.tabulate<Nat8>(n, func(i : Nat) : Nat8 { entropyPool.get(size - n + i) });
    var k = 0;
    while (k < n) { ignore entropyPool.removeLast(); k += 1 };
    if (entropyPool.size() < ENTROPY_LOW_WATER and not entropyRefilling) {
      ignore topUpEntropy();
    };
    out
  };

  private func toHex(bytes : [Nat8]) : Text {
    let digits = ["0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f"];
    var out = "";
    for (b in bytes.vals()) {
      out := out # digits[Nat8.toNat(b / 16)] # digits[Nat8.toNat(b % 16)];
    };
    out
  };
  
  // ════════════════════════════════════════════════════════════════════════════
  // STABLE STORAGE
  // ════════════════════════════════════════════════════════════════════════════
  private var alternativeOriginsStable : [Text] = [];
  private var stableUsersByEmail : [(Text, UserProfile)] = [];
  private var stableUsersByPrincipal : [(Principal, UserProfile)] = [];
  stable var stableGames : [(Text, GameInfoLegacy)] = []; 
  stable var deletedGamesEntries : [(Text, DeletedGameLegacy)] = [];

// V2 stable vars (currently deployed - with OAuth, without time validation)
  stable var stableGamesV2 : [(Text, GameInfoV2)] = [];
  stable var deletedGamesEntriesV2 : [(Text, DeletedGameV2)] = [];

// V3 stable vars (new format - with time validation)
  stable var stableGamesV3 : [(Text, GameInfo)] = [];
  stable var deletedGamesEntriesV3 : [(Text, DeletedGame)] = [];
  
  stable var oauthMigrationDone : Bool = false;
  stable var timeValidationMigrationDone : Bool = false;
  
  private var stableSessions : [(Text, Session)] = [];
  private var stableSuspicionLog : [{ player_id : Text; gameId : Text; reason : Text; timestamp : Nat64 }] = [];
  // Audit trail for dev-initiated board entry deletions
  type EntryDeletionRecord = {
    caller : Principal;
    gameId : Text;
    scope : Text;        // scoreboardId, or "ALL" for a player wipe
    playerKey : Text;    // opaque hash of the player identifier
    nickname : Text;
    liveRemoved : Nat;
    archiveRemoved : Nat;
    profileReset : Bool;
    timestamp : Nat64;
  };
  private var stableEntryDeletionLog : [EntryDeletionRecord] = [];
  private var stableAnalyticsEvents : [AnalyticsEvent] = [];
  private var stableDailyStats : [(Text, DailyStats)] = [];
  private var stablePlayerStats : [(Text, PlayerStats)] = [];
  private var stableLastSubmitTime : [(Text, Nat64)] = [];
  private var sessionCounter : Nat64 = 0;
  private var deleteRateLimitEntries : [(Principal, [DeletionAttempt])] = [];
  private var apiKeysStable : [(Text, ApiKey)] = [];
  private var developerTiersStable : [(Principal, DeveloperTier)] = [];
  // Release A (Oct 2026): engine tag per game + optional developer contact email.
  private var gameEnginesStable : [(Text, Text)] = [];
  private var developerContactsStable : [(Principal, Text)] = [];
  private var gameWebsitesStable : [(Text, Text)] = [];
  // v0.14.0: session-path developer identity, looked up by exact email.
  private var emailOwnerIdsStable : [(Text, Principal)] = [];
  private var ownerIdsSeeded : Bool = false;
  private var ownerIdCollisions : [Text] = [];
  // Scoreboard stable storage
  private var scoreboardConfigsStable : [(Text, ScoreboardConfig)] = [];
  private var scoreboardEntriesStable : [(Text, [ScoreEntry])] = [];
  private var scoreboardConfigsStableV2 : [(Text, ScoreboardConfig)] = [];
  private var scoreboardEntriesStableV2 : [(Text, [ScoreEntry])] = [];
  private var scoreboardArchivesStable : [(Text, ArchivedScoreboard)] = [];
  private var scoreboardArchivesStableV2 : [(Text, ArchivedScoreboard)] = [];
  private var userIdCounter : Nat = 0;
  var totalSubmissions : Nat = 0;
  var submissionsToday : Nat = 0;
  var lastResetDate : Text = "";

  private var playSessionsStable : [(Text, PlaySession)] = [];

  // ════════════════════════════════════════════════════════════════════════════
  // RUNTIME MAPS
  // ════════════════════════════════════════════════════════════════════════════  
  
  private transient var scoreboardTimerId : ?Timer.TimerId = null;
  private transient var alternativeOrigins = Buffer.Buffer<Text>(10);
  private transient var deletedGames = HashMap.HashMap<Text, DeletedGame>(10, Text.equal, Text.hash);
  private transient var deleteRateLimit = HashMap.HashMap<Principal, [DeletionAttempt]>(10, Principal.equal, Principal.hash);
  private transient var usersByEmail = HashMap.HashMap<Text, UserProfile>(10, Text.equal, Text.hash);
  private transient var usersByPrincipal = HashMap.HashMap<Principal, UserProfile>(10, Principal.equal, Principal.hash);
  private transient var games = HashMap.HashMap<Text, GameInfo>(10, Text.equal, Text.hash);
  private transient var sessions = HashMap.HashMap<Text, Session>(10, Text.equal, Text.hash);
  private transient var lastSubmitTime = HashMap.HashMap<Text, Nat64>(10, Text.equal, Text.hash);
  // PLAY-DEDUPE 2026-09-08: since the 2026-08-31 stats fix, EVERY submit path
  // counts a play, so one run fanned out to N boards as N client calls counted
  // N plays (Scooter Dash: main + 2 targeted = +3 per run). A play now counts
  // at most once per window per (player, game), shared across submitScore and
  // submitScoreToBoard. Deliberately transient and NOT copied through
  // preupgrade: worst case after a deploy is one double-counted play per
  // mid-window player, and transient means the window literal below actually
  // takes effect on upgrade (VERIFIER stable-let lesson).
  private transient let PLAY_DEDUPE_WINDOW_NS : Nat64 = 5_000_000_000; // 5s
  private transient var lastPlayCounted = HashMap.HashMap<Text, Nat64>(10, Text.equal, Text.hash);
  private transient var cachedLeaderboards = HashMap.HashMap<Text, [(Text, Nat64, Nat64, Text)]>(10, Text.equal, Text.hash);
  private transient var leaderboardLastUpdate = HashMap.HashMap<Text, Nat64>(10, Text.equal, Text.hash);
  private transient let LEADERBOARD_CACHE_TTL : Nat64 = 60_000_000_000;
  private transient var analyticsEvents = Buffer.Buffer<AnalyticsEvent>(100);
  private transient var dailyStats = HashMap.HashMap<Text, DailyStats>(10, Text.equal, Text.hash);
  private transient var playerStats = HashMap.HashMap<Text, PlayerStats>(10, Text.equal, Text.hash);
  private transient var apiKeys = HashMap.HashMap<Text, ApiKey>(50, Text.equal, Text.hash);
  private transient var suspicionLog : List.List<{ player_id : Text; gameId : Text; reason : Text; timestamp : Nat64 }> = List.nil();
  private transient var entryDeletionLog : List.List<EntryDeletionRecord> = List.nil();
  private transient var sessionsEntries : [(Text, Session)] = [];
  private transient var principalToSessionEntries : [(Text, Text)] = [];
  private transient var principalToSession = HashMap.HashMap<Text, Text>(10, Text.equal, Text.hash);
  private transient var developerTiers = HashMap.HashMap<Principal, DeveloperTier>(10, Principal.equal, Principal.hash);
  private transient var gameEngines = HashMap.HashMap<Text, Text>(50, Text.equal, Text.hash);
  private transient var developerContacts = HashMap.HashMap<Principal, Text>(10, Principal.equal, Principal.hash);
  private transient var gameWebsites = HashMap.HashMap<Text, Text>(50, Text.equal, Text.hash);
  private transient var emailOwnerIds = HashMap.HashMap<Text, Principal>(100, Text.equal, Text.hash);
  
  // Scoreboard runtime maps
  private transient var scoreboardConfigs = HashMap.HashMap<Text, ScoreboardConfig>(50, Text.equal, Text.hash);
  private transient var scoreboardEntries = HashMap.HashMap<Text, Buffer.Buffer<ScoreEntry>>(50, Text.equal, Text.hash);
  private transient var cachedScoreboards = HashMap.HashMap<Text, [PublicScoreEntry]>(50, Text.equal, Text.hash);
  private transient var scoreboardLastUpdate = HashMap.HashMap<Text, Nat64>(50, Text.equal, Text.hash);
  private transient let SCOREBOARD_CACHE_TTL : Nat64 = 30_000_000_000; // 30 seconds
  private transient var scoreboardArchives = HashMap.HashMap<Text, ArchivedScoreboard>(100, Text.equal, Text.hash);
  private transient var playSessions = HashMap.HashMap<Text, PlaySession>(100, Text.equal, Text.hash);

  // DEPRECATED - kept for stable storage compatibility, use Scoreboards.MAX_ARCHIVES_PER_SCOREBOARD instead
  private let MAX_ARCHIVES_PER_SCOREBOARD : Nat = 52;
  
  // ════════════════════════════════════════════════════════════════════════════
  // CONSTANTS
  // ════════════════════════════════════════════════════════════════════════════

  // CONTROLLER: your dfx identity's principal (`dfx identity get-principal`).
  // Grants SuperAdmin access to adminGate commands. REPLACE before deploying.
  // NOTE: implicitly stable (persistent actor) — changing this literal after
  // the first deploy has no effect on an upgraded canister; see VERIFIER above.
  private var CONTROLLER : Principal = Principal.fromText("aaaaa-aa");
  // 30 days (was 24h). Sessions also renew on every successful use — see validateSessionInternal.
  private transient let SESSION_DURATION_NS : Nat64 = 30 * 24 * 60 * 60 * 1_000_000_000;
  private transient var lastCleanup : Nat64 = 0;
  private transient let _MAX_GAMES_PER_DEVELOPER : Nat = 3;  // superseded by getMaxGamesForDeveloper (tiers)
  private var adminRolesStable : [(Principal, AdminRole)] = [];
  private var auditLogStable : [AdminAction] = [];
  private var deletedUsersStable : [(Text, DeletedUser)] = [];
  private var emergencyPaused : Bool = false;

  private transient var adminRoles = HashMap.fromIter<Principal, AdminRole>(
    adminRolesStable.vals(), 10, Principal.equal, Principal.hash
  );

  private transient var deletedUsers = HashMap.fromIter<Text, DeletedUser>(
    deletedUsersStable.vals(), 10, Text.equal, Text.hash
  );

  private transient var lastCommandTime = HashMap.HashMap<(Principal, Text), Nat64>(
    10,
    func(a: (Principal, Text), b: (Principal, Text)) : Bool { 
      Principal.equal(a.0, b.0) and Text.equal(a.1, b.1)
    },
    func(x: (Principal, Text)) : Hash.Hash {
      Principal.hash(x.0)
    }
  );

  private transient var pendingDeletions = HashMap.HashMap<Text, PendingDeletion>(
    10, Text.equal, Text.hash
  );

  private transient var auditLog = Buffer.Buffer<AdminAction>(100);

  private transient let DEFAULT_SESSION_DURATION_MINS : Nat = 30;
  private transient let MAX_ACTIVE_SESSIONS_PER_PLAYER : Nat = 3;  // Prevent token hoarding
  // Global play-session sweep kicks in once the map passes this size. Per-player
  // cleanup only runs when that player starts another session, so sessions from
  // one-off players lingered forever (1,290 on fdvph, 30 Sep 2026).
  private transient let PLAY_SESSION_SWEEP_THRESHOLD : Nat = 500;

  // ════════════════════════════════════════════════════════════════════════════
  // HELPERS
  // ════════════════════════════════════════════════════════════════════════════

  func now() : Nat64 = Nat64.fromIntWrap(Time.now());

  public query func debugDataState() : async {
    legacyGamesCount: Nat;
    legacyDeletedCount: Nat;
    v2GamesCount: Nat;
    v2DeletedCount: Nat;
    runtimeGamesCount: Nat;
    runtimeDeletedCount: Nat;
    migrationDone: Bool;
} {
    {
        legacyGamesCount = stableGames.size();
        legacyDeletedCount = deletedGamesEntries.size();
        v2GamesCount = stableGamesV2.size();
        v2DeletedCount = deletedGamesEntriesV2.size();
        runtimeGamesCount = games.size();
        runtimeDeletedCount = deletedGames.size();
        migrationDone = oauthMigrationDone;
    }
};

  
  private func getMaxGamesForDeveloper(owner: Principal) : Nat {
    switch (developerTiers.get(owner)) {
        case (?#pro) { 10 };
        case (_) { 3 };  // free tier default
    }
};

private func getDeveloperTierText(owner: Principal) : Text {
    switch (developerTiers.get(owner)) {
        case (?#pro) { "pro" };
        case (_) { "free" };
    }
};

  // v0.10.0: 256 bits from raw_rand (see takeRandomBytes). Counter kept for stats.
  func generateSessionId(randomBytes : [Nat8]) : Text {
    sessionCounter += 1;
    "session_" # toHex(randomBytes)
  };

  func logSuspicion(playerId : Text, gameId : Text, reason : Text) {
    suspicionLog := List.push({
      player_id = playerId;
      gameId = gameId;
      reason = reason;
      timestamp = now();
    }, suspicionLog);
  };

  private func isAdmin(caller: Principal) : Bool {
    if (caller == CONTROLLER) {
      return true;
    };
    Option.isSome(adminRoles.get(caller))
  };

  func getDateString(timestamp : Nat64) : Text {
    let day = timestamp / 86_400_000_000_000;
    "day-" # Nat64.toText(day)
  };

  func getTimeOfDay(timestamp : Nat64) : Text {
    let hour = (timestamp / 3_600_000_000_000) % 24;
    if (hour < 6) { "night" }
    else if (hour < 12) { "morning" }
    else if (hour < 18) { "afternoon" }
    else { "evening" }
  };


  func cleanupExpiredSessions() {
    let currentTime = now();
    let sessionEntries = Iter.toArray(sessions.entries());
    
    var cleanedCount = 0;
    for ((sessionId, session) in sessionEntries.vals()) {
      if (currentTime > session.expires) {
        sessions.delete(sessionId);
        cleanedCount += 1;
      };
    };
  };

  func trackEventInternal(identifier: UserIdentifier, gameId: Text, eventType : Text, metadata : [(Text, Text)]) : () {
    let event : AnalyticsEvent = {
      eventType = eventType;
      gameId = gameId;
      identifier = identifier;  
      timestamp = now();
      metadata = metadata;
    };
    
    analyticsEvents.add(event);
    
    if (analyticsEvents.size() > 10000) {
      let newBuffer = Buffer.Buffer<AnalyticsEvent>(10000);
      let startIdx : Nat = Int.abs(+analyticsEvents.size() - 10000);
      for (i in Iter.range(startIdx, analyticsEvents.size() - 1)) {
        newBuffer.add(analyticsEvents.get(i));
      };
      analyticsEvents := newBuffer;
    };
    
    let dateStr = getDateString(event.timestamp);
    let statsKey = dateStr # ":" # gameId;
    
    switch (dailyStats.get(statsKey)) {
      case (?stats) {
        let updated = {
          date = stats.date;
          gameId = gameId;
          uniquePlayers = stats.uniquePlayers;
          totalGames = if (eventType == "game_end") { stats.totalGames + 1 } else { stats.totalGames };
          totalScore = stats.totalScore;
          newUsers = if (eventType == "signup") { stats.newUsers + 1 } else { stats.newUsers };
          authenticatedPlays = if (eventType == "game_end") { stats.authenticatedPlays + 1 } else { stats.authenticatedPlays };
        };
        dailyStats.put(statsKey, updated);
      };
      case null {
        dailyStats.put(statsKey, {
          date = dateStr;
          gameId = gameId;
          uniquePlayers = 1;
          totalGames = if (eventType == "game_end") { 1 } else { 0 };
          totalScore = 0;
          newUsers = if (eventType == "signup") { 1 } else { 0 };
          authenticatedPlays = if (eventType == "game_end") { 1 } else { 0 };
        });
      };
    };
    
    let playerKey = identifierToText(identifier) # ":" # gameId;
    switch (playerStats.get(playerKey)) {
      case (?stats) {
        let updated = {
          gameId = gameId;
          identifier = identifier;
          totalGames = if (eventType == "game_end") { stats.totalGames + 1 } else { stats.totalGames };
          avgScore = stats.avgScore;
          playStreak = stats.playStreak;
          lastPlayed = now();
          favoriteTime = getTimeOfDay(now());
        };
        playerStats.put(playerKey, updated);
      };
      case null {
        playerStats.put(playerKey, {
          gameId = gameId;
          identifier = identifier;
          totalGames = if (eventType == "game_end") { 1 } else { 0 };
          avgScore = 0;
          playStreak = 1;
          lastPlayed = now();
          favoriteTime = getTimeOfDay(now());
        });
      };
    };
  };

  func getValidationRules(gameId : Text) : {
    maxScorePerRound : ?Nat64;
    maxStreakDelta : ?Nat64;
    absoluteScoreCap : ?Nat64;
    absoluteStreakCap : ?Nat64;
  } {
    switch (games.get(gameId)) {
      case (?game) {
        {
          maxScorePerRound = game.maxScorePerRound;
          maxStreakDelta = game.maxStreakDelta;
          absoluteScoreCap = game.absoluteScoreCap;
          absoluteStreakCap = game.absoluteStreakCap;
        }
      };
      case null {
        {
          maxScorePerRound = null;
          maxStreakDelta = null;
          absoluteScoreCap = null;
          absoluteStreakCap = null;
        }
      };
    }
  };

    private func calculateCurrentPeriodStart(config : ScoreboardConfig, currentTime : Nat64) : Nat64 {
      // Delegated: daily/weekly/monthly snap to calendar boundaries
      // (midnight / Monday / 1st of month, all UTC); #custom snaps forward
      // from lastReset by whole intervals; #allTime & interval-less custom
      // return currentTime (callers only reach this when a reset is due).
      Scoreboards.currentPeriodStart(config, currentTime)
    };

  // ════════════════════════════════════════════════════════════════════════════
  // PLAYER HELPERS (delegated to Players module)
  // ════════════════════════════════════════════════════════════════════════════

  func identifierToText(id : UserIdentifier) : Text {
    Players.identifierToText(id)
  };

  func makeSubmitKey(identifier : UserIdentifier, gameId : Text) : Text {
    Players.makeSubmitKey(identifier, gameId)
  };

  private func generateDefaultNickname() : Text {
    userIdCounter += 1;
    Players.generateDefaultNickname(userIdCounter)
  };

  private func isDefaultNickname(nickname : Text) : Bool {
    Players.isDefaultNickname(nickname)
  };

  private func isNicknameTaken(nickname : Text, excludeIdentifier : ?UserIdentifier) : Bool {
    Players.isNicknameTaken(
      nickname,
      excludeIdentifier,
      usersByEmail.entries(),
      usersByPrincipal.entries()
    )
  };

  // Get an available nickname - adds _1, _2, etc. if the base name is taken
  private func getAvailableNickname(desiredNickname : Text, excludeIdentifier : ?UserIdentifier) : Text {
    // If the desired nickname is available, use it
    if (not isNicknameTaken(desiredNickname, excludeIdentifier)) {
      return desiredNickname;
    };
    
    // Try with suffixes: _1, _2, _3, etc.
    // Max 16 chars total, so we need to truncate if adding suffix would exceed
    var suffix : Nat = 1;
    let maxSuffix : Nat = 99;
    
    while (suffix <= maxSuffix) {
      let suffixText = "_" # Nat.toText(suffix);
      let suffixLen = Text.size(suffixText);
      
      // Truncate base name if needed to fit within 16 chars
      let maxBaseLen = 16 - suffixLen;
      var baseName = desiredNickname;
      if (Text.size(baseName) > maxBaseLen) {
        // Take first maxBaseLen chars
        var chars = Buffer.Buffer<Char>(maxBaseLen);
        var count = 0;
        for (c in baseName.chars()) {
          if (count < maxBaseLen) {
            chars.add(c);
            count += 1;
          };
        };
        baseName := Text.fromIter(chars.vals());
      };
      
      let candidate = baseName # suffixText;
      
      if (not isNicknameTaken(candidate, excludeIdentifier)) {
        return candidate;
      };
      
      suffix += 1;
    };
    
    // Fallback: generate a random name (very unlikely to reach here)
    "Player_" # Nat.toText(userIdCounter)
  };

  // Check if a nickname is available (public query for frontend)
  public query func isNicknameAvailable(nickname : Text, gameId : Text) : async Bool {
    not isNicknameTaken(nickname, null)
  };

  private func looksLikeEmail(text : Text) : Bool {
    Players.looksLikeEmail(text)
  };

  private func isValidExternalPlayerId(playerId : Text) : Bool {
    Players.isValidExternalPlayerId(playerId)
  };

  func validateNickname(nickname: Text) : Result.Result<(), Text> {
    Players.validateNickname(nickname)
  };

  // ════════════════════════════════════════════════════════════════════════════
  // SCOREBOARD HELPERS (delegated to Scoreboards module)
  // ════════════════════════════════════════════════════════════════════════════

  func authTypeToText(auth : AuthType) : Text {
    Scoreboards.authTypeToText(auth)
  };

  func accessModeToText(mode : AccessMode) : Text {
    Scoreboards.accessModeToText(mode)
  };

  private func makeArchiveKey(gameId : Text, scoreboardId : Text, timestamp : Nat64) : Text {
    Scoreboards.makeArchiveKey(gameId, scoreboardId, timestamp)
  };

  private func shouldResetDaily(lastReset : Nat64, currentTime : Nat64) : Bool {
    Scoreboards.shouldResetDaily(lastReset, currentTime)
  };

  private func shouldResetWeekly(lastReset : Nat64, currentTime : Nat64) : Bool {
    Scoreboards.shouldResetWeekly(lastReset, currentTime)
  };

  private func shouldResetMonthly(lastReset : Nat64, currentTime : Nat64) : Bool {
    Scoreboards.shouldResetMonthly(lastReset, currentTime)
  };

  private func identifiersEqual(a : UserIdentifier, b : UserIdentifier) : Bool {
    Scoreboards.identifiersEqual(a, b)
  };

  private func makeScoreboardKey(gameId : Text, scoreboardId : Text) : Text {
    Scoreboards.makeKey(gameId, scoreboardId)
  };

  private func scoreboardNeedsReset(config : ScoreboardConfig) : Bool {
    Scoreboards.needsReset(config, now())
  };

  private func periodToText(period : ScoreboardPeriod) : Text {
    Scoreboards.periodToText(period)
  };

  private func textToPeriod(text : Text) : ?ScoreboardPeriod {
    Scoreboards.textToPeriod(text)
  };

  // ═══════════════════════════════════════════════════════════════════════════════
  // PLAY SESSION / TIME VALIDATION HELPERS
  // ═══════════════════════════════════════════════════════════════════════════════

  // v0.10.0: was a 32-bit Text.hash of gameId:identifier:time (guessable);
  // now 128 bits from raw_rand. Format prefix unchanged.
  private func generatePlaySessionToken(gameId: Text, randomBytes : [Nat8]) : Text {
    "ps_" # gameId # "_" # toHex(randomBytes)
  };

  private func getTimeValidationRules(gameId: Text) : {
    enabled: Bool;
    minPlayDurationSecs: Nat64;
    maxScorePerSecond: Nat64;
    maxSessionDurationMins: Nat;
  } {
    switch (games.get(gameId)) {
      case (?game) {
        {
          enabled = game.timeValidationEnabled;
          minPlayDurationSecs = switch (game.minPlayDurationSecs) {
            case (?secs) { secs };
            case null { 0 };
          };
          maxScorePerSecond = switch (game.maxScorePerSecond) {
            case (?rate) { rate };
            case null { 0 };
          };
          maxSessionDurationMins = switch (game.maxSessionDurationMins) {
            case (?mins) { mins };
            case null { DEFAULT_SESSION_DURATION_MINS };
          };
        }
      };
      case null {
        {
          enabled = false;
          minPlayDurationSecs = 0;
          maxScorePerSecond = 0;
          maxSessionDurationMins = DEFAULT_SESSION_DURATION_MINS;
        }
      };
    }
  };

  private func countActiveSessionsForPlayer(identifier: UserIdentifier, gameId: Text) : Nat {
    let currentTime = now();
    var count = 0;
    
    for ((_, session) in playSessions.entries()) {
      if (identifiersEqual(session.identifier, identifier) and 
          session.gameId == gameId and 
          session.isActive and 
          currentTime < session.expiresAt) {
        count += 1;
      };
    };
    
    count
  };

  private func cleanupExpiredPlaySessions(identifier: UserIdentifier, gameId: Text) {
    let currentTime = now();
    let keysToRemove = Buffer.Buffer<Text>(5);
    
    for ((token, session) in playSessions.entries()) {
      if (identifiersEqual(session.identifier, identifier) and 
          session.gameId == gameId and 
          (currentTime >= session.expiresAt or not session.isActive)) {
        keysToRemove.add(token);
      };
    };
    
    for (key in keysToRemove.vals()) {
      playSessions.delete(key);
    };
  };

  // Drops every expired/inactive play session, but only when the map has grown
  // past PLAY_SESSION_SWEEP_THRESHOLD, so the full scan is rare. Same rule as
  // the admin cleanupAllExpiredPlaySessions(), just triggered by traffic.
  private func sweepExpiredPlaySessionsIfLarge() {
    if (playSessions.size() <= PLAY_SESSION_SWEEP_THRESHOLD) { return };
    let currentTime = now();
    let keysToRemove = Buffer.Buffer<Text>(50);
    for ((token, session) in playSessions.entries()) {
      if (currentTime >= session.expiresAt or not session.isActive) {
        keysToRemove.add(token);
      };
    };
    for (key in keysToRemove.vals()) { playSessions.delete(key) };
  };

  private func validatePlaySession(
    sessionToken: Text,
    identifier: UserIdentifier,
    gameId: Text,
    score: Nat64
  ) : TimeValidationResult {
    let currentTime = now();
    
    switch (playSessions.get(sessionToken)) {
      case null {
        return {
          isValid = false;
          playDuration = 0;
          reason = ?"Invalid or expired play session. Start a new game.";
        };
      };
      case (?session) {
        if (not identifiersEqual(session.identifier, identifier)) {
          return {
            isValid = false;
            playDuration = 0;
            reason = ?"Session belongs to another player.";
          };
        };
        
        if (session.gameId != gameId) {
          return {
            isValid = false;
            playDuration = 0;
            reason = ?"Session is for a different game.";
          };
        };
        
        if (not session.isActive) {
          return {
            isValid = false;
            playDuration = 0;
            reason = ?"Session already used. Start a new game.";
          };
        };
        
        if (currentTime >= session.expiresAt) {
          return {
            isValid = false;
            playDuration = 0;
            reason = ?"Session expired. Start a new game.";
          };
        };
        
        let durationNanos = currentTime - session.startedAt;
        let durationSecs = durationNanos / 1_000_000_000;
        
        let rules = getTimeValidationRules(gameId);
        
        if (rules.minPlayDurationSecs > 0 and durationSecs < rules.minPlayDurationSecs) {
          return {
            isValid = false;
            playDuration = durationSecs;
            // Category only — the configured minimum is the dev's setting and
            // must not be echoed to clients (INFO-LEAK fix 2026-08-21). Actual
            // play duration is logged owner-side at the submit call sites.
            reason = ?"Played too quickly.";
          };
        };
        
        if (rules.maxScorePerSecond > 0 and durationSecs > 0) {
          let scorePerSecond = score / durationSecs;
          if (scorePerSecond > rules.maxScorePerSecond) {
            return {
              isValid = false;
              playDuration = durationSecs;
              reason = ?"Score too high for play duration.";
            };
          };
        };
        
        {
          isValid = true;
          playDuration = durationSecs;
          reason = null;
        }
      };
    }
  };

  private func consumePlaySession(sessionToken: Text) {
    switch (playSessions.get(sessionToken)) {
      case null {};
      case (?session) {
        let consumed : PlaySession = {
          sessionToken = session.sessionToken;
          identifier = session.identifier;
          gameId = session.gameId;
          startedAt = session.startedAt;
          expiresAt = session.expiresAt;
          isActive = false;
        };
        playSessions.put(sessionToken, consumed);
      };
    };
  };

  func getUserByIdentifier(identifier : UserIdentifier) : ?UserProfile {
    switch (identifier) {
      case (#email(e)) { usersByEmail.get(e) };
      case (#principal(p)) { usersByPrincipal.get(p) };
    }
  };

  func putUserByIdentifier(user : UserProfile) {
    switch (user.identifier) {
      case (#email(e)) { usersByEmail.put(e, user) };
      case (#principal(p)) { usersByPrincipal.put(p, user) };
    }
  };

  func countGamesByOwner(owner : Principal) : Nat {
    var count = 0;
    for ((_, game) in games.entries()) {
      if (game.owner == owner) {
        count += 1;
      };
    };
    count
  };

  // Archive a scoreboard before reset - call this before clearing entries
  private func archiveScoreboard(key : Text, config : ScoreboardConfig) : () {
    let entriesBuffer = switch (scoreboardEntries.get(key)) {
      case (?buf) { buf };
      case null { return }; // Nothing to archive
    };
    
    // Don't archive empty scoreboards
    if (entriesBuffer.size() == 0) {
      return;
    };
    
    let t = now();
    let archiveKey = makeArchiveKey(config.gameId, config.scoreboardId, t);
    
    let archive : ArchivedScoreboard = {
      scoreboardId = config.scoreboardId;
      gameId = config.gameId;
      name = config.name;
      period = config.period;
      sortBy = config.sortBy;
      periodStart = config.lastReset;
      periodEnd = t;
      // Sort into final leaderboard order at archive time — the live buffer
      // is insertion-ordered and only sorted at read time, but archives are
      // read raw by the dashboard/API, so store them canonically sorted.
      entries = Scoreboards.sortEntries(Buffer.toArray(entriesBuffer), config.sortBy);
      totalEntries = entriesBuffer.size();
    };
    
    scoreboardArchives.put(archiveKey, archive);
    
    // Cleanup old archives if we have too many
    cleanupOldArchives(config.gameId, config.scoreboardId);
  };

  // ═══════════════════════════════════════════════════════════════════════════════
  // HELPER: Create default scoreboards for a new game
  // ═══════════════════════════════════════════════════════════════════════════════
  
private func createDefaultScoreboards(gameId : Text, owner : Principal) : () {
    let currentTime = now();
    
    // Create All-Time scoreboard (by score)
    let allTimeKey = makeScoreboardKey(gameId, "all-time");
    let allTimeConfig : ScoreboardConfig = {
      scoreboardId = "all-time";
      gameId = gameId;
      name = "All Time";
      description = "Best scores of all time";
      period = #allTime;
      sortBy = #score;
      maxEntries = 1000;
      created = currentTime;
      lastReset = currentTime;
      isActive = true;
      targeted = ?false;
      resetIntervalNanos = null;
    };
    scoreboardConfigs.put(allTimeKey, allTimeConfig);
    scoreboardEntries.put(allTimeKey, Buffer.Buffer<ScoreEntry>(100));
    
    // Create Weekly scoreboard (by score)
    let weeklyKey = makeScoreboardKey(gameId, "weekly");
    let weeklyConfig : ScoreboardConfig = {
      scoreboardId = "weekly";
      gameId = gameId;
      name = "Weekly";
      description = "Top scores this week";
      period = #weekly;
      sortBy = #score;
      maxEntries = 1000;
      created = currentTime;
      lastReset = currentTime;
      isActive = true;
      targeted = ?false;
      resetIntervalNanos = null;
    };
    scoreboardConfigs.put(weeklyKey, weeklyConfig);
    scoreboardEntries.put(weeklyKey, Buffer.Buffer<ScoreEntry>(100));
    
    // Create Daily scoreboard (by score)
    let dailyKey = makeScoreboardKey(gameId, "daily");
    let dailyConfig : ScoreboardConfig = {
      scoreboardId = "daily";
      gameId = gameId;
      name = "Daily";
      description = "Top scores today";
      period = #daily;
      sortBy = #score;
      maxEntries = 1000;
      created = currentTime;
      lastReset = currentTime;
      isActive = true;
      targeted = ?false;
      resetIntervalNanos = null;
    };
    scoreboardConfigs.put(dailyKey, dailyConfig);
    scoreboardEntries.put(dailyKey, Buffer.Buffer<ScoreEntry>(100));
    
    trackEventInternal(#principal(owner), gameId, "default_scoreboards_created", [
      ("scoreboards", "all-time,weekly,daily")
    ]);
  };

  // Remove old archives beyond the limit
  private func cleanupOldArchives(gameId : Text, scoreboardId : Text) : () {
    let prefix = gameId # ":" # scoreboardId # ":";
    
    // Collect all archive keys for this scoreboard
    let archiveKeys = Buffer.Buffer<(Text, Nat64)>(10);
    for ((key, archive) in scoreboardArchives.entries()) {
      if (Text.startsWith(key, #text prefix)) {
        archiveKeys.add((key, archive.periodEnd));
      };
    };
    
    // If under limit, nothing to do
    if (archiveKeys.size() <= Scoreboards.MAX_ARCHIVES_PER_SCOREBOARD) {
      return;
    };
    
    // Sort by timestamp (oldest first)
    let sorted = Array.sort<(Text, Nat64)>(
      Buffer.toArray(archiveKeys),
      func(a, b) {
        if (a.1 < b.1) { #less }
        else if (a.1 > b.1) { #greater }
        else { #equal }
      }
    );
    
    // Remove oldest archives
    let toRemove = sorted.size() - Scoreboards.MAX_ARCHIVES_PER_SCOREBOARD;
    for (i in Iter.range(0, toRemove - 1)) {
      scoreboardArchives.delete(sorted[i].0);
    };
  };


  // Writes one player's best-merged entry into a SINGLE scoreboard buffer.
  // Extracted from updateScoreboardsForGame so the fan-out path and the targeted
  // submitScoreToBoard path share identical reset/merge/trim/cache semantics.
  private func writeEntryToBoard(
    sbKey : Text,
    config : ScoreboardConfig,
    userIdentifier : UserIdentifier,
    nickname : Text,
    score : Nat64,
    streak : Nat64,
    authType : AuthType,
    t : Nat64
  ) {
    // Auto-reset if due (interval-aware for #custom via Scoreboards.needsReset)
    let needsReset = Scoreboards.needsReset(config, t);

    var entriesBuffer = switch (scoreboardEntries.get(sbKey)) {
      case (?buf) { buf };
      case null { Buffer.Buffer<ScoreEntry>(config.maxEntries) };
    };

    if (needsReset) {
      archiveScoreboard(sbKey, config);
      entriesBuffer := Buffer.Buffer<ScoreEntry>(config.maxEntries);
      scoreboardConfigs.put(sbKey, {
        scoreboardId = config.scoreboardId;
        gameId = config.gameId;
        name = config.name;
        description = config.description;
        period = config.period;
        sortBy = config.sortBy;
        maxEntries = config.maxEntries;
        created = config.created;
        // Anchor to the period boundary (midnight/Monday/1st UTC, or the
        // custom-interval step), not the submission time — keeps periods
        // aligned and archive periodStart values exact.
        lastReset = Scoreboards.currentPeriodStart(config, t);
        isActive = config.isActive;
        targeted = config.targeted;
        resetIntervalNanos = config.resetIntervalNanos;
      });
    };

    var existingEntry : ?ScoreEntry = null;
    var existingIdx : ?Nat = null;
    var idx : Nat = 0;
    for (entry in entriesBuffer.vals()) {
      if (identifiersEqual(entry.odentifier, userIdentifier)) {
        existingEntry := ?entry;
        existingIdx := ?idx;
      };
      idx += 1;
    };

    let existingScore : Nat64 = switch (existingEntry) { case null { 0 }; case (?e) { e.score } };
    let existingStreak : Nat64 = switch (existingEntry) { case null { 0 }; case (?e) { e.streak } };

    let mergedScore : Nat64 = if (score > existingScore) score else existingScore;
    let mergedStreak : Nat64 = if (streak > existingStreak) streak else existingStreak;

    let scoreImproved = score > existingScore;
    let streakImproved = streak > existingStreak;
    let nicknameChanged = switch (existingEntry) { case null { false }; case (?e) { e.nickname != nickname } };
    let isNewEntry = existingEntry == null;
    let shouldWrite = isNewEntry or scoreImproved or streakImproved or nicknameChanged;

    let sortImproved = switch (config.sortBy) {
      case (#score) { scoreImproved };
      case (#streak) { streakImproved };
    };

    if (shouldWrite) {
      let newSubmittedAt = if (sortImproved or isNewEntry) { t }
                           else {
                             switch (existingEntry) {
                               case (?e) { e.submittedAt };
                               case null { t };
                             };
                           };

      let newEntry : ScoreEntry = {
        odentifier = userIdentifier;
        nickname = nickname;
        score = mergedScore;
        streak = mergedStreak;
        submittedAt = newSubmittedAt;
        authType = authType;
      };

      switch (existingIdx) {
        case (?i) { entriesBuffer.put(i, newEntry) };
        case null {
          entriesBuffer.add(newEntry);
          if (entriesBuffer.size() > config.maxEntries) {
            var worstIdx : Nat = 0;
            var worstValue : Nat64 = switch (config.sortBy) {
              case (#score) { entriesBuffer.get(0).score };
              case (#streak) { entriesBuffer.get(0).streak };
            };
            var i : Nat = 1;
            while (i < entriesBuffer.size()) {
              let entryValue = switch (config.sortBy) {
                case (#score) { entriesBuffer.get(i).score };
                case (#streak) { entriesBuffer.get(i).streak };
              };
              if (entryValue < worstValue) {
                worstValue := entryValue;
                worstIdx := i;
              };
              i += 1;
            };
            let newBuffer = Buffer.Buffer<ScoreEntry>(config.maxEntries);
            i := 0;
            for (entry in entriesBuffer.vals()) {
              if (i != worstIdx) { newBuffer.add(entry) };
              i += 1;
            };
            entriesBuffer := newBuffer;
          };
        };
      };

      scoreboardEntries.put(sbKey, entriesBuffer);
      cachedScoreboards.delete(sbKey);
      scoreboardLastUpdate.delete(sbKey);
    };
  };

 private func updateScoreboardsForGame(
    gameId : Text,
    userIdentifier : UserIdentifier,
    nickname : Text,
    score : Nat64,
    streak : Nat64,
    authType : AuthType
  ) {
    let t = now();
    let playerId = identifierToText(userIdentifier);
    
    // Get game's anti-cheat rules and validate score/streak before inserting into scoreboards
    let rules = getValidationRules(gameId);
    
    // Check maxScorePerRound (per-submission limit)
    switch (rules.maxScorePerRound) {
      case (?maxPerRound) {
        if (score > maxPerRound) {
          logSuspicion(playerId, gameId, "Score per round exceeded: " # Nat64.toText(score) # " > " # Nat64.toText(maxPerRound));
          return;
        };
      };
      case null {};
    };
    
    // Check absoluteScoreCap
    switch (rules.absoluteScoreCap) {
      case (?cap) {
        if (score > cap) {
          logSuspicion(playerId, gameId, "Absolute score cap exceeded: " # Nat64.toText(score) # " > " # Nat64.toText(cap));
          return;
        };
      };
      case null {};
    };
    
    // Check maxStreakDelta (per-submission limit)
    switch (rules.maxStreakDelta) {
      case (?maxDelta) {
        if (streak > maxDelta) {
          logSuspicion(playerId, gameId, "Streak delta exceeded: " # Nat64.toText(streak) # " > " # Nat64.toText(maxDelta));
          return;
        };
      };
      case null {};
    };
    
    // Check absoluteStreakCap
    switch (rules.absoluteStreakCap) {
      case (?cap) {
        if (streak > cap) {
          logSuspicion(playerId, gameId, "Absolute streak cap exceeded: " # Nat64.toText(streak) # " > " # Nat64.toText(cap));
          return;
        };
      };
      case null {};
    };
    
    // Fan-out to this game's NON-targeted boards. Targeted (category) boards are
    // written only via submitScoreToBoard, so a plain submit never pollutes them.
    for ((sbKey, config) in scoreboardConfigs.entries()) {
      let isTargeted = config.targeted == ?true;
      if (config.gameId == gameId and config.isActive and not isTargeted) {
        writeEntryToBoard(sbKey, config, userIdentifier, nickname, score, streak, authType, t);
      };
    };
  };

  private func sweepExpiredScoreboards() : async () {
  let t = now();
  
  for ((key, config) in scoreboardConfigs.entries()) {
    // Skip boards that don't have timed periods
    switch (config.period) {
      case (#allTime) {};
      case (_) {
        // Check if this board's period has elapsed
        if (Scoreboards.needsReset(config, t)) {
          
          // Only archive if there are actual entries
          let hasEntries = switch (scoreboardEntries.get(key)) {
            case (?buf) { buf.size() > 0 };
            case null { false };
          };
          
          if (hasEntries) {
            archiveScoreboard(key, config);
          };
          
          // Snap lastReset to the start of the CURRENT period
          // (skips over any empty intermediate periods)
          let newPeriodStart = calculateCurrentPeriodStart(config, t);
          
          // Update config
          scoreboardConfigs.put(key, {
            scoreboardId = config.scoreboardId;
            gameId = config.gameId;
            name = config.name;
            description = config.description;
            period = config.period;
            sortBy = config.sortBy;
            maxEntries = config.maxEntries;
            created = config.created;
            lastReset = newPeriodStart;
            isActive = config.isActive;
            targeted = config.targeted;
            resetIntervalNanos = config.resetIntervalNanos;
          });
          
          // Clear entries for the new period
          scoreboardEntries.put(key, Buffer.Buffer<ScoreEntry>(config.maxEntries));
          
          // Bust caches
          cachedScoreboards.delete(key);
          scoreboardLastUpdate.delete(key);
        };
      };
    };
  };
};

  // ════════════════════════════════════════════════════════════════════════════
  // VALIDATION - Updated to handle external users
  // ════════════════════════════════════════════════════════════════════════════

  private func validateCaller(
    msg : { caller : Principal },
    userIdType : Text,
    userId : Text
  ) : Result.Result<(), Text> {
    
    // Handle external API users
    if (userIdType == "external") {
      // External users are validated by API key at the proxy. v0.10.0: the
      // canister is directly callable, so only the proxy (VERIFIER) may use
      // this path — otherwise anyone could write as any player, keyless.
      if (not isVerifier(msg.caller)) {
        return #err("Unauthorized: external calls must go through the API");
      };
      if (not isValidExternalPlayerId(userId)) {
        return #err("Invalid external player ID. Use 1-100 alphanumeric characters, underscore, or hyphen.");
      };
      return #ok(());
    };
    
    if (userIdType == "session" or userIdType == "email") {
      switch (validateSessionInternal(userId)) {
        case (#err(e)) { return #err(e) };
        case (#ok(session)) { 
          return #ok(());
        };
      };
    };
    
    if (Principal.isAnonymous(msg.caller)) {
      return #err("Authentication required");
    };
    
    if (userIdType == "principal") {
      if (userId != Principal.toText(msg.caller)) {
        return #err("Principal mismatch");
      };
      return #ok(());
    };
    
    #err("Invalid user type")
  };
    
  func validateScore(score: Nat64, gameId: Text) : Result.Result<(), Text> {
    let rules = getValidationRules(gameId);
    
    // Check maxScorePerRound (per-submission limit)
    switch (rules.maxScorePerRound) {
      case (?maxPerRound) {
        if (score > maxPerRound) {
          return #err("Score exceeds maximum per round (" # Nat64.toText(maxPerRound) # ")");
        };
      };
      case null {};
    };
    
    // Check absoluteScoreCap
    switch (rules.absoluteScoreCap) {
      case (?cap) {
        if (score > cap) {
          return #err("Score exceeds maximum allowed (" # Nat64.toText(cap) # ")");
        };
      };
      case null {}; // No limit set, skip validation
    };
    
    #ok(())
  };
  
  func validateStreak(streak: Nat64, gameId: Text) : Result.Result<(), Text> {
    let rules = getValidationRules(gameId);
    
    // Check maxStreakDelta (per-submission limit)
    switch (rules.maxStreakDelta) {
      case (?maxDelta) {
        if (streak > maxDelta) {
          return #err("Streak exceeds maximum per round (" # Nat64.toText(maxDelta) # ")");
        };
      };
      case null {};
    };
    
    // Check absoluteStreakCap
    switch (rules.absoluteStreakCap) {
      case (?cap) {
        if (streak > cap) {
          return #err("Streak exceeds maximum allowed (" # Nat64.toText(cap) # ")");
        };
      };
      case null {}; // No limit set, skip validation
    };
    
    #ok(())
  };
  
  func validateGameId(gameId: Text) : Result.Result<(), Text> {
    switch (games.get(gameId)) {
      case null {
        #err("Game not found: " # gameId)
      };
      case (?game) {
        if (not game.isActive) {
          return #err("Game is not active");
        };
        #ok(())
      };
    }
  };

  // Check access mode for a game
  private func validateAccessMode(game : GameInfo, userIdType : Text) : Result.Result<(), Text> {
    switch (game.accessMode, userIdType) {
      case (#webOnly, "external") { 
        #err("This game only accepts web SDK submissions") 
      };
      case (#apiOnly, "principal") { 
        #err("This game only accepts API submissions") 
      };
      case (#apiOnly, "session") { 
        #err("This game only accepts API submissions") 
      };
      case (#apiOnly, "email") { 
        #err("This game only accepts API submissions") 
      };
      case _ { #ok(()) };
    }
  };

  private func getUserKeyFromAuth(
    userIdType : Text,
    userId : Text
  ) : Result.Result<Text, Text> {
    
    if (userIdType == "email" or userIdType == "session") {
      switch (validateSessionInternal(userId)) {
        case (#err(e)) { #err(e) };
        case (#ok(session)) {
          #ok(userIdType # ":" # session.email)
        };
      };
    } else if (userIdType == "principal") {
      #ok(userIdType # ":" # userId)
    } else if (userIdType == "external") {
      #ok("external:" # userId)
    } else {
      #err("Invalid user type")
    };
  };

  private func getAdminRole(caller: Principal) : ?AdminRole {
    if (caller == CONTROLLER) {
      return ?#SuperAdmin;
    };
    adminRoles.get(caller)
  };

  private func hasPermission(caller: Principal, requiredRole: AdminRole) : Bool {
    if (caller == CONTROLLER) {
      return true;
    };
    
    switch (adminRoles.get(caller)) {
      case null false;
      case (?role) {
        switch (role, requiredRole) {
          case (#SuperAdmin, _) true;
          case (#Moderator, #ReadOnly) true;
          case (#Moderator, #Support) true;
          case (#Moderator, #Moderator) true;
          case (#Support, #ReadOnly) true;
          case (#Support, #Support) true;
          case (#ReadOnly, #ReadOnly) true;
          case (_, _) false;
        }
      };
    }
  };

  private func logAction(admin: Principal, command: Text, args: [Text], success: Bool, result: Text) {
    let role = Option.get(adminRoles.get(admin), #ReadOnly);
    let action : AdminAction = {
      timestamp = now();
      admin = admin;
      adminRole = role;
      command = command;
      args = args;
      success = success;
      result = result;
      ipAddress = null;
    };
    auditLog.add(action);
    
    if (auditLog.size() > 1000) {
      auditLogStable := Array.append(auditLogStable, Buffer.toArray(auditLog));
      auditLog := Buffer.Buffer<AdminAction>(100);
    };
  };

  private func isDestructiveCommand(command: Text) : Bool {
    command == "resetAll" or 
    command == "deleteUser" or 
    command == "confirmDeleteUser" or
    command == "permanentDelete"
  };

  private func checkRateLimit(caller: Principal, command: Text) : Result.Result<(), Text> {
    if (not isDestructiveCommand(command)) {
      return #ok();
    };
    
    let key = (caller, command);
    switch (lastCommandTime.get(key)) {
      case (?lastTime) {
        let cooldown : Nat64 = 60_000_000_000;
        let timeSince = now() - lastTime;
        if (timeSince < cooldown) {
          let remaining = (cooldown - timeSince) / 1_000_000_000;
          return #err("⏱️ Rate limit: Wait " # Nat64.toText(remaining) # " more seconds");
        };
      };
      case null {};
    };
    
    lastCommandTime.put(key, now());
    #ok()
  };

  private func generateConfirmationCode(userId: Text) : Text {
    let timestamp = now();
    let hash = Text.hash(userId # Nat64.toText(timestamp));
    "DELETE-" # Nat32.toText(hash)
  };

  func checkDeleteRateLimit(caller : Principal) : Bool {
    let now = Nat64.fromNat(Int.abs(Time.now()));
    let oneHourAgo = now - (24 * 60 * 60 * 1_000_000_000);
    
    switch (deleteRateLimit.get(caller)) {
      case (?attempts) {
        let recentAttempts = Array.filter<DeletionAttempt>(attempts, func(attempt) {
          attempt.timestamp > oneHourAgo
        });
        
        if (recentAttempts.size() >= 3) {
          return false;
        };
        
        true
      };
      case null { true };
    }
  };

  func recordDeleteAttempt(caller : Principal, gameId : Text) {
    let now = Nat64.fromNat(Int.abs(Time.now()));
    let oneHourAgo = now - (60 * 60 * 1_000_000_000);
    
    let newAttempt : DeletionAttempt = {
      timestamp = now;
      gameId = gameId;
    };
    
    switch (deleteRateLimit.get(caller)) {
      case (?attempts) {
        let recentAttempts = Array.filter<DeletionAttempt>(attempts, func(attempt) {
          attempt.timestamp > oneHourAgo
        });
        let updatedAttempts = Array.append(recentAttempts, [newAttempt]);
        deleteRateLimit.put(caller, updatedAttempts);
      };
      case null {
        deleteRateLimit.put(caller, [newAttempt]);
      };
    };
  };

  // Sweeps games whose 30-day recovery window has fully expired: removes them
  // from BOTH the recovery map AND the live games map (the old version only
  // touched deletedGames and had an impossible `not canRecover` guard, so expired
  // games accumulated forever). Safe to call opportunistically from hot paths.
  // HARDENING (Oct 2026): everything keyed by gameId that outlives the GameInfo
  // record. Called when a game ID leaves the games map for good, and again when
  // an ID is registered fresh, so a re-used ID never inherits the previous
  // registration's API key, engine tag or website.
  // NOT called on soft delete: the key has to survive a recovery inside the
  // 30-day window, and an inactive game rejects submits anyway.
  // Returns how many active keys were revoked.
  private func purgeGameRemnants(gameId : Text) : Nat {
    var revoked = 0;
    label sweep loop {
      switch (ApiKeys.revokeForGame(apiKeys, gameId)) {
        case (?(key, revokedKey)) {
          apiKeys.put(key, revokedKey);
          revoked += 1;
          // One active key per game is the rule; the cap is only a guard
          // against a module change ever returning the same key twice.
          if (revoked >= 20) { break sweep };
        };
        case null { break sweep };
      };
    };
    gameEngines.delete(gameId);
    gameWebsites.delete(gameId);
    revoked
  };

  func cleanupDeletedGames() {
    let nowT = Nat64.fromNat(Int.abs(Time.now()));

    let toRemove = Buffer.Buffer<Text>(0);

    for ((gameId, deleted) in deletedGames.entries()) {
      if (nowT > deleted.permanentDeletionAt) {
        toRemove.add(gameId);
      };
    };

    for (gameId in toRemove.vals()) {
      games.delete(gameId);        // remove the (inactive) record from the live map
      deletedGames.delete(gameId); // remove the recovery record
      ignore purgeGameRemnants(gameId); // revoke its API key, clear engine/website
    };
  };

  // ════════════════════════════════════════════════════════════════════════════
  // GAME MANAGEMENT
  // ════════════════════════════════════════════════════════════════════════════

  public shared(msg) func deleteGame(gameId : Text) : async Result.Result<Text, Text> {
    if (not checkDeleteRateLimit(msg.caller)) {
      return #err("Rate limit exceeded. You can only delete 3 games per hour. Please try again later.");
    };

    // Opportunistic sweep: remove any games whose 30-day recovery window has
    // expired (both from games and deletedGames). Runs as a side effect of normal
    // activity since IC canisters can't self-schedule cron. Cheap: iterates only
    // the deletedGames map, which is small.
    cleanupDeletedGames();
    
    switch (games.get(gameId)) {
      case (?game) {
        if (game.owner != msg.caller and not isAdmin(msg.caller)) {
          return #err("Only game owner can delete this game");
        };
        
        recordDeleteAttempt(msg.caller, gameId);
        
        let nowTime = Nat64.fromNat(Int.abs(Time.now()));
        let thirtyDays : Nat64 = 30 * 24 * 60 * 60 * 1_000_000_000;
        
        let deletedGame : DeletedGame = {
          game = game;
          deletedBy = msg.caller;
          deletedAt = nowTime;
          permanentDeletionAt = nowTime + thirtyDays;
          reason = "Owner requested deletion";
          canRecover = true;
        };
        
        deletedGames.put(gameId, deletedGame);
        
        let updated : GameInfo = {
          gameId = game.gameId;
          name = game.name;
          description = game.description;
          owner = game.owner;
          gameUrl = game.gameUrl;
          created = game.created;
          accessMode = game.accessMode;
          totalPlayers = game.totalPlayers;
          totalPlays = game.totalPlays;
          isActive = false;
          maxScorePerRound = game.maxScorePerRound;
          maxStreakDelta = game.maxStreakDelta;
          absoluteScoreCap = game.absoluteScoreCap;
          absoluteStreakCap = game.absoluteStreakCap;
          timeValidationEnabled = game.timeValidationEnabled;
          minPlayDurationSecs = game.minPlayDurationSecs;
          maxScorePerSecond = game.maxScorePerSecond;
          maxSessionDurationMins = game.maxSessionDurationMins;
          googleClientIds = game.googleClientIds;
          appleBundleId = game.appleBundleId;
          appleTeamId = game.appleTeamId;
        };
        games.put(gameId, updated);
        
        trackEventInternal(
          #principal(msg.caller),
          "system",
          "game_deleted",
          [
            ("gameId", gameId),
            ("gameName", game.name),
            ("recoveryPeriod", "30 days")
          ]
        );
        
        #ok("Game deleted successfully. You can recover it within 30 days from the 'Deleted Games' section.")
      };
      case null { #err("Game not found") };
    }
  };

  public shared(msg) func recoverDeletedGame(gameId : Text) : async Result.Result<Text, Text> {
    switch (deletedGames.get(gameId)) {
      case (?deleted) {
        let nowTime = Nat64.fromNat(Int.abs(Time.now()));
        
        if (deleted.game.owner != msg.caller and not isAdmin(msg.caller)) {
          return #err("Only game owner can recover this game");
        };
        
        if (nowTime > deleted.permanentDeletionAt) {
          return #err("Recovery period expired (30 days). Game has been permanently deleted.");
        };
        
        if (not deleted.canRecover) {
          return #err("This game cannot be recovered");
        };
        
        let restored : GameInfo = {
          gameId = deleted.game.gameId;
          name = deleted.game.name;
          description = deleted.game.description;
          owner = deleted.game.owner;
          gameUrl = deleted.game.gameUrl;
          created = deleted.game.created;
          accessMode = deleted.game.accessMode;
          totalPlayers = deleted.game.totalPlayers;
          totalPlays = deleted.game.totalPlays;
          isActive = true;
          maxScorePerRound = deleted.game.maxScorePerRound;
          maxStreakDelta = deleted.game.maxStreakDelta;
          absoluteScoreCap = deleted.game.absoluteScoreCap;
          absoluteStreakCap = deleted.game.absoluteStreakCap;
          timeValidationEnabled = deleted.game.timeValidationEnabled;
          minPlayDurationSecs = deleted.game.minPlayDurationSecs;
          maxScorePerSecond = deleted.game.maxScorePerSecond;
          maxSessionDurationMins = deleted.game.maxSessionDurationMins;
          googleClientIds = deleted.game.googleClientIds;
          appleBundleId = deleted.game.appleBundleId;
          appleTeamId = deleted.game.appleTeamId;
        };
        
        games.put(gameId, restored);
        deletedGames.delete(gameId);
        
        trackEventInternal(
          #principal(msg.caller),
          "system",
          "game_recovered",
          [
            ("gameId", gameId),
            ("gameName", deleted.game.name)
          ]
        );
        
        #ok("Game recovered successfully and is now active again!")
      };
      case null { #err("Game not found in deleted games") };
    }
  };

  public query(msg) func getDeletedGames() : async [DeletedGame] {
    let buffer = Buffer.Buffer<DeletedGame>(0);
    
    for ((_, deleted) in deletedGames.entries()) {
      if (deleted.game.owner == msg.caller or isAdmin(msg.caller)) {
        buffer.add(deleted);
      };
    };
    
    Buffer.toArray(buffer)
  };

  public shared(msg) func permanentlyDeleteGame(gameId : Text) : async Result.Result<Text, Text> {
    switch (deletedGames.get(gameId)) {
      case (?deleted) {
        let nowTime = Nat64.fromNat(Int.abs(Time.now()));
        
        if (nowTime <= deleted.permanentDeletionAt and not isAdmin(msg.caller)) {
          return #err("Game can only be permanently deleted after 30 days or by super admin");
        };
        
        if (deleted.game.owner != msg.caller and not isAdmin(msg.caller)) {
          return #err("Not authorized");
        };
        
        games.delete(gameId);
        deletedGames.delete(gameId);
        ignore purgeGameRemnants(gameId);
        
        trackEventInternal(
          #principal(msg.caller),
          "system",
          "game_permanently_deleted",
          [
            ("gameId", gameId),
            ("gameName", deleted.game.name)
          ]
        );
        
        #ok("Game permanently deleted. All data has been removed.")
      };
      case null { #err("Game not found in deleted games") };
    }
  };

  public query(msg) func canDeleteGame() : async Bool {
    checkDeleteRateLimit(msg.caller)
  };

  public query(msg) func getRemainingDeleteAttempts() : async Nat {
    let nowTime = Nat64.fromNat(Int.abs(Time.now()));
    let oneHourAgo = nowTime - (60 * 60 * 1_000_000_000);
    
    switch (deleteRateLimit.get(msg.caller)) {
      case (?attempts) {
        let recentAttempts = Array.filter<DeletionAttempt>(attempts, func(attempt) {
          attempt.timestamp > oneHourAgo
        });
        
        let used = recentAttempts.size();
        if (used >= 3) { 0 } else { 3 - used }
      };
      case null { 3 };
    }
  };

  public shared(msg) func cleanupExpiredGames() : async Result.Result<Text, Text> {
    if (not isAdmin(msg.caller)) {
      return #err("Only admin can trigger cleanup");
    };
    
    let nowTime = Nat64.fromNat(Int.abs(Time.now()));
    let cleaned = Buffer.Buffer<Text>(0);
    
    for ((gameId, deleted) in deletedGames.entries()) {
      if (nowTime > deleted.permanentDeletionAt) {
        games.delete(gameId);
        deletedGames.delete(gameId);
        ignore purgeGameRemnants(gameId);
        cleaned.add(gameId);
        
        trackEventInternal(
          #principal(msg.caller),
          "system",
          "game_auto_cleanup",
          [("gameId", gameId)]
        );
      };
    };
    
    let count = cleaned.size();
    #ok("Cleaned up " # Nat.toText(count) # " expired games")
  };

  // STATS FIX 2026-08-31: one-shot repair for history. Walks LIVE entries on
  // TARGETED boards and, for every player who has no gameProfile for that
  // game, creates the 0/0 profile and counts their entries as plays. Players
  // who already have a profile are skipped entirely — submitScore counted
  // them at the time, and their targeted plays before today are
  // unrecoverable without double-count risk, so we take the honest floor.
  // IDEMPOTENT: a second run finds no missing profiles and changes nothing.
  // Pass null for all games or ?"game-id" for one.
  public shared(msg) func adminBackfillBoardStats(gameFilter : ?Text) : async Result.Result<Text, Text> {
    if (not isAdmin(msg.caller)) {
      return #err("Only admin can run the stats backfill");
    };

    // Players registered by THIS run, so their 2nd..nth board entries within
    // the same game accumulate into play_count instead of being skipped as
    // "already profiled". Key: gameId # "\n" # identifier text.
    let createdThisRun = HashMap.HashMap<Text, Bool>(64, Text.equal, Text.hash);
    let newPlayersByGame = HashMap.HashMap<Text, Nat>(16, Text.equal, Text.hash);
    let playsByGame = HashMap.HashMap<Text, Nat>(16, Text.equal, Text.hash);
    var orphanedEntries : Nat = 0;

    for ((sbKey, config) in scoreboardConfigs.entries()) {
      let inScope = switch (gameFilter) {
        case null { true };
        case (?g) { config.gameId == g };
      };
      if (inScope and config.targeted == ?true) {
        switch (games.get(config.gameId)) {
          case null {}; // orphaned config after a game deletion — nothing to credit
          case (?_) {
            switch (scoreboardEntries.get(sbKey)) {
              case null {};
              case (?entries) {
                for (entry in entries.vals()) {
                  switch (getUserByIdentifier(entry.odentifier)) {
                    case null { orphanedEntries += 1 }; // deleted account
                    case (?player) {
                      let runKey = config.gameId # "\n" # identifierToText(entry.odentifier);
                      var hasProfile = false;
                      for ((gId, _) in player.gameProfiles.vals()) {
                        if (gId == config.gameId) { hasProfile := true };
                      };
                      let createdNow = Option.isSome(createdThisRun.get(runKey));
                      if (not hasProfile or createdNow) {
                        let (bumpedProfiles, newToGame) =
                          registerBoardPlay(player, config.gameId, entry.submittedAt, true);
                        putUserByIdentifier({
                          identifier = player.identifier;
                          nickname = player.nickname;
                          authType = player.authType;
                          gameProfiles = bumpedProfiles;
                          created = player.created;
                          last_updated = player.last_updated;
                        });
                        if (newToGame) {
                          createdThisRun.put(runKey, true);
                          newPlayersByGame.put(
                            config.gameId,
                            Option.get(newPlayersByGame.get(config.gameId), 0) + 1
                          );
                        };
                        playsByGame.put(
                          config.gameId,
                          Option.get(playsByGame.get(config.gameId), 0) + 1
                        );
                      };
                    };
                  };
                };
              };
            };
          };
        };
      };
    };

    var gamesTouched : Nat = 0;
    var totalNewPlayers : Nat = 0;
    var totalPlaysAdded : Nat = 0;
    for ((gameId, plays) in playsByGame.entries()) {
      let newPlayers = Option.get(newPlayersByGame.get(gameId), 0);
      switch (games.get(gameId)) {
        case (?gameInfo) {
          games.put(gameId, updateGameStats(gameInfo, newPlayers, plays));
          gamesTouched += 1;
          totalNewPlayers += newPlayers;
          totalPlaysAdded += plays;
        };
        case null {};
      };
    };

    #ok("\u{1F527} Backfill complete: " # Nat.toText(totalNewPlayers) # " players registered, "
      # Nat.toText(totalPlaysAdded) # " plays counted across " # Nat.toText(gamesTouched)
      # " games (" # Nat.toText(orphanedEntries) # " orphaned entries skipped)")
  };

  // ═══════════════════════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════════════════
// ACCOUNT MIGRATION: Anonymous → Verified (Google/Apple/II)
// ═══════════════════════════════════════════════════════════════════════════════
// Flow:
//   1. Anonymous user plays with device ID (ext:dev_123456_abcdef)
//   2. User authenticates with Google/Apple → gets a session
//   3. SDK calls migrateAnonymousAccount(sessionId, deviceId)
//   4. Backend merges scores, achievements, play counts from anon → verified
//   5. Updates all scoreboard entries to point to new identity
//   6. Deletes the anonymous profile
//
// Authorization: Caller must have a valid session (proves they authenticated)
// The device ID is passed as a parameter — only someone on that device would know it
// ═══════════════════════════════════════════════════════════════════════════════

// Build a merged scoreboard entry from an anonymous entry + an existing verified
// entry, taking per-field maximums so a personal-best streak on anon propagates
// into the verified entry even if the verified entry has a higher score (and
// vice versa). Mirrors the submission-time merge at line ~1053 — the old
// all-or-nothing swap (keepAnon based on score alone) would silently wipe
// whichever field happened to be lower on the "winning" side.
//
// submittedAt tracks whichever field is the board's sortBy, since that's what
// affects rank ordering and tiebreaks.
private func mergeScoreEntries(
  aEntry : ScoreEntry,
  vEntry : ScoreEntry,
  newIdentifier : UserIdentifier,
  newNickname : Text,
  newAuthType : AuthType,
  sortBy : SortBy
) : ScoreEntry {
  let mergedScore : Nat64 = if (aEntry.score > vEntry.score) aEntry.score else vEntry.score;
  let mergedStreak : Nat64 = if (aEntry.streak > vEntry.streak) aEntry.streak else vEntry.streak;

  // Pick the submittedAt from whichever source owns the sort-relevant field.
  // If both are tied on the sort field, prefer the older timestamp to keep
  // existing rank position (consistent with submission-path tiebreak behaviour).
  let mergedSubmittedAt : Nat64 = switch (sortBy) {
    case (#score) {
      if (aEntry.score > vEntry.score) { aEntry.submittedAt }
      else if (vEntry.score > aEntry.score) { vEntry.submittedAt }
      else if (aEntry.submittedAt < vEntry.submittedAt) { aEntry.submittedAt }
      else { vEntry.submittedAt }
    };
    case (#streak) {
      if (aEntry.streak > vEntry.streak) { aEntry.submittedAt }
      else if (vEntry.streak > aEntry.streak) { vEntry.submittedAt }
      else if (aEntry.submittedAt < vEntry.submittedAt) { aEntry.submittedAt }
      else { vEntry.submittedAt }
    };
  };

  {
    odentifier = newIdentifier;
    nickname = newNickname;
    score = mergedScore;
    streak = mergedStreak;
    submittedAt = mergedSubmittedAt;
    authType = newAuthType;
  };
};

// Look up a scoreboard's sortBy config, defaulting to #score if config is missing
// (preserves old behaviour for any scoreboards without explicit config).
private func scoreboardSortBy(sbKey : Text) : SortBy {
  switch (scoreboardConfigs.get(sbKey)) {
    case (?cfg) { cfg.sortBy };
    case null { #score };
  };
};

public shared(msg) func migrateAnonymousAccount(
  sessionId : Text,
  deviceId : Text
) : async Result.Result<{
  message : Text;
  migratedGames : Nat;
  migratedScoreboards : Nat;
}, Text> {

  // v0.10.0: proxy-only. Possession of a deviceId is the only proof of
  // ownership, so the direct-call route is closed.
  if (not isVerifier(msg.caller)) {
    return #err("Unauthorized: account migration must go through the API");
  };

  // ── Step 1: Validate the session (proves caller is authenticated) ──
  let session = switch (validateSessionInternal(sessionId)) {
    case (#err(e)) { return #err("Authentication required: " # e) };
    case (#ok(s)) { s };
  };

  let newEmail = session.email;
  let newIdentifier : UserIdentifier = #email(newEmail);

  // ── Step 2: Find the anonymous user ──
  let anonKey = "ext:" # deviceId;
  let anonIdentifier : UserIdentifier = #email(anonKey);

  let anonUser = switch (usersByEmail.get(anonKey)) {
    case null { return #err("Anonymous account not found for device: " # deviceId) };
    case (?u) { u };
  };

  // ── Step 3: Prevent self-migration ──
  if (anonKey == newEmail) {
    return #err("Cannot migrate to the same account");
  };

  // ── Step 4: Get or create the verified user ──
  let verifiedUser = switch (usersByEmail.get(newEmail)) {
    case null {
      // Shouldn't happen if they just logged in, but handle gracefully
      return #err("Verified account not found. Please login first.");
    };
    case (?u) { u };
  };

  // ── Step 5: Merge game profiles ──
  // Strategy: For each game the anonymous user played:
  //   - If verified user also has a profile: take best score, best streak, merge achievements, add play counts
  //   - If verified user doesn't have it: copy the whole game profile over
  
  let mergedProfiles = Buffer.Buffer<(Text, GameProfile)>(
    verifiedUser.gameProfiles.size() + anonUser.gameProfiles.size()
  );

  // Start with all verified user's existing profiles
  var migratedGames : Nat = 0;

  for ((gId, verifiedGP) in verifiedUser.gameProfiles.vals()) {
    // Check if anon also has a profile for this game
    var anonGP : ?GameProfile = null;
    for ((aGId, aGP) in anonUser.gameProfiles.vals()) {
      if (aGId == gId) {
        anonGP := ?aGP;
      };
    };

    switch (anonGP) {
      case null {
        // Verified user has this game but anon doesn't — keep as-is
        mergedProfiles.add((gId, verifiedGP));
      };
      case (?aGP) {
        // Both have profiles — merge: take best scores, combine achievements
        migratedGames += 1;

        // Merge achievements (deduplicated)
        let achievementSet = Buffer.Buffer<Text>(
          verifiedGP.achievements.size() + aGP.achievements.size()
        );
        for (a in verifiedGP.achievements.vals()) {
          achievementSet.add(a);
        };
        for (a in aGP.achievements.vals()) {
          var exists = false;
          for (existing in achievementSet.vals()) {
            if (existing == a) { exists := true };
          };
          if (not exists) {
            achievementSet.add(a);
          };
        };

        let merged : GameProfile = {
          gameId = gId;
          total_score = if (aGP.total_score > verifiedGP.total_score) { aGP.total_score } else { verifiedGP.total_score };
          best_streak = if (aGP.best_streak > verifiedGP.best_streak) { aGP.best_streak } else { verifiedGP.best_streak };
          achievements = Buffer.toArray(achievementSet);
          last_played = if (aGP.last_played > verifiedGP.last_played) { aGP.last_played } else { verifiedGP.last_played };
          play_count = verifiedGP.play_count + aGP.play_count;
        };
        mergedProfiles.add((gId, merged));
      };
    };
  };

  // Add any games the anon user had that the verified user didn't
  for ((aGId, aGP) in anonUser.gameProfiles.vals()) {
    var alreadyMerged = false;
    for ((gId, _) in verifiedUser.gameProfiles.vals()) {
      if (gId == aGId) { alreadyMerged := true };
    };
    if (not alreadyMerged) {
      migratedGames += 1;
      mergedProfiles.add((aGId, aGP));
    };
  };

  // ── Step 6: Update scoreboard entries ──
  // Find all scoreboard entries that reference the anonymous identifier
  // and update them to point to the verified user
  var migratedScoreboards : Nat = 0;

  for ((sbKey, entriesBuffer) in scoreboardEntries.entries()) {
    var modified = false;

    let newBuffer = Buffer.Buffer<ScoreEntry>(entriesBuffer.size());

    // First pass: check if verified user already has an entry in this scoreboard
    var verifiedEntry : ?ScoreEntry = null;
    var verifiedIdx : ?Nat = null;
    var anonEntry : ?ScoreEntry = null;
    var idx : Nat = 0;

    for (entry in entriesBuffer.vals()) {
      if (identifiersEqual(entry.odentifier, newIdentifier)) {
        verifiedEntry := ?entry;
        verifiedIdx := ?idx;
      };
      if (identifiersEqual(entry.odentifier, anonIdentifier)) {
        anonEntry := ?entry;
      };
      idx += 1;
    };

    switch (anonEntry) {
      case null {
        // Anonymous user has no entry in this scoreboard — nothing to do
      };
      case (?aEntry) {
        modified := true;
        migratedScoreboards += 1;

        switch (verifiedEntry) {
          case null {
            // Verified user has no entry — just update the anonymous entry's identifier
            for (entry in entriesBuffer.vals()) {
              if (identifiersEqual(entry.odentifier, anonIdentifier)) {
                let updated : ScoreEntry = {
                  odentifier = newIdentifier;
                  nickname = verifiedUser.nickname;
                  score = entry.score;
                  streak = entry.streak;
                  submittedAt = entry.submittedAt;
                  authType = verifiedUser.authType;
                };
                newBuffer.add(updated);
              } else {
                newBuffer.add(entry);
              };
            };
          };
          case (?vEntry) {
            // Both have entries — merge with per-field maximums under verified
            // identity, drop the anon entry. Previously this used an all-or-nothing
            // swap based on score, which silently dropped a higher anon streak
            // whenever the verified score was higher (and vice versa).
            let mergedEntry = mergeScoreEntries(
              aEntry,
              vEntry,
              newIdentifier,
              verifiedUser.nickname,
              verifiedUser.authType,
              scoreboardSortBy(sbKey)
            );

            for (entry in entriesBuffer.vals()) {
              if (identifiersEqual(entry.odentifier, anonIdentifier)) {
                // Skip the anonymous entry (merged into the verified one below)
              } else if (identifiersEqual(entry.odentifier, newIdentifier)) {
                newBuffer.add(mergedEntry);
              } else {
                newBuffer.add(entry);
              };
            };
          };
        };

        if (modified) {
          scoreboardEntries.put(sbKey, newBuffer);
          // Invalidate cache for this scoreboard
          cachedScoreboards.delete(sbKey);
          scoreboardLastUpdate.delete(sbKey);
        };
      };
    };
  };

  // Also invalidate legacy leaderboard caches
  for ((aGId, _) in anonUser.gameProfiles.vals()) {
    cachedLeaderboards.delete(aGId # ":score");
    cachedLeaderboards.delete(aGId # ":streak");
  };

  // ── Step 7: Save the merged profile ──
  let t = now();
  let updatedVerified : UserProfile = {
    identifier = verifiedUser.identifier;
    nickname = verifiedUser.nickname;
    authType = verifiedUser.authType;
    gameProfiles = Buffer.toArray(mergedProfiles);
    created = verifiedUser.created;
    last_updated = t;
  };
  usersByEmail.put(newEmail, updatedVerified);

  // ── Step 8: Delete the anonymous profile ──
  ignore usersByEmail.remove(anonKey);

  // ── Step 9: Clean up any play sessions for the old identity ──
  let keysToRemove = Buffer.Buffer<Text>(5);
  for ((token, ps) in playSessions.entries()) {
    if (identifiersEqual(ps.identifier, anonIdentifier)) {
      keysToRemove.add(token);
    };
  };
  for (key in keysToRemove.vals()) {
    playSessions.delete(key);
  };

  // ── Step 10: Track the migration event ──
  trackEventInternal(newIdentifier, "system", "account_migrated", [
    ("from_device", deviceId),
    ("to_email", newEmail),
    ("migrated_games", Nat.toText(migratedGames)),
    ("migrated_scoreboards", Nat.toText(migratedScoreboards)),
    ("auth_type", authTypeToText(verifiedUser.authType))
  ]);

  #ok({
    message = "Account upgraded! " # Nat.toText(migratedGames) # " game(s) and " # Nat.toText(migratedScoreboards) # " scoreboard entries migrated.";
    migratedGames = migratedGames;
    migratedScoreboards = migratedScoreboards;
  })
};

// ═══════════════════════════════════════════════════════════════════════════════
// ACCOUNT MIGRATION: Anonymous → Internet Identity
// ═══════════════════════════════════════════════════════════════════════════════

public shared(msg) func migrateAnonymousToII(
  deviceId : Text
) : async Result.Result<{
  message : Text;
  migratedGames : Nat;
  migratedScoreboards : Nat;
}, Text> {

  let caller = msg.caller;

  if (Principal.isAnonymous(caller)) {
    return #err("Internet Identity authentication required");
  };

  let newIdentifier : UserIdentifier = #principal(caller);

  // Find the anonymous user
  let anonKey = "ext:" # deviceId;
  let anonIdentifier : UserIdentifier = #email(anonKey);

  let anonUser = switch (usersByEmail.get(anonKey)) {
    case null { return #err("Anonymous account not found for device: " # deviceId) };
    case (?u) { u };
  };

  // Get or create II user
  let iiUser = switch (usersByPrincipal.get(caller)) {
    case null { return #err("II account not found. Please login with Internet Identity first.") };
    case (?u) { u };
  };

  let mergedProfiles = Buffer.Buffer<(Text, GameProfile)>(
    iiUser.gameProfiles.size() + anonUser.gameProfiles.size()
  );

  var migratedGames : Nat = 0;

  for ((gId, iiGP) in iiUser.gameProfiles.vals()) {
    var anonGP : ?GameProfile = null;
    for ((aGId, aGP) in anonUser.gameProfiles.vals()) {
      if (aGId == gId) { anonGP := ?aGP };
    };

    switch (anonGP) {
      case null { mergedProfiles.add((gId, iiGP)) };
      case (?aGP) {
        migratedGames += 1;
        let achievementSet = Buffer.Buffer<Text>(iiGP.achievements.size() + aGP.achievements.size());
        for (a in iiGP.achievements.vals()) { achievementSet.add(a) };
        for (a in aGP.achievements.vals()) {
          var exists = false;
          for (existing in achievementSet.vals()) { if (existing == a) { exists := true } };
          if (not exists) { achievementSet.add(a) };
        };

        mergedProfiles.add((gId, {
          gameId = gId;
          total_score = if (aGP.total_score > iiGP.total_score) { aGP.total_score } else { iiGP.total_score };
          best_streak = if (aGP.best_streak > iiGP.best_streak) { aGP.best_streak } else { iiGP.best_streak };
          achievements = Buffer.toArray(achievementSet);
          last_played = if (aGP.last_played > iiGP.last_played) { aGP.last_played } else { iiGP.last_played };
          play_count = iiGP.play_count + aGP.play_count;
        }));
      };
    };
  };

  for ((aGId, aGP) in anonUser.gameProfiles.vals()) {
    var alreadyMerged = false;
    for ((gId, _) in iiUser.gameProfiles.vals()) {
      if (gId == aGId) { alreadyMerged := true };
    };
    if (not alreadyMerged) {
      migratedGames += 1;
      mergedProfiles.add((aGId, aGP));
    };
  };

  // ── Update scoreboard entries ──
  var migratedScoreboards : Nat = 0;

  for ((sbKey, entriesBuffer) in scoreboardEntries.entries()) {
    var anonEntry : ?ScoreEntry = null;
    var iiEntry : ?ScoreEntry = null;

    for (entry in entriesBuffer.vals()) {
      if (identifiersEqual(entry.odentifier, anonIdentifier)) { anonEntry := ?entry };
      if (identifiersEqual(entry.odentifier, newIdentifier)) { iiEntry := ?entry };
    };

    switch (anonEntry) {
      case null {};
      case (?aEntry) {
        migratedScoreboards += 1;
        let newBuffer = Buffer.Buffer<ScoreEntry>(entriesBuffer.size());

        switch (iiEntry) {
          case null {
            for (entry in entriesBuffer.vals()) {
              if (identifiersEqual(entry.odentifier, anonIdentifier)) {
                newBuffer.add({
                  odentifier = newIdentifier;
                  nickname = iiUser.nickname;
                  score = entry.score;
                  streak = entry.streak;
                  submittedAt = entry.submittedAt;
                  authType = #internetIdentity;
                });
              } else { newBuffer.add(entry) };
            };
          };
          case (?vEntry) {
            // Per-field-max merge (see mergeScoreEntries). Previously this used
            // an all-or-nothing swap based on score, which silently dropped a
            // higher anon streak whenever the II account's score was higher.
            let mergedEntry = mergeScoreEntries(
              aEntry,
              vEntry,
              newIdentifier,
              iiUser.nickname,
              #internetIdentity,
              scoreboardSortBy(sbKey)
            );
            for (entry in entriesBuffer.vals()) {
              if (identifiersEqual(entry.odentifier, anonIdentifier)) {
                // skip
              } else if (identifiersEqual(entry.odentifier, newIdentifier)) {
                newBuffer.add(mergedEntry);
              } else { newBuffer.add(entry) };
            };
          };
        };

        scoreboardEntries.put(sbKey, newBuffer);
        cachedScoreboards.delete(sbKey);
        scoreboardLastUpdate.delete(sbKey);
      };
    };
  };

  for ((aGId, _) in anonUser.gameProfiles.vals()) {
    cachedLeaderboards.delete(aGId # ":score");
    cachedLeaderboards.delete(aGId # ":streak");
  };

  // ── Save and cleanup ──
  let t = now();
  usersByPrincipal.put(caller, {
    identifier = iiUser.identifier;
    nickname = iiUser.nickname;
    authType = iiUser.authType;
    gameProfiles = Buffer.toArray(mergedProfiles);
    created = iiUser.created;
    last_updated = t;
  });

  ignore usersByEmail.remove(anonKey);

  let keysToRemove = Buffer.Buffer<Text>(5);
  for ((token, ps) in playSessions.entries()) {
    if (identifiersEqual(ps.identifier, anonIdentifier)) {
      keysToRemove.add(token);
    };
  };
  for (key in keysToRemove.vals()) { playSessions.delete(key) };

  trackEventInternal(newIdentifier, "system", "account_migrated_ii", [
    ("from_device", deviceId),
    ("to_principal", Principal.toText(caller)),
    ("migrated_games", Nat.toText(migratedGames)),
    ("migrated_scoreboards", Nat.toText(migratedScoreboards))
  ]);

  #ok({
    message = "Account upgraded to Internet Identity! " # Nat.toText(migratedGames) # " game(s) and " # Nat.toText(migratedScoreboards) # " scoreboard entries migrated.";
    migratedGames = migratedGames;
    migratedScoreboards = migratedScoreboards;
  })
};


// ═══════════════════════════════════════════════════════════════════════════════
// ADMIN: REPAIR MIGRATED STREAKS (internal helper, exposed via adminGate)
// ═══════════════════════════════════════════════════════════════════════════════
// Backfills the pre-fix migration bug where an anonymous-account's personal-best
// streak was silently dropped during link-account if the verified entry had a
// higher score. The GameProfile.best_streak merge was always correct, so we use
// the profile as the source of truth and pull any scoreboard entry's streak up
// to match. Score cannot be safely repaired this way (GameProfile.total_score is
// cumulative, not best-run), so only streak is touched.
//
// Safe to run multiple times — no-op once all entries match their profile.
// Call with dryRun=true first to preview without writing.
// ═══════════════════════════════════════════════════════════════════════════════

private func repairMigratedStreaksInternal(dryRun : Bool) : Text {
  var scoreboardsScanned : Nat = 0;
  var entriesScanned : Nat = 0;
  var entriesRepaired : Nat = 0;
  var entriesSkippedNoUser : Nat = 0;
  var entriesSkippedNoProfile : Nat = 0;
  let details = Buffer.Buffer<Text>(64);
  let cachesToInvalidate = Buffer.Buffer<Text>(16);

  for ((sbKey, entriesBuffer) in scoreboardEntries.entries()) {
    scoreboardsScanned += 1;

    // Look up the config to learn which gameId this scoreboard belongs to.
    // Without a config we can't tell which GameProfile to cross-reference, so skip.
    let gameId : Text = switch (scoreboardConfigs.get(sbKey)) {
      case (?cfg) { cfg.gameId };
      case null { "" };  // sentinel for "skip"
    };
    if (gameId == "") {
      // No config for this scoreboard — can't repair
    } else {
      let newBuffer = Buffer.Buffer<ScoreEntry>(entriesBuffer.size());
      var sbModified = false;

      for (entry in entriesBuffer.vals()) {
        entriesScanned += 1;

        // Look up the owning user by the entry's identifier
        switch (getUserByIdentifier(entry.odentifier)) {
          case null {
            // User no longer exists (deleted, pruned, etc.) — leave entry alone
            entriesSkippedNoUser += 1;
            newBuffer.add(entry);
          };
          case (?user) {
            // Find the GameProfile matching this scoreboard's gameId
            var profileStreak : ?Nat64 = null;
            for ((gId, gp) in user.gameProfiles.vals()) {
              if (gId == gameId) { profileStreak := ?gp.best_streak };
            };

            switch (profileStreak) {
              case null {
                // User has no profile for this game — leave entry alone
                entriesSkippedNoProfile += 1;
                newBuffer.add(entry);
              };
              case (?bestStreak) {
                if (bestStreak > entry.streak) {
                  // This is the repair case: profile knows a higher streak than
                  // the entry reflects, which only happens if the migration
                  // merge dropped it.
                  entriesRepaired += 1;
                  if (details.size() < 50) {
                    details.add(
                      "  • " # gameId # "/" # sbKey # ": " # entry.nickname
                      # " streak " # Nat64.toText(entry.streak)
                      # " → " # Nat64.toText(bestStreak)
                    );
                  };
                  sbModified := true;
                  newBuffer.add({
                    odentifier = entry.odentifier;
                    nickname = entry.nickname;
                    score = entry.score;
                    streak = bestStreak;
                    submittedAt = entry.submittedAt;
                    authType = entry.authType;
                  });
                } else {
                  // Entry already correct (or higher, which shouldn't happen
                  // but we leave it alone either way)
                  newBuffer.add(entry);
                };
              };
            };
          };
        };
      };

      if (sbModified and not dryRun) {
        scoreboardEntries.put(sbKey, newBuffer);
        cachesToInvalidate.add(sbKey);
      };
    };
  };

  // Invalidate caches for any scoreboards we touched. Only do this on a real
  // run — a dry-run must not have side effects.
  if (not dryRun) {
    for (sbKey in cachesToInvalidate.vals()) {
      cachedScoreboards.delete(sbKey);
      scoreboardLastUpdate.delete(sbKey);
    };
    // Also invalidate legacy leaderboard caches for any gameIds we touched
    let touchedGames = Buffer.Buffer<Text>(8);
    for (sbKey in cachesToInvalidate.vals()) {
      switch (scoreboardConfigs.get(sbKey)) {
        case (?cfg) {
          var seen = false;
          for (g in touchedGames.vals()) { if (g == cfg.gameId) { seen := true } };
          if (not seen) { touchedGames.add(cfg.gameId) };
        };
        case null {};
      };
    };
    for (gId in touchedGames.vals()) {
      cachedLeaderboards.delete(gId # ":score");
      cachedLeaderboards.delete(gId # ":streak");
    };
  };

  // Format report
  let header = if (dryRun) {
    "🧪 DRY RUN — no changes written\n"
  } else {
    "🔧 REPAIR APPLIED\n"
  };
  let verb = if (dryRun) { "would repair" } else { "repaired" };

  var report = header
    # "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
    # "Scoreboards scanned:   " # Nat.toText(scoreboardsScanned) # "\n"
    # "Entries scanned:       " # Nat.toText(entriesScanned) # "\n"
    # "Entries " # verb # ":  " # Nat.toText(entriesRepaired) # "\n"
    # "Skipped (no user):     " # Nat.toText(entriesSkippedNoUser) # "\n"
    # "Skipped (no profile):  " # Nat.toText(entriesSkippedNoProfile) # "\n";

  if (details.size() > 0) {
    report := report # "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\nChanges";
    if (entriesRepaired > 50) {
      report := report # " (first 50 of " # Nat.toText(entriesRepaired) # ")";
    };
    report := report # ":\n";
    for (line in details.vals()) {
      report := report # line # "\n";
    };
  } else {
    report := report # "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\nNo changes needed — all entries already match their profiles. ✅\n";
  };

  report
};


  // ════════════════════════════════════════════════════════════════════════════
  // UPGRADE HOOKS
  // ════════════════════════════════════════════════════════════════════════════

  system func preupgrade() {
    alternativeOriginsStable := Buffer.toArray(alternativeOrigins);
    stableUsersByEmail := Iter.toArray(usersByEmail.entries());
    stableUsersByPrincipal := Iter.toArray(usersByPrincipal.entries());
    
    // Save to V3 (current format with time validation)
    stableGamesV3 := Iter.toArray(games.entries());
    deletedGamesEntriesV3 := Iter.toArray(deletedGames.entries());
    
    // Clear old formats
    stableGames := [];
    deletedGamesEntries := [];
    stableGamesV2 := [];
    deletedGamesEntriesV2 := [];
    
    stableSessions := Iter.toArray(sessions.entries());
    stableSuspicionLog := List.toArray(suspicionLog);
    stableEntryDeletionLog := List.toArray(entryDeletionLog);
    stableAnalyticsEvents := Buffer.toArray(analyticsEvents);
    stableDailyStats := Iter.toArray(dailyStats.entries());
    stablePlayerStats := Iter.toArray(playerStats.entries());
    stableLastSubmitTime := Iter.toArray(lastSubmitTime.entries());
    sessionsEntries := Iter.toArray(sessions.entries());
    principalToSessionEntries := Iter.toArray(principalToSession.entries());
    adminRolesStable := Iter.toArray(adminRoles.entries());
    deletedUsersStable := Iter.toArray(deletedUsers.entries());
    auditLogStable := Array.append(auditLogStable, Buffer.toArray(auditLog));
    deleteRateLimitEntries := Iter.toArray(deleteRateLimit.entries());
    apiKeysStable := Iter.toArray(apiKeys.entries());
    developerTiersStable := Iter.toArray(developerTiers.entries());
    gameEnginesStable := Iter.toArray(gameEngines.entries());
    developerContactsStable := Iter.toArray(developerContacts.entries());
    gameWebsitesStable := Iter.toArray(gameWebsites.entries());
    emailOwnerIdsStable := Iter.toArray(emailOwnerIds.entries());
    
    // Scoreboards - save to V2, DO NOT clear old ones
    scoreboardConfigsStableV2 := Iter.toArray(scoreboardConfigs.entries());
    // scoreboardConfigsStable - leave unchanged!
    
    let entriesBuffer = Buffer.Buffer<(Text, [ScoreEntry])>(scoreboardEntries.size());
    for ((key, buffer) in scoreboardEntries.entries()) {
        entriesBuffer.add((key, Buffer.toArray(buffer)));
    };
    scoreboardEntriesStableV2 := Buffer.toArray(entriesBuffer);
    scoreboardArchivesStableV2 := Iter.toArray(scoreboardArchives.entries());
    
    // Play sessions
    playSessionsStable := Iter.toArray(playSessions.entries());

};

system func postupgrade() {
    // Force VERIFIER to the current source value, overriding any stale persisted
    // value from stable memory (fixes the old placeholder that survived upgrades).
    VERIFIER := Principal.fromText(VERIFIER_PRINCIPAL);
    
    usersByEmail := HashMap.HashMap<Text, UserProfile>(10, Text.equal, Text.hash);
    for ((e, prof) in stableUsersByEmail.vals()) { usersByEmail.put(e, prof) };

    usersByPrincipal := HashMap.HashMap<Principal, UserProfile>(10, Principal.equal, Principal.hash);
    for ((p, prof) in stableUsersByPrincipal.vals()) { usersByPrincipal.put(p, prof) };

    if (userIdCounter == 0) {
        let totalUsers = usersByEmail.size() + usersByPrincipal.size();
        if (totalUsers > 0) {
            userIdCounter := totalUsers;
        };
    };

    alternativeOrigins := Buffer.fromArray<Text>(alternativeOriginsStable);
    alternativeOriginsStable := [];

    games := HashMap.HashMap<Text, GameInfo>(10, Text.equal, Text.hash);
    
    // Priority: V3 (newest) > V2 (with OAuth, no time validation) > Legacy (no OAuth)
    if (stableGamesV3.size() > 0) {
        // Already in latest format
        for ((id, game) in stableGamesV3.vals()) {
            games.put(id, game);
        };
        stableGamesV3 := [];
        timeValidationMigrationDone := true;
    } else if (stableGamesV2.size() > 0) {
        // MIGRATE from V2 (has OAuth, missing time validation fields)
        for ((id, oldGame) in stableGamesV2.vals()) {
            let migratedGame : GameInfo = {
                gameId = oldGame.gameId;
                name = oldGame.name;
                description = oldGame.description;
                owner = oldGame.owner;
                gameUrl = oldGame.gameUrl;
                created = oldGame.created;
                accessMode = oldGame.accessMode;
                totalPlayers = oldGame.totalPlayers;
                totalPlays = oldGame.totalPlays;
                isActive = oldGame.isActive;
                maxScorePerRound = oldGame.maxScorePerRound;
                maxStreakDelta = oldGame.maxStreakDelta;
                absoluteScoreCap = oldGame.absoluteScoreCap;
                absoluteStreakCap = oldGame.absoluteStreakCap;
                timeValidationEnabled = false;
                minPlayDurationSecs = null;
                maxScorePerSecond = null;
                maxSessionDurationMins = null;
                googleClientIds = oldGame.googleClientIds;
                appleBundleId = oldGame.appleBundleId;
                appleTeamId = oldGame.appleTeamId;
            };
            games.put(id, migratedGame);
        };
        stableGamesV2 := [];
        timeValidationMigrationDone := true;
        oauthMigrationDone := true;
    } else if (stableGames.size() > 0) {
        // MIGRATE from legacy format (no OAuth fields)
        for ((id, oldGame) in stableGames.vals()) {
            let migratedGame : GameInfo = {
                gameId = oldGame.gameId;
                name = oldGame.name;
                description = oldGame.description;
                owner = oldGame.owner;
                gameUrl = oldGame.gameUrl;
                created = oldGame.created;
                accessMode = oldGame.accessMode;
                totalPlayers = oldGame.totalPlayers;
                totalPlays = oldGame.totalPlays;
                isActive = oldGame.isActive;
                maxScorePerRound = oldGame.maxScorePerRound;
                maxStreakDelta = oldGame.maxStreakDelta;
                absoluteScoreCap = oldGame.absoluteScoreCap;
                absoluteStreakCap = oldGame.absoluteStreakCap;
                timeValidationEnabled = false;
                minPlayDurationSecs = null;
                maxScorePerSecond = null;
                maxSessionDurationMins = null;
                googleClientIds = [];
                appleBundleId = null;
                appleTeamId = null;
            };
            games.put(id, migratedGame);
        };
        stableGames := [];
        oauthMigrationDone := true;
        timeValidationMigrationDone := true;
    };

    // Migrate deleted games - same priority order
    deletedGames := HashMap.HashMap<Text, DeletedGame>(10, Text.equal, Text.hash);
    
    if (deletedGamesEntriesV3.size() > 0) {
        // Already in latest format
        for ((id, deleted) in deletedGamesEntriesV3.vals()) {
            deletedGames.put(id, deleted);
        };
        deletedGamesEntriesV3 := [];
    } else if (deletedGamesEntriesV2.size() > 0) {
        // MIGRATE from V2 (has OAuth, missing time validation)
        for ((id, oldDeleted) in deletedGamesEntriesV2.vals()) {
            let migratedGame : GameInfo = {
                gameId = oldDeleted.game.gameId;
                name = oldDeleted.game.name;
                description = oldDeleted.game.description;
                owner = oldDeleted.game.owner;
                gameUrl = oldDeleted.game.gameUrl;
                created = oldDeleted.game.created;
                accessMode = oldDeleted.game.accessMode;
                totalPlayers = oldDeleted.game.totalPlayers;
                totalPlays = oldDeleted.game.totalPlays;
                isActive = oldDeleted.game.isActive;
                maxScorePerRound = oldDeleted.game.maxScorePerRound;
                maxStreakDelta = oldDeleted.game.maxStreakDelta;
                absoluteScoreCap = oldDeleted.game.absoluteScoreCap;
                absoluteStreakCap = oldDeleted.game.absoluteStreakCap;
                timeValidationEnabled = false;
                minPlayDurationSecs = null;
                maxScorePerSecond = null;
                maxSessionDurationMins = null;
                googleClientIds = oldDeleted.game.googleClientIds;
                appleBundleId = oldDeleted.game.appleBundleId;
                appleTeamId = oldDeleted.game.appleTeamId;
            };
            let migratedDeleted : DeletedGame = {
                game = migratedGame;
                deletedBy = oldDeleted.deletedBy;
                deletedAt = oldDeleted.deletedAt;
                permanentDeletionAt = oldDeleted.permanentDeletionAt;
                reason = oldDeleted.reason;
                canRecover = oldDeleted.canRecover;
            };
            deletedGames.put(id, migratedDeleted);
        };
        deletedGamesEntriesV2 := [];
    } else if (deletedGamesEntries.size() > 0) {
        // MIGRATE from legacy (no OAuth)
        for ((id, oldDeleted) in deletedGamesEntries.vals()) {
            let migratedGame : GameInfo = {
                gameId = oldDeleted.game.gameId;
                name = oldDeleted.game.name;
                description = oldDeleted.game.description;
                owner = oldDeleted.game.owner;
                gameUrl = oldDeleted.game.gameUrl;
                created = oldDeleted.game.created;
                accessMode = oldDeleted.game.accessMode;
                totalPlayers = oldDeleted.game.totalPlayers;
                totalPlays = oldDeleted.game.totalPlays;
                isActive = oldDeleted.game.isActive;
                maxScorePerRound = oldDeleted.game.maxScorePerRound;
                maxStreakDelta = oldDeleted.game.maxStreakDelta;
                absoluteScoreCap = oldDeleted.game.absoluteScoreCap;
                absoluteStreakCap = oldDeleted.game.absoluteStreakCap;
                timeValidationEnabled = false;
                minPlayDurationSecs = null;
                maxScorePerSecond = null;
                maxSessionDurationMins = null;
                googleClientIds = [];
                appleBundleId = null;
                appleTeamId = null;
            };
            let migratedDeleted : DeletedGame = {
                game = migratedGame;
                deletedBy = oldDeleted.deletedBy;
                deletedAt = oldDeleted.deletedAt;
                permanentDeletionAt = oldDeleted.permanentDeletionAt;
                reason = oldDeleted.reason;
                canRecover = oldDeleted.canRecover;
            };
            deletedGames.put(id, migratedDeleted);
        };
        deletedGamesEntries := [];
    };

    lastSubmitTime := HashMap.HashMap<Text, Nat64>(10, Text.equal, Text.hash);
    for ((key, time) in stableLastSubmitTime.vals()) { lastSubmitTime.put(key, time) };

    suspicionLog := List.fromArray(stableSuspicionLog);
    entryDeletionLog := List.fromArray(stableEntryDeletionLog);
    
    analyticsEvents := Buffer.fromArray<AnalyticsEvent>(stableAnalyticsEvents);
    
    dailyStats := HashMap.HashMap<Text, DailyStats>(10, Text.equal, Text.hash);
    for ((date, stats) in stableDailyStats.vals()) {
        dailyStats.put(date, stats);
    };
    
    playerStats := HashMap.HashMap<Text, PlayerStats>(10, Text.equal, Text.hash);
    for ((p, stats) in stablePlayerStats.vals()) {
        playerStats.put(p, stats);
    };

    cachedLeaderboards := HashMap.HashMap<Text, [(Text, Nat64, Nat64, Text)]>(10, Text.equal, Text.hash);
    leaderboardLastUpdate := HashMap.HashMap<Text, Nat64>(10, Text.equal, Text.hash);
    
    // v0.10.0 FIX: restore from stableSessions (stable, written by preupgrade).
    // This used to read sessionsEntries, which is `transient` and therefore
    // always [] after an upgrade, so every deploy silently logged out every
    // signed-in player and developer.
    sessions := HashMap.fromIter<Text, Session>(
        stableSessions.vals(), 10, Text.equal, Text.hash
    );
    stableSessions := [];
    principalToSession := HashMap.fromIter<Text, Text>(
        principalToSessionEntries.vals(), 10, Text.equal, Text.hash
    );
    
    sessionsEntries := [];
    principalToSessionEntries := [];
    adminRolesStable := [];
    deletedUsersStable := [];
    
    deleteRateLimit := HashMap.fromIter<Principal, [DeletionAttempt]>(
        deleteRateLimitEntries.vals(),
        10,
        Principal.equal,
        Principal.hash
    );
    
    deleteRateLimitEntries := [];

    apiKeys := HashMap.fromIter<Text, ApiKey>(apiKeysStable.vals(), 50, Text.equal, Text.hash);
    apiKeysStable := [];

    developerTiers := HashMap.fromIter<Principal, DeveloperTier>(
        developerTiersStable.vals(), 10, Principal.equal, Principal.hash
    );
    gameEngines := HashMap.fromIter<Text, Text>(gameEnginesStable.vals(), 50, Text.equal, Text.hash);
    developerContacts := HashMap.fromIter<Principal, Text>(developerContactsStable.vals(), 10, Principal.equal, Principal.hash);
    gameWebsites := HashMap.fromIter<Text, Text>(gameWebsitesStable.vals(), 50, Text.equal, Text.hash);
    emailOwnerIds := HashMap.fromIter<Text, Principal>(emailOwnerIdsStable.vals(), 100, Text.equal, Text.hash);
    seedOwnerIds(); // one-time; no-op once ownerIdsSeeded is set
    
    // Restore scoreboard configs - prefer V2, fallback to old
    let configSource = if (scoreboardConfigsStableV2.size() > 0) { 
        scoreboardConfigsStableV2 
    } else { 
        scoreboardConfigsStable 
    };
    scoreboardConfigs := HashMap.fromIter<Text, ScoreboardConfig>(
        configSource.vals(), 50, Text.equal, Text.hash
    );
    // Clear AFTER reading
    scoreboardConfigsStable := [];
    scoreboardConfigsStableV2 := [];
    
    // Restore scoreboard entries - prefer V2, fallback to old
    let entriesSource = if (scoreboardEntriesStableV2.size() > 0) {
        scoreboardEntriesStableV2
    } else {
        scoreboardEntriesStable
    };
    scoreboardEntries := HashMap.HashMap<Text, Buffer.Buffer<ScoreEntry>>(50, Text.equal, Text.hash);
    for ((key, entries) in entriesSource.vals()) {
        scoreboardEntries.put(key, Buffer.fromArray<ScoreEntry>(entries));
    };
    // Clear AFTER reading
    scoreboardEntriesStable := [];
    scoreboardEntriesStableV2 := [];
    
    // Initialize scoreboard caches
    cachedScoreboards := HashMap.HashMap<Text, [PublicScoreEntry]>(50, Text.equal, Text.hash);
    scoreboardLastUpdate := HashMap.HashMap<Text, Nat64>(50, Text.equal, Text.hash);

    let archivesSource = if (scoreboardArchivesStableV2.size() > 0) {
      scoreboardArchivesStableV2
    } else {
      scoreboardArchivesStable
    };
    scoreboardArchives := HashMap.fromIter<Text, ArchivedScoreboard>(
      archivesSource.vals(), 100, Text.equal, Text.hash
    );
    // Clear after reading
    scoreboardArchivesStable := [];
    scoreboardArchivesStableV2 := [];

    // Restore play sessions
    playSessions := HashMap.fromIter<Text, PlaySession>(
      playSessionsStable.vals(), 100, Text.equal, Text.hash
    );
    playSessionsStable := [];

    // Bootstrap SuperAdmin. REPLACE with your admin principal before deploying.
    let firstAdmin = Principal.fromText("aaaaa-aa");
    adminRoles.put(firstAdmin, #SuperAdmin);

    // Cancel any previous timer (safety for redeployments)
    switch (scoreboardTimerId) {
      case (?id) { Timer.cancelTimer(id) };
      case null {};
    };
    
    // Start recurring sweep - every hour (3600 seconds)
    scoreboardTimerId := ?Timer.recurringTimer<system>(
      #seconds(3600),
      sweepExpiredScoreboards
    );
};

  // ════════════════════════════════════════════════════════════════════════════
  // HTTP INTERFACE
  // ════════════════════════════════════════════════════════════════════════════

  // ── HTTP board reads (invocation cut: reads bypass the Netlify proxy) ───────
  // Served over the raw domain (https://<canister-id>.raw.icp0.io). Response
  // shape mirrors the Netlify proxy (api.js v1.7.1) exactly, so clients migrate
  // by swapping the base URL only:
  //   200: {"ok":true,"data":{"scoreboardId","config",
  //         "entries","totalEntries"}}
  //   4xx: {"ok":false,"error":"..."}

  // Escape user-supplied text for JSON. Nicknames are player-controlled, so
  // this is load-bearing: one quote character in a nickname would otherwise
  // break the whole board response for every consumer.
  private func escapeJson(t : Text) : Text {
    var out = "";
    for (c in t.chars()) {
      let code = Char.toNat32(c);
      if (c == '\"') { out := out # "\\\"" }
      else if (c == '\\') { out := out # "\\\\" }
      else if (c == '\n') { out := out # "\\n" }
      else if (c == '\r') { out := out # "\\r" }
      else if (c == '\t') { out := out # "\\t" }
      else if (code < 32) { out := out # " " } // drop other control chars
      else { out := out # Text.fromChar(c) };
    };
    out
  };

  // Minimal digit parser for query params (avoids Nat.fromText dependency).
  // Caller caps input length before calling.
  private func parseNatParam(t : Text) : ?Nat {
    var n : Nat = 0;
    var any = false;
    for (c in t.chars()) {
      let d = Char.toNat32(c);
      if (d >= 48 and d <= 57) {
        n := n * 10 + Nat32.toNat(d - 48);
        any := true;
      } else { return null };
    };
    if (any) { ?n } else { null }
  };

  // ── Capacity metrics (cycles / memory / map sizes) ──
  // Served at GET /metrics for the Upptime "capacity" monitor and as the
  // memStats() query for dfx. "status":"warn" flips the monitor to degraded.
  // transient: literal thresholds must not become stable (VERIFIER lesson).
  private transient let CYCLES_WARN : Nat = 5_000_000_000_000;   // 5T
  private transient let MEMORY_WARN : Nat = 1_500_000_000;       // 1.5 GB of the 3 GB wasm limit

  private func scoreboardEntryTotal() : Nat {
    var total = 0;
    for ((_, buf) in scoreboardEntries.entries()) { total += buf.size() };
    total
  };

  private func metricsSnapshot() : {
    status : Text;
    cycles : Nat;
    heapBytes : Nat;
    maxLiveBytes : Nat;
    memoryBytes : Nat;
    users : Nat;
    games : Nat;
    sessions : Nat;
    principalToSession : Nat;
    playSessions : Nat;
    lastSubmitTime : Nat;
    lastPlayCounted : Nat;
    scoreboards : Nat;
    scoreboardEntries : Nat;
    cachedScoreboards : Nat;
    cachedLeaderboards : Nat;
    scoreboardArchives : Nat;
    analyticsEvents : Nat;
    dailyStats : Nat;
    playerStats : Nat;
    suspicionLog : Nat;
    entryDeletionLog : Nat;
  } {
    let cycles = Cycles.balance();
    let memoryBytes = Prim.rts_memory_size();
    {
      status = if (cycles < CYCLES_WARN or memoryBytes > MEMORY_WARN) "warn" else "ok";
      cycles = cycles;
      heapBytes = Prim.rts_heap_size();
      maxLiveBytes = Prim.rts_max_live_size();
      memoryBytes = memoryBytes;
      users = usersByEmail.size() + usersByPrincipal.size();
      games = games.size();
      sessions = sessions.size();
      principalToSession = principalToSession.size();
      playSessions = playSessions.size();
      lastSubmitTime = lastSubmitTime.size();
      lastPlayCounted = lastPlayCounted.size();
      scoreboards = scoreboardConfigs.size();
      scoreboardEntries = scoreboardEntryTotal();
      cachedScoreboards = cachedScoreboards.size();
      cachedLeaderboards = cachedLeaderboards.size();
      scoreboardArchives = scoreboardArchives.size();
      analyticsEvents = analyticsEvents.size();
      dailyStats = dailyStats.size();
      playerStats = playerStats.size();
      suspicionLog = List.size(suspicionLog);
      entryDeletionLog = List.size(entryDeletionLog);
    }
  };

  private func metricsJson() : Text {
    let m = metricsSnapshot();
    func f(k : Text, v : Nat) : Text { "\"" # k # "\":" # Nat.toText(v) };
    "{\"status\":\"" # m.status # "\","
      # f("cycles", m.cycles) # ","
      # f("heapBytes", m.heapBytes) # ","
      # f("maxLiveBytes", m.maxLiveBytes) # ","
      # f("memoryBytes", m.memoryBytes) # ","
      # f("users", m.users) # ","
      # f("games", m.games) # ","
      # f("sessions", m.sessions) # ","
      # f("principalToSession", m.principalToSession) # ","
      # f("playSessions", m.playSessions) # ","
      # f("lastSubmitTime", m.lastSubmitTime) # ","
      # f("lastPlayCounted", m.lastPlayCounted) # ","
      # f("scoreboards", m.scoreboards) # ","
      # f("scoreboardEntries", m.scoreboardEntries) # ","
      # f("cachedScoreboards", m.cachedScoreboards) # ","
      # f("cachedLeaderboards", m.cachedLeaderboards) # ","
      # f("scoreboardArchives", m.scoreboardArchives) # ","
      # f("analyticsEvents", m.analyticsEvents) # ","
      # f("dailyStats", m.dailyStats) # ","
      # f("playerStats", m.playerStats) # ","
      # f("suspicionLog", m.suspicionLog) # ","
      # f("entryDeletionLog", m.entryDeletionLog)
      # "}"
  };

  public query func memStats() : async {
    status : Text;
    cycles : Nat;
    heapBytes : Nat;
    maxLiveBytes : Nat;
    memoryBytes : Nat;
    users : Nat;
    games : Nat;
    sessions : Nat;
    principalToSession : Nat;
    playSessions : Nat;
    lastSubmitTime : Nat;
    lastPlayCounted : Nat;
    scoreboards : Nat;
    scoreboardEntries : Nat;
    cachedScoreboards : Nat;
    cachedLeaderboards : Nat;
    scoreboardArchives : Nat;
    analyticsEvents : Nat;
    dailyStats : Nat;
    playerStats : Nat;
    suspicionLog : Nat;
    entryDeletionLog : Nat;
  } {
    metricsSnapshot()
  };

  private func httpJson(status : Nat16, body : Text) : HttpResponse {
    {
      status_code = status;
      headers = [
        ("Content-Type", "application/json"),
        ("Access-Control-Allow-Origin", "*"),
        // Keyless GETs with no custom headers are CORS "simple requests",
        // so no OPTIONS preflight handling is needed.
        ("Cache-Control", "public, max-age=30")
      ];
      body = Text.encodeUtf8(body);
      streaming_strategy = null;
    }
  };

  private func httpError(status : Nat16, message : Text) : HttpResponse {
    httpJson(status, "{\"ok\":false,\"error\":\"" # escapeJson(message) # "\"}")
  };

  private func serveScoreboardJson(gameId : Text, scoreboardId : Text, limitOpt : ?Nat) : HttpResponse {
    let key = makeScoreboardKey(gameId, scoreboardId);

    switch (scoreboardConfigs.get(key)) {
      case null {
        return httpError(404, "Scoreboard not found");
      };
      case (?config) {
        if (not config.isActive) {
          // Proxy surfaces the canister's #err as 404; mirror that.
          return httpError(404, "Scoreboard is not active");
        };

        // Mirror the proxy route's limit handling: default 100, clamp 1..1000.
        var limit : Nat = switch (limitOpt) { case null 100; case (?l) l };
        if (limit < 1) { limit := 1 };
        if (limit > 1000) { limit := 1000 };
        // Then the canister-side cap, as getScoreboard applies it.
        let cap = if (limit > config.maxEntries) { config.maxEntries } else { limit };

        // Mirror getScoreboard: expired period reads as empty; the actual
        // reset happens lazily on the next write path.
        let isExpired = switch (config.period) {
          case (#allTime) { false };
          case (#custom) { false };
          case (#daily) { Scoreboards.shouldResetDaily(config.lastReset, now()) };
          case (#weekly) { Scoreboards.shouldResetWeekly(config.lastReset, now()) };
          case (#monthly) { Scoreboards.shouldResetMonthly(config.lastReset, now()) };
        };

        let sortByText = switch (config.sortBy) { case (#score) "score"; case (#streak) "streak" };

        var entriesJson = "";
        var emitted : Nat = 0;

        if (not isExpired) {
          let buffer = switch (scoreboardEntries.get(key)) {
            case null { Buffer.Buffer<ScoreEntry>(0) };
            case (?b) { b };
          };

          let sorted = Scoreboards.sortEntries(Buffer.toArray(buffer), config.sortBy);

          label emit for (entry in sorted.vals()) {
            if (emitted >= cap) { break emit };
            if (emitted > 0) { entriesJson := entriesJson # "," };
            entriesJson := entriesJson # "{"
              # "\"rank\":" # Nat.toText(emitted + 1) # ","
              # "\"nickname\":\"" # escapeJson(entry.nickname) # "\","
              # "\"score\":" # Nat64.toText(entry.score) # ","
              # "\"streak\":" # Nat64.toText(entry.streak) # ","
              # "\"authType\":\"" # authTypeToText(entry.authType) # "\","
              # "\"submittedAt\":" # Nat64.toText(entry.submittedAt)
              # "}";
            emitted += 1;
          };
        };

        let json = "{\"ok\":true,\"data\":{"
          # "\"scoreboardId\":\"" # escapeJson(scoreboardId) # "\","
          # "\"config\":{"
            # "\"name\":\"" # escapeJson(config.name) # "\","
            # "\"description\":\"" # escapeJson(config.description) # "\","
            # "\"period\":\"" # periodToText(config.period) # "\","
            # "\"sortBy\":\"" # sortByText # "\","
            # "\"lastReset\":" # Nat64.toText(config.lastReset)
          # "},"
          # "\"entries\":[" # entriesJson # "],"
          # "\"totalEntries\":" # Nat.toText(emitted)
        # "}}";

        httpJson(200, json)
      };
    }
  };

  public query func http_request(request : HttpRequest) : async HttpResponse {
  
    if (request.url == "/.well-known/ii-alternative-origins" or 
        Text.startsWith(request.url, #text "/.well-known/ii-alternative-origins?")) {
      
      let origins = Buffer.toArray(alternativeOrigins);
      var json = "{\"alternativeOrigins\":[";
      
      var first = true;
      for (origin in origins.vals()) {
        if (not first) { json := json # "," };
        json := json # "\"" # origin # "\"";
        first := false;
      };
      json := json # "]}";
      
      return {
        status_code = 200;
        headers = [
          ("Content-Type", "application/json"),
          ("Access-Control-Allow-Origin", "*")
        ];
        body = Text.encodeUtf8(json);
        streaming_strategy = null;
      };
    };
    
    // Public board reads: GET /games/{gameId}/scoreboards/{boardId}[?limit=N]
    let urlParts = Iter.toArray(Text.split(request.url, #char '?'));
    let path = urlParts[0];
    let queryString = if (urlParts.size() > 1) { urlParts[1] } else { "" };

    // Filtering empty segments also absorbs trailing slashes
    // (community-dungeon's client requests ".../last-login/").
    let segs = Array.filter<Text>(
      Iter.toArray(Text.split(path, #char '/')),
      func(s : Text) : Bool { s != "" }
    );

    // Capacity monitor: GET /metrics
    if (segs.size() == 1 and segs[0] == "metrics") {
      return httpJson(200, metricsJson());
    };

    if (segs.size() == 4 and segs[0] == "games" and segs[2] == "scoreboards") {
      var limitOpt : ?Nat = null;
      for (param in Text.split(queryString, #char '&')) {
        let kv = Iter.toArray(Text.split(param, #char '='));
        // Length cap keeps parseNatParam from chewing absurd inputs.
        if (kv.size() == 2 and kv[0] == "limit" and Text.size(kv[1]) <= 6) {
          limitOpt := parseNatParam(kv[1]);
        };
      };
      return serveScoreboardJson(segs[1], segs[3], limitOpt);
    };

    {
      status_code = 404;
      headers = [];
      body = Text.encodeUtf8("{\"error\":\"Not found\"}");
      streaming_strategy = null;
    }
  };

  // ════════════════════════════════════════════════════════════════════════════
  // GAME REGISTRATION - Updated with accessMode
  // ════════════════════════════════════════════════════════════════════════════

  // ═══════════════════════════════════════════════════════════════════════════════
// COMPLETE GAME MANAGEMENT FUNCTIONS - With OAuth Fields
// Replace your existing game management functions with these
// ═══════════════════════════════════════════════════════════════════════════════

  // ── Game metadata limits ──
  // transient: in a persistent actor, plain top-level lets become STABLE and
  // future literal edits would be silently ignored on upgrade (VERIFIER lesson).
  private transient let MAX_GAME_NAME_LENGTH : Nat = 50;
  private transient let MAX_GAME_DESCRIPTION_LENGTH : Nat = 200;

  // Silently clamp over-long metadata instead of rejecting, so dashboard
  // edits of grandfathered games (which resend the old long description)
  // keep working and REST callers can't stuff junk into stable memory.
  private func clampText(t : Text, max : Nat) : Text {
    if (Text.size(t) <= max) { return t };
    var out = "";
    var i = 0;
    label take for (c in t.chars()) {
      if (i >= max) { break take };
      out := out # Text.fromChar(c);
      i += 1;
    };
    out
  };

  // ── Game URL validation (release A, 30 Sep 2026) ──
  // players.html renders gameUrl as a public link and updateGame feeds it into
  // alternativeOrigins, so it's rejected (not clamped) when it isn't a plain
  // https:// URL. Empty/whitespace becomes null so "clear the field" works.
  private transient let MAX_GAME_URL_LENGTH : Nat = 200;

  private func sanitizeGameUrl(url : ?Text) : Result.Result<?Text, Text> {
    switch (url) {
      case null { #ok(null) };
      case (?raw) {
        let u = Text.trim(raw, #predicate(func(c : Char) : Bool { c == ' ' or c == '\t' or c == '\n' or c == '\r' }));
        if (Text.size(u) == 0) { return #ok(null) };
        if (not Text.startsWith(u, #text "https://")) {
          return #err("Game URL must start with https://");
        };
        if (Text.size(u) > MAX_GAME_URL_LENGTH) {
          return #err("Game URL too long (max " # Nat.toText(MAX_GAME_URL_LENGTH) # " characters)");
        };
        if (Text.size(u) <= 8) {
          return #err("Game URL is missing a host");
        };
        for (c in u.chars()) {
          if (c == ' ' or c == '\"' or c == '\'' or c == '<' or c == '>' or c == '\\' or Char.toNat32(c) < 32) {
            return #err("Game URL contains invalid characters");
          };
        };
        #ok(?u)
      };
    }
  };

public shared(msg) func registerGame(
    gameId: Text, 
    name: Text, 
    description: Text,
    maxScorePerRound: ?Nat64,
    maxStreakDelta: ?Nat64,
    absoluteScoreCap: ?Nat64,
    absoluteStreakCap: ?Nat64,
    gameUrlRaw: ?Text,
    accessMode: ?AccessMode
  ) : async Result.Result<Text, Text> {
    let gameUrl : ?Text = switch (sanitizeGameUrl(gameUrlRaw)) {
      case (#err(e)) { return #err(e) };
      case (#ok(u)) { u };
    };
    
    if (Principal.isAnonymous(msg.caller)) {
      return #err("❌ Must authenticate with Internet Identity to register a game");
    };
    
    if (Text.size(gameId) < 3 or Text.size(gameId) > 50) {
      return #err("Game ID must be 3-50 characters");
    };
    
    switch (games.get(gameId)) {
      case (?existing) {
        if (existing.owner == msg.caller) {
          #ok("You already own this game")
        } else {
          #err("Game ID already taken by another developer")
        }
      };
      case null {
        // Charset rule enforced on NEW registrations only, so pre-existing
        // mixed-case IDs (e.g. Bullet-Candy) are grandfathered: they never
        // reach this branch and keep resolving via the ?existing case above.
        if (not isValidGameId(gameId)) {
          return #err("Invalid game ID format. Use lowercase letters, numbers, and hyphens only.");
        };
        
        let currentGameCount = countGamesByOwner(msg.caller);
        let maxGames = getMaxGamesForDeveloper(msg.caller);
        
        if (currentGameCount >= maxGames and not isAdmin(msg.caller)) {
          return #err("🚫 Maximum " # Nat.toText(maxGames) # " games per developer. You currently have " # Nat.toText(currentGameCount) # " games registered.");
        };
        
        let gameInfo : GameInfo = {
          gameId = gameId;
          name = clampText(name, MAX_GAME_NAME_LENGTH);
          description = clampText(description, MAX_GAME_DESCRIPTION_LENGTH);
          owner = msg.caller;
          gameUrl = gameUrl;
          created = now();
          accessMode = Option.get(accessMode, #both);
          totalPlayers = 0;
          totalPlays = 0;
          isActive = true;
          maxScorePerRound = maxScorePerRound;
          maxStreakDelta = maxStreakDelta;
          absoluteScoreCap = absoluteScoreCap;
          absoluteStreakCap = absoluteStreakCap;
          timeValidationEnabled = false;
          minPlayDurationSecs = null;
          maxScorePerSecond = null;
          maxSessionDurationMins = null;
          googleClientIds = [];
          appleBundleId = null;
          appleTeamId = null;
        };
        // A fresh registration starts clean: revoke any key (and clear any
        // engine/website) left behind by an earlier game with this ID.
        ignore purgeGameRemnants(gameId);
        games.put(gameId, gameInfo);
        
        // Create default scoreboards (all-time, weekly and daily)
        createDefaultScoreboards(gameId, msg.caller);
        
        switch(gameUrl) {
          case(?url) {
            if (Text.startsWith(url, #text("https://"))) {
              let exists = Buffer.contains<Text>(alternativeOrigins, url, Text.equal);
              if (not exists) {
                alternativeOrigins.add(url);
              };
            };
          };
          case(null) {};
        };
        
        trackEventInternal(#principal(msg.caller), gameId, "game_registered", [
          ("game_name", name),
          ("game_id", gameId),
          ("access_mode", accessModeToText(Option.get(accessMode, #both))),
          ("total_games", Nat.toText(currentGameCount + 1))
        ]);
        
        #ok("✅ Game '" # name # "' registered successfully! (" # Nat.toText(currentGameCount + 1) # "/" # Nat.toText(maxGames) # " games) Default scoreboards created: all-time, weekly, daily")
      };
    }
  };

  public shared(msg) func updateGame(
    gameId : Text, 
    name : Text, 
    description : Text,
    gameUrlRaw : ?Text
  ) : async Result.Result<Text, Text> {
    let gameUrl : ?Text = switch (sanitizeGameUrl(gameUrlRaw)) {
      case (#err(e)) { return #err(e) };
      case (#ok(u)) { u };
    };
    switch (games.get(gameId)) {
      case (?game) {
        if (game.owner != msg.caller and not isAdmin(msg.caller)) {
          return #err("Only game owner can update");
        };
        
        switch(game.gameUrl) {
          case(?oldUrl) {
            switch(gameUrl) {
              case(?newUrl) {
                if (oldUrl != newUrl) {
                  let newOrigins = Buffer.Buffer<Text>(alternativeOrigins.size());
                  for (url in alternativeOrigins.vals()) {
                    if (url != oldUrl) {
                      newOrigins.add(url);
                    };
                  };
                  alternativeOrigins := newOrigins;
                  if (Text.startsWith(newUrl, #text("https://"))) {
                    let exists = Buffer.contains<Text>(alternativeOrigins, newUrl, Text.equal);
                    if (not exists) {
                      alternativeOrigins.add(newUrl);
                    };
                  };
                };
              };
              case(null) {
                let newOrigins = Buffer.Buffer<Text>(alternativeOrigins.size());
                for (url in alternativeOrigins.vals()) {
                  if (url != oldUrl) {
                    newOrigins.add(url);
                  };
                };
                alternativeOrigins := newOrigins;
              };
            };
          };
          case(null) {
            switch(gameUrl) {
              case(?newUrl) {
                if (Text.startsWith(newUrl, #text("https://"))) {
                  let exists = Buffer.contains<Text>(alternativeOrigins, newUrl, Text.equal);
                  if (not exists) {
                    alternativeOrigins.add(newUrl);
                  };
                };
              };
              case(null) {};
            };
          };
        };
        
        let updated : GameInfo = {
          gameId = game.gameId;
          name = clampText(name, MAX_GAME_NAME_LENGTH);
          description = clampText(description, MAX_GAME_DESCRIPTION_LENGTH);
          owner = game.owner;
          gameUrl = gameUrl;
          created = game.created;
          accessMode = game.accessMode;
          totalPlayers = game.totalPlayers;
          totalPlays = game.totalPlays;
          isActive = game.isActive;
          maxScorePerRound = game.maxScorePerRound;
          maxStreakDelta = game.maxStreakDelta;
          absoluteScoreCap = game.absoluteScoreCap;
          absoluteStreakCap = game.absoluteStreakCap;
          timeValidationEnabled = game.timeValidationEnabled;
          minPlayDurationSecs = game.minPlayDurationSecs;
          maxScorePerSecond = game.maxScorePerSecond;
          maxSessionDurationMins = game.maxSessionDurationMins;
          googleClientIds = game.googleClientIds;
          appleBundleId = game.appleBundleId;
          appleTeamId = game.appleTeamId;
        };
        games.put(gameId, updated);
        #ok("Game updated")
      };
      case null { #err("Game not found") };
    }
  };

  public shared(msg) func updateGameAccessMode(
    gameId : Text,
    newAccessMode : AccessMode
  ) : async Result.Result<Text, Text> {
    switch (games.get(gameId)) {
      case (?game) {
        if (game.owner != msg.caller and not isAdmin(msg.caller)) {
          return #err("Only game owner can update access mode");
        };
        
        let updated : GameInfo = {
          gameId = game.gameId;
          name = game.name;
          description = game.description;
          owner = game.owner;
          gameUrl = game.gameUrl;
          created = game.created;
          accessMode = newAccessMode;
          totalPlayers = game.totalPlayers;
          totalPlays = game.totalPlays;
          isActive = game.isActive;
          maxScorePerRound = game.maxScorePerRound;
          maxStreakDelta = game.maxStreakDelta;
          absoluteScoreCap = game.absoluteScoreCap;
          absoluteStreakCap = game.absoluteStreakCap;
          timeValidationEnabled = game.timeValidationEnabled;
          minPlayDurationSecs = game.minPlayDurationSecs;
          maxScorePerSecond = game.maxScorePerSecond;
          maxSessionDurationMins = game.maxSessionDurationMins;
          googleClientIds = game.googleClientIds;
          appleBundleId = game.appleBundleId;
          appleTeamId = game.appleTeamId;
        };
        games.put(gameId, updated);
        #ok("Access mode updated to " # accessModeToText(newAccessMode))
      };
      case null { #err("Game not found") };
    }
  };

  public shared(msg) func updateGameRules(
    gameId : Text,
    maxScorePerRound : ?Nat64,
    maxStreakDelta : ?Nat64,
    absoluteScoreCap : ?Nat64,
    absoluteStreakCap : ?Nat64
  ) : async Result.Result<Text, Text> {
    switch (games.get(gameId)) {
      case (?game) {
        if (game.owner != msg.caller and not isAdmin(msg.caller)) {
          return #err("Only game owner can update rules");
        };
        
        let updated : GameInfo = {
          gameId = game.gameId;
          name = game.name;
          description = game.description;
          owner = game.owner;
          gameUrl = game.gameUrl;
          created = game.created;
          accessMode = game.accessMode;
          totalPlayers = game.totalPlayers;
          totalPlays = game.totalPlays;
          isActive = game.isActive;
          maxScorePerRound = maxScorePerRound;
          maxStreakDelta = maxStreakDelta;
          absoluteScoreCap = absoluteScoreCap;
          absoluteStreakCap = absoluteStreakCap;
          timeValidationEnabled = game.timeValidationEnabled;
          minPlayDurationSecs = game.minPlayDurationSecs;
          maxScorePerSecond = game.maxScorePerSecond;
          maxSessionDurationMins = game.maxSessionDurationMins;
          googleClientIds = game.googleClientIds;
          appleBundleId = game.appleBundleId;
          appleTeamId = game.appleTeamId;
        };
        games.put(gameId, updated);
        #ok("Game rules updated")
      };
      case null { #err("Game not found") };
    }
  };

  public shared(msg) func toggleGameActive(gameId : Text) : async Result.Result<Text, Text> {
    switch (games.get(gameId)) {
      case (?game) {
        if (game.owner != msg.caller and not isAdmin(msg.caller)) {
          return #err("Only game owner can toggle");
        };
        
        let updated : GameInfo = {
          gameId = game.gameId;
          name = game.name;
          description = game.description;
          owner = game.owner;
          gameUrl = game.gameUrl;
          created = game.created;
          accessMode = game.accessMode;
          totalPlayers = game.totalPlayers;
          totalPlays = game.totalPlays;
          isActive = not game.isActive;
          maxScorePerRound = game.maxScorePerRound;
          maxStreakDelta = game.maxStreakDelta;
          absoluteScoreCap = game.absoluteScoreCap;
          absoluteStreakCap = game.absoluteStreakCap;
          timeValidationEnabled = game.timeValidationEnabled;
          minPlayDurationSecs = game.minPlayDurationSecs;
          maxScorePerSecond = game.maxScorePerSecond;
          maxSessionDurationMins = game.maxSessionDurationMins;
          googleClientIds = game.googleClientIds;
          appleBundleId = game.appleBundleId;
          appleTeamId = game.appleTeamId;
        };
        games.put(gameId, updated);
        #ok("Game " # (if (updated.isActive) "activated" else "deactivated"))
      };
      case null { #err("Game not found") };
    }
  };

  // ═══════════════════════════════════════════════════════════════════════════════
  // OAUTH CREDENTIAL MANAGEMENT
  // ═══════════════════════════════════════════════════════════════════════════════

  public shared(msg) func setGameGoogleCredentials(
    gameId : Text,
    clientIds : [Text]
  ) : async Result.Result<Text, Text> {
    switch (games.get(gameId)) {
      case null { #err("Game not found") };
      case (?game) {
        if (game.owner != msg.caller and not isAdmin(msg.caller)) {
          return #err("Only game owner can update OAuth credentials");
        };
        
        for (clientId in clientIds.vals()) {
          if (not Text.endsWith(clientId, #text ".apps.googleusercontent.com")) {
            return #err("Invalid Google client ID format: " # clientId);
          };
        };
        
        let updated : GameInfo = {
          gameId = game.gameId;
          name = game.name;
          description = game.description;
          owner = game.owner;
          gameUrl = game.gameUrl;
          created = game.created;
          accessMode = game.accessMode;
          totalPlayers = game.totalPlayers;
          totalPlays = game.totalPlays;
          isActive = game.isActive;
          maxScorePerRound = game.maxScorePerRound;
          maxStreakDelta = game.maxStreakDelta;
          absoluteScoreCap = game.absoluteScoreCap;
          absoluteStreakCap = game.absoluteStreakCap;
          timeValidationEnabled = game.timeValidationEnabled;
          minPlayDurationSecs = game.minPlayDurationSecs;
          maxScorePerSecond = game.maxScorePerSecond;
          maxSessionDurationMins = game.maxSessionDurationMins;
          googleClientIds = clientIds;
          appleBundleId = game.appleBundleId;
          appleTeamId = game.appleTeamId;
        };
        games.put(gameId, updated);
        
        trackEventInternal(#principal(msg.caller), gameId, "oauth_google_configured", [
          ("client_count", Nat.toText(clientIds.size()))
        ]);
        
        #ok("Google OAuth configured with " # Nat.toText(clientIds.size()) # " client ID(s)")
      };
    }
  };

  public shared(msg) func setGameAppleCredentials(
    gameId : Text,
    bundleId : Text,
    teamId : ?Text
  ) : async Result.Result<Text, Text> {
    switch (games.get(gameId)) {
      case null { #err("Game not found") };
      case (?game) {
        if (game.owner != msg.caller and not isAdmin(msg.caller)) {
          return #err("Only game owner can update OAuth credentials");
        };
        
        if (Text.size(bundleId) < 3 or not Text.contains(bundleId, #char '.')) {
          return #err("Invalid bundle ID format. Expected: com.company.appname");
        };
        
        let updated : GameInfo = {
          gameId = game.gameId;
          name = game.name;
          description = game.description;
          owner = game.owner;
          gameUrl = game.gameUrl;
          created = game.created;
          accessMode = game.accessMode;
          totalPlayers = game.totalPlayers;
          totalPlays = game.totalPlays;
          isActive = game.isActive;
          maxScorePerRound = game.maxScorePerRound;
          maxStreakDelta = game.maxStreakDelta;
          absoluteScoreCap = game.absoluteScoreCap;
          absoluteStreakCap = game.absoluteStreakCap;
          timeValidationEnabled = game.timeValidationEnabled;
          minPlayDurationSecs = game.minPlayDurationSecs;
          maxScorePerSecond = game.maxScorePerSecond;
          maxSessionDurationMins = game.maxSessionDurationMins;
          googleClientIds = game.googleClientIds;
          appleBundleId = ?bundleId;
          appleTeamId = teamId;
        };
        games.put(gameId, updated);
        
        trackEventInternal(#principal(msg.caller), gameId, "oauth_apple_configured", [
          ("bundle_id", bundleId)
        ]);
        
        #ok("Apple Sign-In configured for " # bundleId)
      };
    }
  };

  public query func getGameOAuthConfig(gameId : Text) : async ?{
    googleClientIds : [Text];
    appleBundleId : ?Text;
    appleTeamId : ?Text;
    nativeAuthEnabled : Bool;
  } {
    switch (games.get(gameId)) {
      case null { null };
      case (?game) {
        let hasGoogle = game.googleClientIds.size() > 0;
        let hasApple = Option.isSome(game.appleBundleId);
        
        ?{
          googleClientIds = game.googleClientIds;
          appleBundleId = game.appleBundleId;
          appleTeamId = game.appleTeamId;
          nativeAuthEnabled = hasGoogle or hasApple;
        }
      };
    }
  };

  public shared(msg) func clearGameOAuthCredentials(
    gameId : Text,
    provider : Text
  ) : async Result.Result<Text, Text> {
    switch (games.get(gameId)) {
      case null { #err("Game not found") };
      case (?game) {
        if (game.owner != msg.caller and not isAdmin(msg.caller)) {
          return #err("Only game owner can clear OAuth credentials");
        };
        
        let (newGoogle, newApple, newTeam) = switch (provider) {
          case ("google") { ([], game.appleBundleId, game.appleTeamId) };
          case ("apple") { (game.googleClientIds, null, null) };
          case ("all") { ([], null, null) };
          case (_) { return #err("Invalid provider. Use: google, apple, or all") };
        };
        
        let updated : GameInfo = {
          gameId = game.gameId;
          name = game.name;
          description = game.description;
          owner = game.owner;
          gameUrl = game.gameUrl;
          created = game.created;
          accessMode = game.accessMode;
          totalPlayers = game.totalPlayers;
          totalPlays = game.totalPlays;
          isActive = game.isActive;
          maxScorePerRound = game.maxScorePerRound;
          maxStreakDelta = game.maxStreakDelta;
          absoluteScoreCap = game.absoluteScoreCap;
          absoluteStreakCap = game.absoluteStreakCap;
          timeValidationEnabled = game.timeValidationEnabled;
          minPlayDurationSecs = game.minPlayDurationSecs;
          maxScorePerSecond = game.maxScorePerSecond;
          maxSessionDurationMins = game.maxSessionDurationMins;
          googleClientIds = newGoogle;
          appleBundleId = newApple;
          appleTeamId = newTeam;
        };
        games.put(gameId, updated);
        
        #ok("OAuth credentials cleared for: " # provider)
      };
    }
  };

  // ═══════════════════════════════════════════════════════════════════════════════
  // SESSION-BASED VERSIONS (for dashboard)
  // ═══════════════════════════════════════════════════════════════════════════════

  public shared func setGameGoogleCredentialsBySession(
    sessionId : Text,
    gameId : Text,
    clientIds : [Text]
  ) : async Result.Result<Text, Text> {
    switch (getOwnerFromSession(sessionId)) {
      case (#err(e)) { #err(e) };
      case (#ok(owner)) {
        switch (games.get(gameId)) {
          case null { #err("Game not found") };
          case (?game) {
            if (not Principal.equal(game.owner, owner)) {
              return #err("You don't own this game");
            };
            
            for (clientId in clientIds.vals()) {
              if (not Text.endsWith(clientId, #text ".apps.googleusercontent.com")) {
                return #err("Invalid Google client ID: " # clientId);
              };
            };
            
            let updated : GameInfo = {
              gameId = game.gameId;
              name = game.name;
              description = game.description;
              owner = game.owner;
              gameUrl = game.gameUrl;
              created = game.created;
              accessMode = game.accessMode;
              totalPlayers = game.totalPlayers;
              totalPlays = game.totalPlays;
              isActive = game.isActive;
              maxScorePerRound = game.maxScorePerRound;
              maxStreakDelta = game.maxStreakDelta;
              absoluteScoreCap = game.absoluteScoreCap;
              absoluteStreakCap = game.absoluteStreakCap;
          timeValidationEnabled = game.timeValidationEnabled;
          minPlayDurationSecs = game.minPlayDurationSecs;
          maxScorePerSecond = game.maxScorePerSecond;
          maxSessionDurationMins = game.maxSessionDurationMins;
          googleClientIds = clientIds;
              appleBundleId = game.appleBundleId;
              appleTeamId = game.appleTeamId;
            };
            games.put(gameId, updated);
            
            trackEventInternal(#principal(owner), gameId, "oauth_google_configured", [
              ("client_count", Nat.toText(clientIds.size()))
            ]);
            
            #ok("Google OAuth configured")
          };
        };
      };
    };
  };

  public shared func setGameAppleCredentialsBySession(
    sessionId : Text,
    gameId : Text,
    bundleId : Text,
    teamId : ?Text
  ) : async Result.Result<Text, Text> {
    switch (getOwnerFromSession(sessionId)) {
      case (#err(e)) { #err(e) };
      case (#ok(owner)) {
        switch (games.get(gameId)) {
          case null { #err("Game not found") };
          case (?game) {
            if (not Principal.equal(game.owner, owner)) {
              return #err("You don't own this game");
            };
            
            if (Text.size(bundleId) < 3 or not Text.contains(bundleId, #char '.')) {
              return #err("Invalid bundle ID format");
            };
            
            let updated : GameInfo = {
              gameId = game.gameId;
              name = game.name;
              description = game.description;
              owner = game.owner;
              gameUrl = game.gameUrl;
              created = game.created;
              accessMode = game.accessMode;
              totalPlayers = game.totalPlayers;
              totalPlays = game.totalPlays;
              isActive = game.isActive;
              maxScorePerRound = game.maxScorePerRound;
              maxStreakDelta = game.maxStreakDelta;
              absoluteScoreCap = game.absoluteScoreCap;
              absoluteStreakCap = game.absoluteStreakCap;
          timeValidationEnabled = game.timeValidationEnabled;
          minPlayDurationSecs = game.minPlayDurationSecs;
          maxScorePerSecond = game.maxScorePerSecond;
          maxSessionDurationMins = game.maxSessionDurationMins;
          googleClientIds = game.googleClientIds;
              appleBundleId = ?bundleId;
              appleTeamId = teamId;
            };
            games.put(gameId, updated);
            
            trackEventInternal(#principal(owner), gameId, "oauth_apple_configured", [
              ("bundle_id", bundleId)
            ]);
            
            #ok("Apple Sign-In configured")
          };
        };
      };
    };
  };

  public query func getGameOAuthConfigBySession(sessionId : Text, gameId : Text) : async Result.Result<{
    googleClientIds : [Text];
    appleBundleId : ?Text;
    appleTeamId : ?Text;
    googleConfigured : Bool;
    appleConfigured : Bool;
  }, Text> {
    switch (getValidSession(sessionId)) {
      case null { #err("Invalid session") };
      case (?session) {
        let owner = ownerIdOrNobody(session.email);
        
        switch (games.get(gameId)) {
          case null { #err("Game not found") };
          case (?game) {
            if (not Principal.equal(game.owner, owner)) {
              return #err("You don't own this game");
            };
            
            #ok({
          googleClientIds = game.googleClientIds;
              appleBundleId = game.appleBundleId;
              appleTeamId = game.appleTeamId;
              googleConfigured = game.googleClientIds.size() > 0;
              appleConfigured = Option.isSome(game.appleBundleId);
            })
          };
        };
      };
    };
  };

  public shared func clearGameOAuthCredentialsBySession(
    sessionId : Text,
    gameId : Text,
    provider : Text
  ) : async Result.Result<Text, Text> {
    switch (getOwnerFromSession(sessionId)) {
      case (#err(e)) { #err(e) };
      case (#ok(owner)) {
        switch (games.get(gameId)) {
          case null { #err("Game not found") };
          case (?game) {
            if (not Principal.equal(game.owner, owner)) {
              return #err("You don't own this game");
            };
            
            let (newGoogle, newApple, newTeam) = switch (provider) {
              case ("google") { ([], game.appleBundleId, game.appleTeamId) };
              case ("apple") { (game.googleClientIds, null, null) };
              case ("all") { ([], null, null) };
              case (_) { return #err("Invalid provider. Use: google, apple, or all") };
            };
            
            let updated : GameInfo = {
              gameId = game.gameId;
              name = game.name;
              description = game.description;
              owner = game.owner;
              gameUrl = game.gameUrl;
              created = game.created;
              accessMode = game.accessMode;
              totalPlayers = game.totalPlayers;
              totalPlays = game.totalPlays;
              isActive = game.isActive;
              maxScorePerRound = game.maxScorePerRound;
              maxStreakDelta = game.maxStreakDelta;
              absoluteScoreCap = game.absoluteScoreCap;
              absoluteStreakCap = game.absoluteStreakCap;
          timeValidationEnabled = game.timeValidationEnabled;
          minPlayDurationSecs = game.minPlayDurationSecs;
          maxScorePerSecond = game.maxScorePerSecond;
          maxSessionDurationMins = game.maxSessionDurationMins;
          googleClientIds = newGoogle;
              appleBundleId = newApple;
              appleTeamId = newTeam;
            };
            games.put(gameId, updated);
            
            #ok("OAuth credentials cleared for: " # provider)
          };
        };
      };
    };
  };

  // ═══════════════════════════════════════════════════════════════════════════════
  // UPDATE registerGameBySession TO INCLUDE OAUTH FIELDS
  // ═══════════════════════════════════════════════════════════════════════════════

  public shared func registerGameBySession(
    sessionId: Text,
    gameId: Text,
    name: Text,
    description: Text,
    maxScorePerRound: ?Nat64,
    maxStreakDelta: ?Nat64,
    absoluteScoreCap: ?Nat64,
    absoluteStreakCap: ?Nat64,
    gameUrlRaw: ?Text
  ) : async Result.Result<Text, Text> {
    let gameUrl : ?Text = switch (sanitizeGameUrl(gameUrlRaw)) {
      case (#err(e)) { return #err(e) };
      case (#ok(u)) { u };
    };
    switch (getOwnerFromSession(sessionId)) {
      case (#err(e)) { return #err(e) };
      case (#ok(owner)) {
        
        if (not isValidGameId(gameId)) {
          return #err("Invalid game ID format. Use lowercase letters, numbers, and hyphens only.");
        };
        
        switch (games.get(gameId)) {
          case (?_) { return #err("Game ID already exists") };
          case null {};
        };
        
        let ownerGames = getGameCountByOwner(owner);
        let maxGames = getMaxGamesForDeveloper(owner);
        
        if (ownerGames >= maxGames) {
          let upgradeMsg = if (maxGames == 3) { " Upgrade to Pro for 10 slots!" } else { "" };
          return #err("Maximum " # Nat.toText(maxGames) # " games reached." # upgradeMsg # " Delete a game to register a new one.");
        };
        
        let currentTime = Nat64.fromNat(Int.abs(Time.now()));
        
        let newGame : GameInfo = {
          gameId = gameId;
          name = clampText(name, MAX_GAME_NAME_LENGTH);
          description = clampText(description, MAX_GAME_DESCRIPTION_LENGTH);
          owner = owner;
          gameUrl = gameUrl;
          created = currentTime;
          accessMode = #both;
          totalPlayers = 0;
          totalPlays = 0;
          isActive = true;
          maxScorePerRound = maxScorePerRound;
          maxStreakDelta = maxStreakDelta;
          absoluteScoreCap = absoluteScoreCap;
          absoluteStreakCap = absoluteStreakCap;
          timeValidationEnabled = false;
          minPlayDurationSecs = null;
          maxScorePerSecond = null;
          maxSessionDurationMins = null;
          googleClientIds = [];
          appleBundleId = null;
          appleTeamId = null;
        };
        
        // A fresh registration starts clean: revoke any key (and clear any
        // engine/website) left behind by an earlier game with this ID.
        ignore purgeGameRemnants(gameId);
        games.put(gameId, newGame);
        
        // Create default scoreboards (all-time, weekly and daily)
        createDefaultScoreboards(gameId, owner);
        
        trackEventInternal(#principal(owner), gameId, "game_registered", [
          ("game_name", name),
          ("game_id", gameId)
        ]);
        
        #ok("Game '" # name # "' registered successfully! (" # Nat.toText(ownerGames + 1) # "/" # Nat.toText(maxGames) # " games) Default scoreboards created: all-time, weekly, daily")
      };
    };
  };

  
  // ═══════════════════════════════════════════════════════════════════════════════
  // UPDATE updateGameBySession TO INCLUDE OAUTH FIELDS
  // ═══════════════════════════════════════════════════════════════════════════════

  public shared func updateGameBySession(
    sessionId: Text,
    gameId: Text,
    name: Text,
    description: Text,
    gameUrlRaw: ?Text
  ) : async Result.Result<Text, Text> {
    let gameUrl : ?Text = switch (sanitizeGameUrl(gameUrlRaw)) {
      case (#err(e)) { return #err(e) };
      case (#ok(u)) { u };
    };
    switch (getOwnerFromSession(sessionId)) {
      case (#err(e)) { return #err(e) };
      case (#ok(owner)) {
        switch (games.get(gameId)) {
          case null { return #err("Game not found") };
          case (?game) {
            if (not Principal.equal(game.owner, owner)) {
              return #err("You don't own this game");
            };
            
            let updatedGame : GameInfo = {
              gameId = game.gameId;
              name = clampText(name, MAX_GAME_NAME_LENGTH);
              description = clampText(description, MAX_GAME_DESCRIPTION_LENGTH);
              owner = game.owner;
              gameUrl = gameUrl;
              created = game.created;
              accessMode = game.accessMode;
              totalPlayers = game.totalPlayers;
              totalPlays = game.totalPlays;
              isActive = game.isActive;
              maxScorePerRound = game.maxScorePerRound;
              maxStreakDelta = game.maxStreakDelta;
              absoluteScoreCap = game.absoluteScoreCap;
              absoluteStreakCap = game.absoluteStreakCap;
          timeValidationEnabled = game.timeValidationEnabled;
          minPlayDurationSecs = game.minPlayDurationSecs;
          maxScorePerSecond = game.maxScorePerSecond;
          maxSessionDurationMins = game.maxSessionDurationMins;
          googleClientIds = game.googleClientIds;
              appleBundleId = game.appleBundleId;
              appleTeamId = game.appleTeamId;
            };
            
            games.put(gameId, updatedGame);
            #ok("Game updated successfully!")
          };
        };
      };
    };
  };

  // ═══════════════════════════════════════════════════════════════════════════════
  // UPDATE updateGameRulesBySession TO INCLUDE OAUTH FIELDS
  // ═══════════════════════════════════════════════════════════════════════════════

  public shared func updateGameRulesBySession(
    sessionId: Text,
    gameId: Text,
    maxScorePerRound: ?Nat64,
    maxStreakDelta: ?Nat64,
    absoluteScoreCap: ?Nat64,
    absoluteStreakCap: ?Nat64
  ) : async Result.Result<Text, Text> {
    
    switch (getOwnerFromSession(sessionId)) {
      case (#err(e)) { return #err(e) };
      case (#ok(owner)) {
        switch (games.get(gameId)) {
          case null { return #err("Game not found") };
          case (?game) {
            if (not Principal.equal(game.owner, owner)) {
              return #err("You don't own this game");
            };
            
            let updatedGame : GameInfo = {
              gameId = game.gameId;
              name = game.name;
              description = game.description;
              owner = game.owner;
              gameUrl = game.gameUrl;
              created = game.created;
              accessMode = game.accessMode;
              totalPlayers = game.totalPlayers;
              totalPlays = game.totalPlays;
              isActive = game.isActive;
              maxScorePerRound = maxScorePerRound;
              maxStreakDelta = maxStreakDelta;
              absoluteScoreCap = absoluteScoreCap;
              absoluteStreakCap = absoluteStreakCap;
              timeValidationEnabled = game.timeValidationEnabled;
              minPlayDurationSecs = game.minPlayDurationSecs;
              maxScorePerSecond = game.maxScorePerSecond;
              maxSessionDurationMins = game.maxSessionDurationMins;
              googleClientIds = game.googleClientIds;
              appleBundleId = game.appleBundleId;
              appleTeamId = game.appleTeamId;
            };
            
            games.put(gameId, updatedGame);
            #ok("Anti-cheat parameters updated!")
          };
        };
      };
    };
  };

  // ═══════════════════════════════════════════════════════════════════════════════
  // UPDATE deleteGameBySession TO INCLUDE OAUTH FIELDS
  // ═══════════════════════════════════════════════════════════════════════════════

  public shared func deleteGameBySession(
    sessionId: Text,
    gameId: Text
  ) : async Result.Result<Text, Text> {
    
    switch (getOwnerFromSession(sessionId)) {
      case (#err(e)) { return #err(e) };
      case (#ok(owner)) {
        let remaining = getRemainingDeleteAttemptsForOwner(owner);
        if (remaining == 0) {
          return #err("Rate limit exceeded. You can only delete 3 games per hour.");
        };

        // Opportunistic sweep (mirrors deleteGame): permanently remove games
        // whose 30-day recovery window has expired. Dashboard deletes come
        // through this BySession path, so without this call the sweep almost
        // never fires and expired soft-deletes accumulate until an admin runs
        // cleanupExpiredGames manually.
        cleanupDeletedGames();

        switch (games.get(gameId)) {
          case null { return #err("Game not found") };
          case (?game) {
            if (not Principal.equal(game.owner, owner)) {
              return #err("You don't own this game");
            };
            
            let currentTime = Nat64.fromNat(Int.abs(Time.now()));
            let thirtyDays : Nat64 = 30 * 24 * 60 * 60 * 1_000_000_000;
            
            let newAttempt : DeletionAttempt = {
              timestamp = currentTime;
              gameId = gameId;
            };
            
            switch (deleteRateLimit.get(owner)) {
              case null {
                deleteRateLimit.put(owner, [newAttempt]);
              };
              case (?existing) {
                deleteRateLimit.put(owner, Array.append(existing, [newAttempt]));
              };
            };
            
            let deletedGame : DeletedGame = {
              game = game;
              deletedBy = owner;
              deletedAt = currentTime;
              permanentDeletionAt = currentTime + thirtyDays;
              reason = "User deleted";
              canRecover = true;
            };
            
            deletedGames.put(gameId, deletedGame);
            
            let inactiveGame : GameInfo = {
              gameId = game.gameId;
              name = game.name;
              description = game.description;
              owner = game.owner;
              gameUrl = game.gameUrl;
              created = game.created;
              accessMode = game.accessMode;
              totalPlayers = game.totalPlayers;
              totalPlays = game.totalPlays;
              isActive = false;
              maxScorePerRound = game.maxScorePerRound;
              maxStreakDelta = game.maxStreakDelta;
              absoluteScoreCap = game.absoluteScoreCap;
              absoluteStreakCap = game.absoluteStreakCap;
          timeValidationEnabled = game.timeValidationEnabled;
          minPlayDurationSecs = game.minPlayDurationSecs;
          maxScorePerSecond = game.maxScorePerSecond;
          maxSessionDurationMins = game.maxSessionDurationMins;
          googleClientIds = game.googleClientIds;
              appleBundleId = game.appleBundleId;
              appleTeamId = game.appleTeamId;
            };
            games.put(gameId, inactiveGame);
            
            #ok("Game '" # game.name # "' deleted. You have 30 days to recover it.")
          };
        };
      };
    };
  };

  // ═══════════════════════════════════════════════════════════════════════════════
  // UPDATE recoverDeletedGameBySession TO INCLUDE OAUTH FIELDS
  // ═══════════════════════════════════════════════════════════════════════════════

  public shared func recoverDeletedGameBySession(
    sessionId: Text,
    gameId: Text
  ) : async Result.Result<Text, Text> {
    
    switch (getOwnerFromSession(sessionId)) {
      case (#err(e)) { return #err(e) };
      case (#ok(owner)) {
        switch (deletedGames.get(gameId)) {
          case null { return #err("Deleted game not found") };
          case (?deleted) {
            if (not Principal.equal(deleted.deletedBy, owner)) {
              return #err("You don't own this game");
            };
            
            let currentTime = Nat64.fromNat(Int.abs(Time.now()));
            
            if (currentTime > deleted.permanentDeletionAt) {
              return #err("Recovery period expired. Game has been permanently deleted.");
            };
            
            let ownerGames = getGameCountByOwner(owner);
            let maxGames = getMaxGamesForDeveloper(owner);
            
            if (ownerGames >= maxGames) {
              let upgradeMsg = if (maxGames == 3) { " Upgrade to Pro for 10 slots or" } else { "" };
              return #err("You already have " # Nat.toText(maxGames) # " active games." # upgradeMsg # " Delete one to recover this game.");
            };
            
            let restoredGame : GameInfo = {
              gameId = deleted.game.gameId;
              name = deleted.game.name;
              description = deleted.game.description;
              owner = deleted.game.owner;
              gameUrl = deleted.game.gameUrl;
              created = deleted.game.created;
              accessMode = deleted.game.accessMode;
              totalPlayers = deleted.game.totalPlayers;
              totalPlays = deleted.game.totalPlays;
              isActive = true;
              maxScorePerRound = deleted.game.maxScorePerRound;
              maxStreakDelta = deleted.game.maxStreakDelta;
              absoluteScoreCap = deleted.game.absoluteScoreCap;
              absoluteStreakCap = deleted.game.absoluteStreakCap;
          timeValidationEnabled = deleted.game.timeValidationEnabled;
          minPlayDurationSecs = deleted.game.minPlayDurationSecs;
          maxScorePerSecond = deleted.game.maxScorePerSecond;
          maxSessionDurationMins = deleted.game.maxSessionDurationMins;
          googleClientIds = deleted.game.googleClientIds;
              appleBundleId = deleted.game.appleBundleId;
              appleTeamId = deleted.game.appleTeamId;
            };
            
            games.put(gameId, restoredGame);
            deletedGames.delete(gameId);
            
            #ok("Game '" # deleted.game.name # "' recovered successfully!")
          };
        };
      };
    };
  };

  // ═══════════════════════════════════════════════════════════════════════════════
  // UPDATE updateGameStats HELPER TO INCLUDE OAUTH FIELDS
  // ═══════════════════════════════════════════════════════════════════════════════

  func updateGameStats(game : GameInfo, newPlayers : Nat, newPlays : Nat) : GameInfo {
    {
      gameId = game.gameId;
      name = game.name;
      description = game.description;
      owner = game.owner;
      gameUrl = game.gameUrl;
      created = game.created;
      accessMode = game.accessMode;
      totalPlayers = game.totalPlayers + newPlayers;
      totalPlays = game.totalPlays + newPlays;
      isActive = game.isActive;
      maxScorePerRound = game.maxScorePerRound;
      maxStreakDelta = game.maxStreakDelta;
      absoluteScoreCap = game.absoluteScoreCap;
      absoluteStreakCap = game.absoluteStreakCap;
      timeValidationEnabled = game.timeValidationEnabled;
          minPlayDurationSecs = game.minPlayDurationSecs;
          maxScorePerSecond = game.maxScorePerSecond;
          maxSessionDurationMins = game.maxSessionDurationMins;
          googleClientIds = game.googleClientIds;
      appleBundleId = game.appleBundleId;
      appleTeamId = game.appleTeamId;
    }
  };

  // STATS FIX 2026-08-31: returns the user's gameProfiles with this game's
  // play counted, plus whether the player was new to the game. A missing
  // profile is created at 0/0: targeted-board scores must NEVER leak into the
  // aggregate total_score / best_streak, because category boards have their
  // own score semantics (a garrison-mode score is not an all-time score).
  // Only play_count and last_played move. last_played takes the max so the
  // backfill can pass historical entry timestamps without rolling an active
  // player backwards.
  // PLAY-DEDUPE 2026-09-08: countPlay=false still creates a missing profile
  // and advances last_played, but leaves play_count alone — a later board
  // submit in an already-counted run must not count again. The backfill
  // always passes true (historical timestamps, no dedupe).
  private func registerBoardPlay(
    u : UserProfile,
    gameId : Text,
    t : Nat64,
    countPlay : Bool
  ) : ([(Text, GameProfile)], Bool) {
    var found = false;
    let profiles = Buffer.Buffer<(Text, GameProfile)>(u.gameProfiles.size() + 1);
    for ((gId, gp) in u.gameProfiles.vals()) {
      if (gId == gameId) {
        found := true;
        profiles.add((gId, {
          gameId = gp.gameId;
          total_score = gp.total_score;
          best_streak = gp.best_streak;
          achievements = gp.achievements;
          last_played = if (t > gp.last_played) t else gp.last_played;
          play_count = gp.play_count + (if (countPlay) 1 else 0);
        }));
      } else {
        profiles.add((gId, gp));
      };
    };
    if (not found) {
      profiles.add((gameId, {
        gameId = gameId;
        total_score = 0;
        best_streak = 0;
        achievements = [];
        last_played = t;
        play_count = if (countPlay) 1 else 0;
      }));
    };
    (Buffer.toArray(profiles), not found)
  };

  // PLAY-DEDUPE 2026-09-08: pure check — true if a play was already counted
  // for this player+game within the window. Underflow-guarded (t >= prev)
  // per the Nat64 underflow sweep. Marking is separate (markPlayCounted) so
  // a submit that is REJECTED after this check never burns the window and
  // suppresses the count of a valid retry.
  private func playCountedRecently(identifier : UserIdentifier, gameId : Text, t : Nat64) : Bool {
    switch (lastPlayCounted.get(makeSubmitKey(identifier, gameId))) {
      case (?prev) { t >= prev and t - prev < PLAY_DEDUPE_WINDOW_NS };
      case null { false };
    };
  };

  private func markPlayCounted(identifier : UserIdentifier, gameId : Text, t : Nat64) {
    lastPlayCounted.put(makeSubmitKey(identifier, gameId), t);
  };



  public query(msg) func getMyGameCount() : async Nat {
    countGamesByOwner(msg.caller)
  };


  // ════════════════════════════════════════════════════════════════════════════
  // ENGINE TAG (release A) — standalone map, not a GameInfo change.
  // Values are a fixed set of lowercase slugs so the dashboard dropdown and any
  // public listing agree. Safe to expose publicly.
  // ════════════════════════════════════════════════════════════════════════════

  private transient let VALID_ENGINES : [Text] = ["godot4", "godot3", "unity", "rest", "other"];

  private func isValidEngine(engine : Text) : Bool {
    for (e in VALID_ENGINES.vals()) { if (e == engine) { return true } };
    false
  };

  // "" clears the tag. Owner or admin only.
  private func setGameEngineInternal(caller : Principal, gameId : Text, engine : Text) : Result.Result<Text, Text> {
    switch (games.get(gameId)) {
      case null { #err("Game not found") };
      case (?game) {
        if (not Principal.equal(game.owner, caller) and not isAdmin(caller)) {
          return #err("Only game owner can set the engine");
        };
        if (engine == "") {
          gameEngines.delete(gameId);
          return #ok("Engine cleared");
        };
        if (not isValidEngine(engine)) {
          return #err("Unknown engine. Use one of: godot4, godot3, unity, rest, other");
        };
        gameEngines.put(gameId, engine);
        #ok("Engine set to " # engine)
      };
    }
  };

  public shared(msg) func setGameEngine(gameId : Text, engine : Text) : async Result.Result<Text, Text> {
    if (Principal.isAnonymous(msg.caller)) { return #err("Anonymous callers cannot set engine") };
    setGameEngineInternal(msg.caller, gameId, engine)
  };

  public shared func setGameEngineBySession(sessionId : Text, gameId : Text, engine : Text) : async Result.Result<Text, Text> {
    switch (getOwnerFromSession(sessionId)) {
      case (#err(e)) { #err(e) };
      case (#ok(owner)) { setGameEngineInternal(owner, gameId, engine) };
    }
  };

  public query func getGameEngine(gameId : Text) : async ?Text {
    gameEngines.get(gameId)
  };

  // All tags at once, for the dashboard/players cards.
  public query func getGameEngines() : async [(Text, Text)] {
    Iter.toArray(gameEngines.entries())
  };

  // ════════════════════════════════════════════════════════════════════════════
  // WEBSITE URL (release A) — optional, gameId -> https URL. Separate from
  // gameUrl, which is the PLAY link; several devs had put their site there.
  // Same standalone-map pattern as the engine tag. Safe to expose publicly.
  // ════════════════════════════════════════════════════════════════════════════

  // "" clears it. Owner or admin only. Validated like gameUrl.
  private func setGameWebsiteInternal(caller : Principal, gameId : Text, website : Text) : Result.Result<Text, Text> {
    switch (games.get(gameId)) {
      case null { #err("Game not found") };
      case (?game) {
        if (not Principal.equal(game.owner, caller) and not isAdmin(caller)) {
          return #err("Only game owner can set the website");
        };
        switch (sanitizeGameUrl(?website)) {
          case (#err(e)) { #err(e) };
          case (#ok(null)) { gameWebsites.delete(gameId); #ok("Website cleared") };
          case (#ok(?u)) { gameWebsites.put(gameId, u); #ok("Website set") };
        }
      };
    }
  };

  public shared(msg) func setGameWebsite(gameId : Text, website : Text) : async Result.Result<Text, Text> {
    if (Principal.isAnonymous(msg.caller)) { return #err("Anonymous callers cannot set website") };
    setGameWebsiteInternal(msg.caller, gameId, website)
  };

  public shared func setGameWebsiteBySession(sessionId : Text, gameId : Text, website : Text) : async Result.Result<Text, Text> {
    switch (getOwnerFromSession(sessionId)) {
      case (#err(e)) { #err(e) };
      case (#ok(owner)) { setGameWebsiteInternal(owner, gameId, website) };
    }
  };

  public query func getGameWebsite(gameId : Text) : async ?Text {
    gameWebsites.get(gameId)
  };

  public query func getGameWebsites() : async [(Text, Text)] {
    Iter.toArray(gameWebsites.entries())
  };

  // ════════════════════════════════════════════════════════════════════════════
  // DEVELOPER CONTACT EMAIL (release A) — optional, principal -> email.
  // Never exposed publicly: getGame is public, so this lives in its own map with
  // owner/admin getters only. Feeds Request-More-Slots.
  // ════════════════════════════════════════════════════════════════════════════

  private transient let MAX_CONTACT_EMAIL_LENGTH : Nat = 254;

  // "" clears the contact.
  private func setDeveloperContactInternal(owner : Principal, email : Text) : Result.Result<Text, Text> {
    let e = Text.trim(email, #predicate(func(c : Char) : Bool { c == ' ' or c == '\t' or c == '\n' or c == '\r' }));
    if (Text.size(e) == 0) {
      developerContacts.delete(owner);
      return #ok("Contact email cleared");
    };
    if (Text.size(e) > MAX_CONTACT_EMAIL_LENGTH) {
      return #err("Contact email too long");
    };
    if (not looksLikeEmail(e)) {
      return #err("Contact email doesn't look like an email address");
    };
    developerContacts.put(owner, e);
    #ok("Contact email saved")
  };

  public shared(msg) func setDeveloperContact(email : Text) : async Result.Result<Text, Text> {
    if (Principal.isAnonymous(msg.caller)) { return #err("Anonymous callers cannot set a contact email") };
    setDeveloperContactInternal(msg.caller, email)
  };

  public shared func setDeveloperContactBySession(sessionId : Text, email : Text) : async Result.Result<Text, Text> {
    switch (getOwnerFromSession(sessionId)) {
      case (#err(e)) { #err(e) };
      case (#ok(owner)) { setDeveloperContactInternal(owner, email) };
    }
  };

  public shared query(msg) func getMyDeveloperContact() : async ?Text {
    developerContacts.get(msg.caller)
  };

  public query func getMyDeveloperContactBySession(sessionId : Text) : async Result.Result<?Text, Text> {
    switch (getOwnerFromSession(sessionId)) {
      case (#err(e)) { #err(e) };
      case (#ok(owner)) { #ok(developerContacts.get(owner)) };
    }
  };

  // Admin: look up a developer's contact (e.g. when handling a slots request).
  public shared query(msg) func getDeveloperContact(owner : Principal) : async Result.Result<?Text, Text> {
    if (not isAdmin(msg.caller)) { return #err("Admin only") };
    #ok(developerContacts.get(owner))
  };

  public query func getGame(gameId : Text) : async ?GameInfo {
    games.get(gameId)
  };

  public query func listGames() : async [GameInfo] {
    Iter.toArray(games.vals())
  };

  public query func getActiveGames() : async [GameInfo] {
    Iter.toArray(
      Iter.filter(games.vals(), func (g : GameInfo) : Bool { g.isActive })
    )
  };

  public query func getGamesByOwner(owner : Principal) : async [GameInfo] {
    // Filter out soft-deleted (inactive) games so a deleted game stops showing in
    // the dashboard — matches getGamesBySession, which already filters isActive.
    Iter.toArray(
      Iter.filter(games.vals(), func (g : GameInfo) : Bool { g.owner == owner and g.isActive })
    )
  };

  public query func getGameAccessMode(gameId : Text) : async ?AccessMode {
    switch (games.get(gameId)) {
      case null { null };
      case (?game) { ?game.accessMode };
    }
  };

  public query func getDeveloperTierBySession(sessionId: Text) : async {tier: Text; maxGames: Nat; currentGames: Nat} {
    switch (getValidSession(sessionId)) {
        case null { {tier = "free"; maxGames = 3; currentGames = 0} };
        case (?session) {
            let owner = ownerIdOrNobody(session.email);
            let maxGames = getMaxGamesForDeveloper(owner);
            let currentGames = getGameCountByOwner(owner);
            let tier = getDeveloperTierText(owner);
            {tier = tier; maxGames = maxGames; currentGames = currentGames}
        };
    };
};

// Also add for II users:
public query func getDeveloperTier() : async {tier: Text; maxGames: Nat; currentGames: Nat} {
    let owner = Principal.fromActor(CheddaBoards); // This won't work - need msg.caller
    {tier = "free"; maxGames = 3; currentGames = 0}
};

// Better version using shared query:
public shared query(msg) func getMyDeveloperTier() : async {tier: Text; maxGames: Nat; currentGames: Nat} {
    let owner = msg.caller;
    let maxGames = getMaxGamesForDeveloper(owner);
    let currentGames = getGameCountByOwner(owner);
    let tier = getDeveloperTierText(owner);
    {tier = tier; maxGames = maxGames; currentGames = currentGames}
};

public query func getScoreboardArchives(
    gameId : Text,
    scoreboardId : Text
  ) : async [ArchiveInfo] {
    let prefix = gameId # ":" # scoreboardId # ":";
    let results = Buffer.Buffer<ArchiveInfo>(10);
    
    for ((key, archive) in scoreboardArchives.entries()) {
      if (Text.startsWith(key, #text prefix)) {
        // Find the actual best entry — archives stored before
        // sorting-at-archive-time have entries in insertion order,
        // so entries[0] is the first submitter, not the winner.
        var topPlayer : ?Text = null;
        var topScore : Nat64 = 0;
        for (entry in archive.entries.vals()) {
          let v = Scoreboards.getEntryValue(entry, archive.sortBy);
          if (topPlayer == null or v > topScore) {
            topPlayer := ?entry.nickname;
            topScore := v;
          };
        };
        
        results.add({
          archiveId = key;
          scoreboardId = archive.scoreboardId;
          periodStart = archive.periodStart;
          periodEnd = archive.periodEnd;
          entryCount = archive.totalEntries;
          topPlayer = topPlayer;
          topScore = topScore;
        });
      };
    };
    
    // Sort by periodEnd descending (newest first)
    let sorted = Array.sort<ArchiveInfo>(
      Buffer.toArray(results),
      func(a, b) {
        if (a.periodEnd > b.periodEnd) { #less }
        else if (a.periodEnd < b.periodEnd) { #greater }
        else { #equal }
      }
    );
    
    sorted
  };

 public query func getArchivedScoreboard(
    archiveId : Text,
    limit : Nat
  ) : async Result.Result<{
    config : {
      name : Text;
      period : Text;
      sortBy : Text;
      periodStart : Nat64;
      periodEnd : Nat64;
    };
    entries : [PublicScoreEntry];
  }, Text> {
    switch (scoreboardArchives.get(archiveId)) {
      case null { #err("Archive not found") };
      case (?archive) {
        // Sort before ranking/truncation — covers archives stored before
        // sorting-at-archive-time was added (they're in insertion order).
        let sortedEntries = Scoreboards.sortEntries(archive.entries, archive.sortBy);

        let cap = if (limit == 0 or limit > sortedEntries.size()) { 
          sortedEntries.size() 
        } else { limit };
        
        let publicEntries = Buffer.Buffer<PublicScoreEntry>(cap);
        var rank : Nat = 1;
        
        for (entry in sortedEntries.vals()) {
          if (rank <= cap) {
            publicEntries.add({
              nickname = entry.nickname;
              score = entry.score;
              streak = entry.streak;
              submittedAt = entry.submittedAt;
              authType = authTypeToText(entry.authType);
              rank = rank;
            });
            rank += 1;
          };
        };
        
        #ok({
          config = {
            name = archive.name;
            period = periodToText(archive.period);
            sortBy = switch (archive.sortBy) { case (#score) "score"; case (#streak) "streak" };
            periodStart = archive.periodStart;
            periodEnd = archive.periodEnd;
          };
          entries = Buffer.toArray(publicEntries);
        })
      };
    };
  };

  public query func getLastArchivedScoreboard(
    gameId : Text,
    scoreboardId : Text,
    limit : Nat
  ) : async Result.Result<{
    archiveId : Text;
    config : {
      name : Text;
      period : Text;
      sortBy : Text;
      periodStart : Nat64;
      periodEnd : Nat64;
    };
    entries : [PublicScoreEntry];
  }, Text> {
    let prefix = gameId # ":" # scoreboardId # ":";
    var latestKey : ?Text = null;
    var latestTime : Nat64 = 0;
    
    for ((key, archive) in scoreboardArchives.entries()) {
      if (Text.startsWith(key, #text prefix)) {
        if (archive.periodEnd > latestTime) {
          latestTime := archive.periodEnd;
          latestKey := ?key;
        };
      };
    };
    
    switch (latestKey) {
      case null { #err("No archives found for this scoreboard") };
      case (?key) {
        switch (scoreboardArchives.get(key)) {
          case null { #err("Archive not found") };
          case (?archive) {
            let cap = if (limit == 0 or limit > archive.entries.size()) { 
              archive.entries.size() 
            } else { limit };
            
            let publicEntries = Buffer.Buffer<PublicScoreEntry>(cap);
            var rank : Nat = 1;
            
            for (entry in archive.entries.vals()) {
              if (rank <= cap) {
                publicEntries.add({
                  nickname = entry.nickname;
                  score = entry.score;
                  streak = entry.streak;
                  submittedAt = entry.submittedAt;
                  authType = authTypeToText(entry.authType);
                  rank = rank;
                });
                rank += 1;
              };
            };
            
            #ok({
              archiveId = key;
              config = {
                name = archive.name;
                period = periodToText(archive.period);
                sortBy = switch (archive.sortBy) { case (#score) "score"; case (#streak) "streak" };
                periodStart = archive.periodStart;
                periodEnd = archive.periodEnd;
              };
              entries = Buffer.toArray(publicEntries);
            })
          };
        };
      };
    };
  };

   public query func getArchivesInRange(
    gameId : Text,
    scoreboardId : Text,
    afterTimestamp : Nat64,
    beforeTimestamp : Nat64
  ) : async [ArchiveInfo] {
    let prefix = gameId # ":" # scoreboardId # ":";
    let results = Buffer.Buffer<ArchiveInfo>(10);
    
    for ((key, archive) in scoreboardArchives.entries()) {
      if (Text.startsWith(key, #text prefix)) {
        // Check if archive falls within range
        if (archive.periodEnd >= afterTimestamp and archive.periodEnd <= beforeTimestamp) {
          // Find the actual best entry — archives stored before
          // sorting-at-archive-time have entries in insertion order,
          // so entries[0] is the first submitter, not the winner.
          var topPlayer : ?Text = null;
          var topScore : Nat64 = 0;
          for (entry in archive.entries.vals()) {
            let v = Scoreboards.getEntryValue(entry, archive.sortBy);
            if (topPlayer == null or v > topScore) {
              topPlayer := ?entry.nickname;
              topScore := v;
            };
          };
          
          results.add({
            archiveId = key;
            scoreboardId = archive.scoreboardId;
            periodStart = archive.periodStart;
            periodEnd = archive.periodEnd;
            entryCount = archive.totalEntries;
            topPlayer = topPlayer;
            topScore = topScore;
          });
        };
      };
    };
    
    // Sort by periodEnd descending (newest first)
    let sorted = Array.sort<ArchiveInfo>(
      Buffer.toArray(results),
      func(a, b) {
        if (a.periodEnd > b.periodEnd) { #less }
        else if (a.periodEnd < b.periodEnd) { #greater }
        else { #equal }
      }
    );
    
    sorted
  };

   public query func getArchiveStats(gameId : Text) : async {
    totalArchives : Nat;
    byScoreboard : [(Text, Nat)];
  } {
    let counts = HashMap.HashMap<Text, Nat>(10, Text.equal, Text.hash);
    var total : Nat = 0;
    
    for ((key, archive) in scoreboardArchives.entries()) {
      if (archive.gameId == gameId) {
        total += 1;
        switch (counts.get(archive.scoreboardId)) {
          case (?c) { counts.put(archive.scoreboardId, c + 1) };
          case null { counts.put(archive.scoreboardId, 1) };
        };
      };
    };
    
    {
      totalArchives = total;
      byScoreboard = Iter.toArray(counts.entries());
    }
  };
// ─────────────────────────────────────────────────────────────────────────────
// 10. UPDATE getRemainingGameSlotsBySession to use dynamic max:
// ─────────────────────────────────────────────────────────────────────────────

public query func getRemainingGameSlotsBySession(sessionId: Text) : async Nat {
    switch (getValidSession(sessionId)) {
        case null { return 0 };
        case (?session) {
            let owner = ownerIdOrNobody(session.email);
            let maxGames = getMaxGamesForDeveloper(owner);
            let count = getGameCountByOwner(owner);
            if (count >= maxGames) { 0 } else { maxGames - count }
        };
    };
};

// And for II users:
public shared query(msg) func getRemainingGameSlots() : async Nat {
    let owner = msg.caller;
    let maxGames = getMaxGamesForDeveloper(owner);
    let count = getGameCountByOwner(owner);
    if (count >= maxGames) { 0 } else { maxGames - count }
};

// ════════════════════════════════════════════════════════════════════════════
  // API KEYS
  // ════════════════════════════════════════════════════════════════════════════

  public shared(msg) func generateApiKey(gameId : Text) : async Result.Result<Text, Text> {
    let game = switch (games.get(gameId)) {
      case null { return #err("Game not found") };
      case (?g) { g };
    };
    
    if (game.owner != msg.caller) {
      return #err("Only the game owner can generate API keys");
    };
    
    if (ApiKeys.hasActiveKey(apiKeys, gameId)) {
      return #err("Active API key exists. Revoke it first to generate a new one.");
    };
    
    // v0.10.0: replace the module's timestamp-based key string with raw_rand.
    let baseKey = ApiKeys.createKey(gameId, msg.caller);
    let newKey = { baseKey with key = "cb_" # gameId # "_" # toHex(await* takeRandomBytes(16)) };
    apiKeys.put(newKey.key, newKey);
    
    trackEventInternal(#principal(msg.caller), gameId, "api_key_generated", [
      ("gameId", gameId)
    ]);
    
    #ok(newKey.key)
  };

  public shared(msg) func getApiKey(gameId : Text) : async Result.Result<Text, Text> {
    let game = switch (games.get(gameId)) {
      case null { return #err("Game not found") };
      case (?g) { g };
    };
    
    if (game.owner != msg.caller) {
      return #err("Only the game owner can view API keys");
    };
    
    switch (ApiKeys.getActiveKey(apiKeys, gameId)) {
      case (?key) { #ok(key) };
      case null { #err("No API key found. Generate one first.") };
    }
  };

  public query func hasApiKey(gameId : Text) : async Bool {
    ApiKeys.hasActiveKey(apiKeys, gameId)
  };

  // HARDENING (Oct 2026): verifier-only. This was a public oracle: anyone could
  // test whether a guessed key was real and which game it belonged to. Only the
  // proxy needs it. Same Candid signature, so no interface change.
  public shared query(msg) func validateApiKeyQuery(key : Text) : async ?{
    gameId : Text;
    tier : Text;
    isActive : Bool;
  } {
    if (not isVerifier(msg.caller)) { return null };
    ApiKeys.validate(apiKeys, key)
  };

  // v0.10.0: verifier-only (public oracle that also bumped usage stats).
  public shared(msg) func validateApiKey(key : Text) : async ?ApiKey {
    if (not isVerifier(msg.caller)) { return null };
    switch (apiKeys.get(key)) {
      case null { null };
      case (?apiKey) {
        if (apiKey.isActive) {
          let updated = ApiKeys.recordUsage(apiKey);
          apiKeys.put(key, updated);
          ?updated
        } else { null }
      };
    }
  };

  public shared(msg) func revokeApiKey(gameId : Text) : async Result.Result<Text, Text> {
    let game = switch (games.get(gameId)) {
      case null { return #err("Game not found") };
      case (?g) { g };
    };
    
    if (game.owner != msg.caller and not isAdmin(msg.caller)) {
      return #err("Only the game owner can revoke API keys");
    };
    
    switch (ApiKeys.revokeForGame(apiKeys, gameId)) {
      case (?(key, revokedKey)) {
        apiKeys.put(key, revokedKey);
        trackEventInternal(#principal(msg.caller), gameId, "api_key_revoked", [
          ("gameId", gameId)
        ]);
        #ok("API key revoked")
      };
      case null { #err("No active API key found") };
    }
  };

  public shared(msg) func updateApiKeyTier(gameId : Text, newTier : Text) : async Result.Result<Text, Text> {
    let game = switch (games.get(gameId)) {
      case null { return #err("Game not found") };
      case (?g) { g };
    };
    
    if (game.owner != msg.caller and not isAdmin(msg.caller)) {
      return #err("Only the game owner can update API key tier");
    };
    
    if (not ApiKeys.isValidTier(newTier)) {
      return #err("Invalid tier. Use: free, indie, or pro");
    };
    
    switch (ApiKeys.updateTierForGame(apiKeys, gameId, newTier)) {
      case (?(key, updatedKey)) {
        apiKeys.put(key, updatedKey);
        #ok("Tier updated to " # newTier)
      };
      case null { #err("No active API key found") };
    }
  };

  // ═══════════════════════════════════════════════════════════════════════════════
// API KEY BY SESSION
// ═══════════════════════════════════════════════════════════════════════════════

public shared func generateApiKeyBySession(
    sessionId: Text,
    gameId: Text
) : async Result.Result<Text, Text> {
    switch (getOwnerFromSession(sessionId)) {
        case (#err(e)) { return #err(e) };
        case (#ok(owner)) {
            switch (games.get(gameId)) {
                case null { return #err("Game not found") };
                case (?game) {
                    if (not Principal.equal(game.owner, owner)) {
                        return #err("You don't own this game");
                    };
                    
                    if (ApiKeys.hasActiveKey(apiKeys, gameId)) {
                        return #err("Active API key exists. Revoke it first to generate a new one.");
                    };
                    
                    // v0.10.0: replace the module's timestamp-based key string with raw_rand.
                    let baseKey = ApiKeys.createKey(gameId, owner);
                    let newKey = { baseKey with key = "cb_" # gameId # "_" # toHex(await* takeRandomBytes(16)) };
                    apiKeys.put(newKey.key, newKey);
                    
                    #ok(newKey.key)
                };
            };
        };
    };
};

public query func getApiKeyBySession(sessionId: Text, gameId: Text) : async Result.Result<Text, Text> {
    switch (getValidSession(sessionId)) {
        case null { return #err("Invalid session") };
        case (?session) {
            let owner = ownerIdOrNobody(session.email);
            
            switch (games.get(gameId)) {
                case null { return #err("Game not found") };
                case (?game) {
                    if (not Principal.equal(game.owner, owner)) {
                        return #err("You don't own this game");
                    };
                    
                    switch (ApiKeys.getActiveKey(apiKeys, gameId)) {
                        case (?key) { #ok(key) };
                        case null { #err("No API key found. Generate one first.") };
                    }
                };
            };
        };
    };
};

public query func hasApiKeyBySession(sessionId: Text, gameId: Text) : async Bool {
    switch (getValidSession(sessionId)) {
        case null { return false };
        case (?session) {
            let owner = ownerIdOrNobody(session.email);
            
            switch (games.get(gameId)) {
                case null { return false };
                case (?game) {
                    if (not Principal.equal(game.owner, owner)) {
                        return false;
                    };
                    ApiKeys.hasActiveKey(apiKeys, gameId)
                };
            };
        };
    };
};

public shared func revokeApiKeyBySession(
    sessionId: Text,
    gameId: Text
) : async Result.Result<Text, Text> {
    switch (getOwnerFromSession(sessionId)) {
        case (#err(e)) { return #err(e) };
        case (#ok(owner)) {
            switch (games.get(gameId)) {
                case null { return #err("Game not found") };
                case (?game) {
                    if (not Principal.equal(game.owner, owner)) {
                        return #err("You don't own this game");
                    };
                    
                    switch (ApiKeys.revokeForGame(apiKeys, gameId)) {
                        case (?(key, revokedKey)) {
                            apiKeys.put(key, revokedKey);
                            #ok("API key revoked successfully")
                        };
                        case null { #err("No active API key found") };
                    }
                };
            };
        };
    };
};

  // ════════════════════════════════════════════════════════════════════════════
  // AUTHENTICATION
  // ════════════════════════════════════════════════════════════════════════════

  // HARDENING (Oct 2026): read-only session lookup for QUERY calls. Returns the
  // session only if it exists and has not expired (same rule as
  // validateSessionInternal). No renewal and no delete: a query can't persist
  // either, and the next update call does both. Use this instead of a raw
  // sessions.get in any query, which would accept an expired session.
  private func getValidSession(sessionId : Text) : ?Session {
    switch (sessions.get(sessionId)) {
      case null { null };
      case (?session) {
        if (now() > session.expires) { null } else { ?session }
      };
    }
  };

  func validateSessionInternal(sessionId : Text) : Result.Result<Session, Text> {
    switch (sessions.get(sessionId)) {
      case null {
        #err("Invalid session: not found")
      };
      case (?session) {
        let currentTime = now();
        
        if (currentTime > session.expires) {
          sessions.delete(sessionId);
          return #err("Session expired");
        };
        
        // Sliding renewal: every successful use pushes expiry out another full window,
        // so an active player never expires. (No-op in query contexts — state changes
        // there are discarded, which is fine; renewal lands on update calls like submits.)
        let renewed : Session = {
          sessionId = session.sessionId;
          email = session.email;
          nickname = session.nickname;
          authType = session.authType;
          created = session.created;
          expires = currentTime + SESSION_DURATION_NS;
          lastUsed = currentTime;
        };
        sessions.put(sessionId, renewed);
        
        #ok(renewed)
      };
    }
  };

  public shared func validateSession(sessionId : Text) : async Result.Result<{ email: Text; nickname: Text; valid: Bool }, Text> {
    switch (sessions.get(sessionId)) {
      case (?session) {
        if (session.expires < now()) {
          sessions.delete(sessionId);
          #err("Session expired")
        } else {
          let updated = {
            sessionId = session.sessionId;
            email = session.email;
            nickname = session.nickname;
            authType = session.authType;
            created = session.created;
            expires = now() + SESSION_DURATION_NS; // sliding renewal, same as validateSessionInternal
            lastUsed = now();
          };
          sessions.put(sessionId, updated);
          
          #ok({
            email = session.email;
            nickname = session.nickname;
            valid = true;
          })
        }
      };
      case null { #err("Invalid session") };
    }
  };

  public shared func destroySession(sessionId : Text) : async Result.Result<Text, Text> {
    switch (sessions.remove(sessionId)) {
      case (?_) { #ok("Session destroyed") };
      case null { #err("Session not found") };
    }
  };

  public shared(msg) func iiLoginAndGetProfile(
    nickname : Text,
    gameId : Text
  ) : async Result.Result<{
    message : Text;
    isNewUser : Bool;
    nickname : Text;
    gameProfile : ?{
      total_score : Nat64;
      best_streak : Nat64;
      achievements : [Text];
      last_played : Nat64;
      play_count : Nat;
    };
  }, Text> {
    
    let caller = msg.caller;
    
    switch (validateNickname(nickname)) {
      case (#err(e)) { return #err(e) };
      case (#ok()) {};
    };
    
    if (Principal.isAnonymous(caller)) {
      return #err("Internet Identity required");
    };
    
    let (user, isNewUser) = switch (usersByPrincipal.get(caller)) {
      case (?existingUser) {
        (existingUser, false)
      };
      case null {
        let newUser : UserProfile = {
          identifier = #principal(caller);
          nickname = nickname;
          authType = #internetIdentity;
          gameProfiles = [];
          created = now();
          last_updated = now();
        };
        usersByPrincipal.put(caller, newUser);
        
        trackEventInternal(#principal(caller), "default", "signup", [
          ("provider", "internetIdentity"),
          ("nickname", nickname)
        ]);
        
        (newUser, true)
      };
    };
    
    var gameProfile : ?{
      total_score : Nat64;
      best_streak : Nat64;
      achievements : [Text];
      last_played : Nat64;
      play_count : Nat;
    } = null;
    
    for ((gId, gp) in user.gameProfiles.vals()) {
      if (gId == gameId) {
        gameProfile := ?{
          total_score = gp.total_score;
          best_streak = gp.best_streak;
          achievements = gp.achievements;
          last_played = gp.last_played;
          play_count = gp.play_count;
        };
      };
    };
    
    let message = if (isNewUser) {
      "Account created for " # user.nickname
    } else {
      "Welcome back, " # user.nickname
    };
    
    #ok({
      message = message;
      isNewUser = isNewUser;
      nickname = user.nickname;
      gameProfile = gameProfile;
    })
  };

  public shared(msg) func socialLoginAndGetProfile(
    email : Text,
    nickname : Text,
    provider : Text,
    gameId : Text
  ) : async Result.Result<{
    message : Text;
    isNewUser : Bool;
    nickname : Text;
    sessionId : Text;
    gameProfile : ?{
      total_score : Nat64;
      best_streak : Nat64;
      achievements : [Text];
      last_played : Nat64;
      play_count : Nat;
    };
  }, Text> {

    // SECURITY: this mints a fully-privileged session from a bare `email` string.
    // The caller MUST be the trusted verifier (same gate as
    // createSessionForVerifiedUser). The verifier is responsible for validating
    // the Google/Apple token before calling this with the verified email.
    if (not isVerifier(msg.caller)) {
      return #err("Unauthorized: login must go through the verifier");
    };

    switch (validateNickname(nickname)) {
      case (#err(e)) { return #err(e) };
      case (#ok()) {};
    };
    
    let authType = if (provider == "google") { #google } else { #apple };
    
    let (user, isNewUser) = switch (usersByEmail.get(email)) {
      case (?existingUser) {
        (existingUser, false)
      };
      case null {
        // For new users, ensure nickname is available (auto-suffix if taken)
        let availableNickname = getAvailableNickname(nickname, null);
        
        let newUser : UserProfile = {
          identifier = #email(email);
          nickname = availableNickname;
          authType = authType;
          gameProfiles = [];
          created = now();
          last_updated = now();
        };
        usersByEmail.put(email, newUser);
        
        trackEventInternal(#email(email), "default", "signup", [
          ("provider", provider),
          ("nickname", availableNickname),
          ("requested_nickname", nickname)
        ]);
        
        (newUser, true)
      };
    };
    
    await* ensureOwnerId(email);
    let sessionId = generateSessionId(await* takeRandomBytes(32));
    let session : Session = {
      sessionId = sessionId;
      email = email;
      nickname = user.nickname;
      authType = authType;
      created = now();
      expires = now() + SESSION_DURATION_NS;
      lastUsed = now();
    };
    sessions.put(sessionId, session);
    // Removed: principalToSession.put(Principal.toText(msg.caller), sessionId);
    // The caller is always VERIFIER now, so this only ever mapped VERIFIER -> the
    // most recent session (last-writer-wins), and nothing in the canister reads
    // this map (it is write-only aside from the upgrade snapshot). Dropping it.

    var gameProfile : ?{
      total_score : Nat64;
      best_streak : Nat64;
      achievements : [Text];
      last_played : Nat64;
      play_count : Nat;
    } = null;
    
    for ((gId, gp) in user.gameProfiles.vals()) {
      if (gId == gameId) {
        gameProfile := ?{
          total_score = gp.total_score;
          best_streak = gp.best_streak;
          achievements = gp.achievements;
          last_played = gp.last_played;
          play_count = gp.play_count;
        };
      };
    };
    
    let message = if (isNewUser) {
      "Account created for " # user.nickname
    } else {
      "Welcome back, " # user.nickname
    };
    
    #ok({
      message = message;
      isNewUser = isNewUser;
      nickname = user.nickname;
      sessionId = sessionId;
      gameProfile = gameProfile;
    })
  };

  public shared ({ caller }) func createSessionForVerifiedUser(
    idp   : AuthType,
    sub   : Text,
    email : ?Text,
    nonce : Text
  ) : async Result.Result<Session, Text> {

    if (not isVerifier(caller)) {
      return #err("Unauthorized: caller is not verifier");
    };

    let userEmail : Text = switch (email) {
      case (null) { return #err("Email required"); };
      case (?e) { e };
    };

    let defaultNickname : Text = generateDefaultNickname();

    let tNow = now();
    let userIdentifier : UserIdentifier = #email(userEmail);

    let actualNickname : Text = switch (usersByEmail.get(userEmail)) {
      case (null) {
        let profile : UserProfile = {
          identifier   = userIdentifier;
          nickname     = defaultNickname;
          authType     = idp;
          gameProfiles = [];
          created      = tNow;
          last_updated = tNow;
        };
        usersByEmail.put(userEmail, profile);
        defaultNickname
      };

      case (?existing) {
        let updated : UserProfile = {
          identifier   = existing.identifier;
          nickname     = existing.nickname;
          authType     = idp;
          gameProfiles = existing.gameProfiles;
          created      = existing.created;
          last_updated = tNow;
        };
        usersByEmail.put(userEmail, updated);
        existing.nickname
      };
    };

    await* ensureOwnerId(userEmail);
    let sessionToken : Text = generateSessionId(await* takeRandomBytes(32));
    let session : Session = {
      sessionId = sessionToken;
      email     = userEmail;
      nickname  = actualNickname;
      authType  = idp;
      created   = tNow;
      expires   = tNow + SESSION_DURATION_NS;
      lastUsed  = tNow;
    };
    sessions.put(sessionToken, session);

    return #ok(session);
  };

  public shared(msg) func suggestNickname() : async Result.Result<Text, Text> {
    let suggestion = generateDefaultNickname();
    #ok(suggestion)
  };

  public shared(msg) func getNicknameBySession(sessionId : Text) : async Result.Result<Text, Text> {
    switch (validateSessionInternal(sessionId)) {
      case (#err(e)) { #err(e) };
      case (#ok(session)) { #ok(session.nickname) };
    };
  };

  public shared(msg) func changeNicknameAndGetProfile(
    userIdType : Text,
    userId : Text,
    newNickname : Text,
    gameId : Text
  ) : async Result.Result<{
    message : Text;
    nickname : Text;
    gameProfile : ?{
      total_score : Nat64;
      best_streak : Nat64;
      achievements : [Text];
      last_played : Nat64;
      play_count : Nat;
    };
  }, Text> {
    
    switch (validateCaller(msg, userIdType, userId)) {
      case (#err(e)) { return #err(e) };
      case (#ok(_)) {};
    };
    
    switch (validateNickname(newNickname)) {
      case (#err(e)) { return #err(e) };
      case (#ok()) {};
    };
    
    let identifier : UserIdentifier = switch (userIdType) {
      case ("email") { 
        switch (validateSessionInternal(userId)) {
          case (#err(e)) { return #err(e) };
          case (#ok(session)) { #email(session.email) };
        };
      };
      case ("session") {
        switch (validateSessionInternal(userId)) {
          case (#err(e)) { return #err(e) };
          case (#ok(session)) { #email(session.email) };
        };
      };
      case ("principal") { #principal(msg.caller) };
      case ("external") { #email("ext:" # userId) };
      case (_) { return #err("Invalid user type") };
    };
    
    // Get an available nickname (auto-suffix if taken)
    let finalNickname = getAvailableNickname(newNickname, ?identifier);
    
    let user = getUserByIdentifier(identifier);
    
    switch (user) {
      case null { #err("User not found") };
      case (?u) {
        let updatedUser : UserProfile = {
          identifier = u.identifier;
          nickname = finalNickname;
          authType = u.authType;
          gameProfiles = u.gameProfiles;
          created = u.created;
          last_updated = now();
        };
        
        putUserByIdentifier(updatedUser);
        
        trackEventInternal(u.identifier, "default", "nickname_changed", [
          ("old_nickname", u.nickname),
          ("new_nickname", finalNickname),
          ("requested_nickname", newNickname)
        ]);
        
        // ── Propagate nickname to all scoreboard entries ──
        if (u.nickname != finalNickname) {
          for ((sbKey, entriesBuffer) in scoreboardEntries.entries()) {
            var found = false;
            var foundIdx : Nat = 0;
            var idx : Nat = 0;
            
            for (entry in entriesBuffer.vals()) {
              if (identifiersEqual(entry.odentifier, identifier)) {
                found := true;
                foundIdx := idx;
              };
              idx += 1;
            };
            
            if (found) {
              let existing = entriesBuffer.get(foundIdx);
              let updated : ScoreEntry = {
                odentifier = existing.odentifier;
                nickname = finalNickname;
                score = existing.score;
                streak = existing.streak;
                submittedAt = existing.submittedAt;
                authType = existing.authType;
              };
              entriesBuffer.put(foundIdx, updated);
              scoreboardEntries.put(sbKey, entriesBuffer);
              cachedScoreboards.delete(sbKey);
              scoreboardLastUpdate.delete(sbKey);
            };
          };
          
          // Also invalidate legacy leaderboard caches for user's games
          for ((gId, _) in u.gameProfiles.vals()) {
            cachedLeaderboards.delete(gId # ":score");
            cachedLeaderboards.delete(gId # ":streak");
          };
          
          // ── Propagate nickname to active sessions ──
          let userEmail = switch (identifier) {
            case (#email(e)) { ?e };
            case (_) { null };
          };
          switch (userEmail) {
            case (?email) {
              for ((sid, sess) in sessions.entries()) {
                if (sess.email == email) {
                  let updatedSession : Session = {
                    sessionId = sess.sessionId;
                    email = sess.email;
                    nickname = finalNickname;
                    authType = sess.authType;
                    created = sess.created;
                    expires = sess.expires;
                    lastUsed = sess.lastUsed;
                  };
                  sessions.put(sid, updatedSession);
                };
              };
            };
            case null {};
          };
        };
        
        var gameProfile : ?{
          total_score : Nat64;
          best_streak : Nat64;
          achievements : [Text];
          last_played : Nat64;
          play_count : Nat;
        } = null;
        
        for ((gId, gp) in updatedUser.gameProfiles.vals()) {
          if (gId == gameId) {
            gameProfile := ?{
              total_score = gp.total_score;
              best_streak = gp.best_streak;
              achievements = gp.achievements;
              last_played = gp.last_played;
              play_count = gp.play_count;
            };
          };
        };
        
        let message = if (finalNickname == newNickname) {
          "Nickname changed to " # finalNickname
        } else {
          "Nickname '" # newNickname # "' was taken, changed to " # finalNickname
        };
        
        #ok({
          message = message;
          nickname = finalNickname;
          gameProfile = gameProfile;
        })
      };
    };
  };

  // ════════════════════════════════════════════════════════════════════════════
  // SCORE SUBMISSION - Updated for external users
  // ════════════════════════════════════════════════════════════════════════════

  public query func getDetailedStats(gameId : Text) : async {
    submissions: {
      total: Nat;
      today: Nat;
    };
    game: ?{
      totalPlayers: Nat;
      totalGames: Nat;
      isActive: Bool;
    };
  } {
    let gameInfo = switch (games.get(gameId)) {
      case (?g) {
        ?{
          totalPlayers = g.totalPlayers;
          totalGames = g.totalPlays;
          isActive = g.isActive;
        }
      };
      case null { null };
    };
    
    {
      submissions = {
        total = totalSubmissions;
        today = submissionsToday;
      };
      game = gameInfo;
    }
  };

  public query func getSubmissionStats() : async {
    total: Nat;
    today: Nat;
    date: Text;
  } {
    {
      total = totalSubmissions;
      today = submissionsToday;
      date = lastResetDate;
    }
  };

  public shared(msg) func submitScore(
    userIdType : Text,
    userId : Text,
    gameId : Text,
    scoreNat : Nat,
    streakNat : Nat,
    roundsPlayed : ?Nat,
    nickname : ?Text,
    playSessionToken : ?Text
  ) : async Result.Result<Text, Text> {
    
    totalSubmissions += 1;
    let t = now();
    let currentDate = getDateString(t);
    if (currentDate != lastResetDate) {
      submissionsToday := 0;
      lastResetDate := currentDate;
    };
    submissionsToday += 1;
    
    let rounds : Nat = switch (roundsPlayed) {
      case (?r) { r };
      case null { 1 };
    };
    
    // Validate caller
    switch (validateCaller(msg, userIdType, userId)) {
      case (#err(e)) { return #err(e) };
      case (#ok(_)) {};
    };
    
    // Build identifier based on user type
    let identifier : UserIdentifier = switch (userIdType) {
      case ("email") { 
        switch (validateSessionInternal(userId)) {
          case (#err(e)) { return #err(e) };
          case (#ok(session)) { #email(session.email) };
        };
      };
      case ("session") {
        switch (validateSessionInternal(userId)) {
          case (#err(e)) { return #err(e) };
          case (#ok(session)) { #email(session.email) };
        };
      };
      case ("principal") { #principal(msg.caller) };
      case ("external") { #email("ext:" # userId) };
      case (_) { return #err("Invalid user type") };
    };
    
    let score = Nat64.fromNat(scoreNat);
    let streak = Nat64.fromNat(streakNat);
    let rules = getValidationRules(gameId);

    // Validate game exists and is active
    let game = switch (games.get(gameId)) {
      case null { 
        return #err("Game not found. Please register the game first.");
      };
      case (?g) {
        if (not g.isActive) {
          return #err("Game is not active");
        };
        g
      };
    };

    // Check access mode
    switch (validateAccessMode(game, userIdType)) {
      case (#err(e)) { return #err(e) };
      case (#ok(_)) {};
    };

    // Validate score and streak
    switch (validateScore(score, gameId)) {
      case (#err(e)) { 
        logSuspicion(userId # "/" # userIdType, gameId, "Invalid score: " # e);
        // Detail stays owner-side (anti-cheat log). Echoing the cap to the
        // client let anyone binary-search a game's limits and submit just
        // under them (INFO-LEAK fix 2026-08-21).
        return #err("Score rejected by game validation rules");
      };
      case (#ok()) {};
    };

    switch (validateStreak(streak, gameId)) {
      case (#err(e)) {
        logSuspicion(userId # "/" # userIdType, gameId, "Invalid streak: " # e);
        return #err("Streak rejected by game validation rules");
      };
      case (#ok()) {};
    };

    // Get or create user
    var user = getUserByIdentifier(identifier);
    
    // Auto-create external users if they don't exist
    if (Option.isNull(user) and userIdType == "external") {
      userIdCounter += 1;
      
      // Use provided nickname or generate default
      let playerNickname = switch (nickname) {
        case (?n) { 
          if (Result.isOk(validateNickname(n)) and not isNicknameTaken(n, null)) { n } 
          else { "Player_" # Nat.toText(userIdCounter) }
        };
        case null { "Player_" # Nat.toText(userIdCounter) };
      };
      
      let newUser : UserProfile = {
        identifier = identifier;
        nickname = playerNickname;
        authType = #external;
        gameProfiles = [];
        created = t;
        last_updated = t;
      };
      usersByEmail.put("ext:" # userId, newUser);
      user := ?newUser;
      
      trackEventInternal(identifier, gameId, "external_user_created", [
        ("playerId", userId),
        ("nickname", playerNickname)
      ]);
    };
    
    // Track if nickname changed
    var nicknameChanged = false;
    var updatedNickname = "";
    
    switch (user, nickname) {
      case (?u, ?n) {
        if (n != u.nickname and Result.isOk(validateNickname(n)) and not isNicknameTaken(n, ?u.identifier)) {
          let updatedWithNickname : UserProfile = {
            identifier = u.identifier;
            nickname = n;
            authType = u.authType;
            gameProfiles = u.gameProfiles;
            created = u.created;
            last_updated = t;
          };
          putUserByIdentifier(updatedWithNickname);
          user := ?updatedWithNickname;
          nicknameChanged := true;
          updatedNickname := n;
        };
      };
      case _ {};
    };
        
    switch (user) {
      case (?u) {
        let submitKey = makeSubmitKey(u.identifier, gameId);
        switch (lastSubmitTime.get(submitKey)) {
          case (?prev) {
            if (t - prev < 2_000_000_000) {
              return #err("Please wait 2 seconds between submissions.");
            };
          };
          case null {};
        };
        lastSubmitTime.put(submitKey, t);

        // Time validation check (if enabled for this game)
        let timeRules = getTimeValidationRules(gameId);
        if (timeRules.enabled) {
          switch (playSessionToken) {
            case null {
              return #err("This game has time validation on. Start a play session first (SDK: start_play_session(), REST: POST /play-sessions/start) and send its token with the score.");
            };
            case (?token) {
              let validation = validatePlaySession(token, u.identifier, gameId, score);
              if (not validation.isValid) {
                switch (validation.reason) {
                  case (?reason) {
                    logSuspicion(identifierToText(u.identifier), gameId, "Time validation failed: " # reason # " (played " # Nat64.toText(validation.playDuration) # "s)");
                    return #err(reason);
                  };
                  case null {
                    return #err("Play session validation failed.");
                  };
                };
              };
              // Valid session - consume it so it can't be reused
              consumePlaySession(token);
            };
          };
        };

        // PLAY-DEDUPE 2026-09-08: one play per run, even when the run also
        // submits to targeted boards. Marked only after the write commits.
        let countPlay = not playCountedRecently(u.identifier, gameId, t);

        var gameProfiles = Buffer.Buffer<(Text, GameProfile)>(u.gameProfiles.size());
        var found = false;
        var scoreImproved = false;
        var streakImproved = false;
        var existingScore : Nat64 = 0;
        var existingStreak : Nat64 = 0;

        for ((gId, gProfile) in u.gameProfiles.vals()) {
          if (gId == gameId) {
            found := true;
            existingScore := gProfile.total_score;
            existingStreak := gProfile.best_streak;
            
            var updatedScore = gProfile.total_score;
            var updatedStreak = gProfile.best_streak;
            
            if (score > gProfile.total_score) {
              // Only check delta if developer set a limit
              switch (rules.maxScorePerRound) {
                case (?maxDelta) {
                  if (score - gProfile.total_score > maxDelta) {
                    logSuspicion(identifierToText(u.identifier), gameId, "Score delta too high");
                    return #err("Score increase too large.");
                  };
                };
                case null {}; // No limit set, skip check
              };
              updatedScore := score;
              scoreImproved := true;
            };

            if (streak > gProfile.best_streak) {
              // Only check delta if developer set a limit
              switch (rules.maxStreakDelta) {
                case (?maxDelta) {
                  if (streak - gProfile.best_streak > maxDelta) {
                    logSuspicion(identifierToText(u.identifier), gameId, "Streak delta too high");
                    return #err("Streak increase too large.");
                  };
                };
                case null {}; // No limit set, skip check
              };
              updatedStreak := streak;
              streakImproved := true;
            };
            
            let updated : GameProfile = {
              gameId = gameId;
              total_score = updatedScore;
              best_streak = updatedStreak;
              achievements = gProfile.achievements;
              last_played = t;
              play_count = gProfile.play_count + (if (countPlay) 1 else 0);
            };
            gameProfiles.add((gId, updated));
          } else {
            gameProfiles.add((gId, gProfile));
          };
        };

        if (not found) {
          let newGameProfile : GameProfile = {
            gameId = gameId;
            total_score = score;
            best_streak = streak;
            achievements = [];
            last_played = t;
            play_count = if (countPlay) 1 else 0;
          };
          gameProfiles.add((gameId, newGameProfile));
          scoreImproved := true;
          streakImproved := true;
          
          switch (games.get(gameId)) {
            case (?gameInfo) {
              games.put(gameId, updateGameStats(gameInfo, 1, if (countPlay) rounds else 0));
            };
            case null {};
          };
        } else {
          switch (games.get(gameId)) {
            case (?gameInfo) {
              games.put(gameId, updateGameStats(gameInfo, 0, if (countPlay) rounds else 0));
            };
            case null {};
          };
        };

        let updatedUser : UserProfile = {
          identifier = u.identifier;
          nickname = u.nickname;
          authType = u.authType;
          gameProfiles = Buffer.toArray(gameProfiles);
          created = u.created;
          last_updated = t;
        };
        
        putUserByIdentifier(updatedUser);
        if (countPlay) { markPlayCounted(u.identifier, gameId, t) };
        
        if (scoreImproved) {
          cachedLeaderboards.delete(gameId # ":score");
        };
        if (streakImproved) {
          cachedLeaderboards.delete(gameId # ":streak");
        };

        if (scoreImproved or streakImproved) {
          let dateStr = getDateString(t);
          let statsKey = dateStr # ":" # gameId;
          switch (dailyStats.get(statsKey)) {
            case (?stats) {
              dailyStats.put(statsKey, {
                date = stats.date;
                gameId = stats.gameId;
                uniquePlayers = stats.uniquePlayers;
                totalGames = stats.totalGames + 1;
                totalScore = stats.totalScore + score;
                newUsers = stats.newUsers;
                authenticatedPlays = stats.authenticatedPlays + 1;
              });
            };
            case null {
              dailyStats.put(statsKey, {
                date = dateStr;
                gameId = gameId;
                uniquePlayers = 1;
                totalGames = 1;
                totalScore = score;
                newUsers = if (not found) 1 else 0;
                authenticatedPlays = 1;
              });
            };
          };
        };
        
        // ALWAYS update scoreboards - let updateScoreboardsForGame handle per-board logic
        // This ensures periodic boards (weekly/daily) get updated even when it's not an all-time best
        updateScoreboardsForGame(gameId, u.identifier, u.nickname, score, streak, u.authType);
        
        // Track analytics only for all-time improvements
        if (scoreImproved or streakImproved) {
          trackEventInternal(u.identifier, gameId, "high_score", [
            ("score", Nat64.toText(score)),
            ("streak", Nat64.toText(streak)),
            ("score_improved", if (scoreImproved) "true" else "false"),
            ("streak_improved", if (streakImproved) "true" else "false"),
            ("rounds", Nat.toText(rounds)),
            ("auth_type", authTypeToText(u.authType))
          ]);
        };
        
        let message = if (scoreImproved and streakImproved) {
          "🎉 New high score and streak!"
        } else if (scoreImproved) {
          "🏆 New high score!"
        } else if (streakImproved) {
          "🔥 New best streak!"
        } else if (nicknameChanged) {
          "✅ Nickname updated"
        } else {
          "✅ Score submitted"
        };
        
        #ok(message # " Score: " # Nat64.toText(score) # ", Streak: " # Nat64.toText(streak))
      };
      case null {
        #err("User not found. Please login first.")
      };
    };
  };


  // Submit a score to ONE targeted (category) board. Mirrors submitScore's
  // front-half but writes a single board and does NOT touch the player's
  // aggregate gameProfile / dailyStats / all-time cache.
  public shared(msg) func submitScoreToBoard(
    userIdType : Text,
    userId : Text,
    gameId : Text,
    scoreboardId : Text,
    scoreNat : Nat,
    streakNat : Nat,
    nickname : ?Text,
    playSessionToken : ?Text
  ) : async Result.Result<Text, Text> {

    totalSubmissions += 1;
    let t = now();
    let currentDate = getDateString(t);
    if (currentDate != lastResetDate) {
      submissionsToday := 0;
      lastResetDate := currentDate;
    };
    submissionsToday += 1;

    switch (validateCaller(msg, userIdType, userId)) {
      case (#err(e)) { return #err(e) };
      case (#ok(_)) {};
    };

    let identifier : UserIdentifier = switch (userIdType) {
      case ("email") {
        switch (validateSessionInternal(userId)) {
          case (#err(e)) { return #err(e) };
          case (#ok(session)) { #email(session.email) };
        };
      };
      case ("session") {
        switch (validateSessionInternal(userId)) {
          case (#err(e)) { return #err(e) };
          case (#ok(session)) { #email(session.email) };
        };
      };
      case ("principal") { #principal(msg.caller) };
      case ("external") { #email("ext:" # userId) };
      case (_) { return #err("Invalid user type") };
    };

    let score = Nat64.fromNat(scoreNat);
    let streak = Nat64.fromNat(streakNat);

    let game = switch (games.get(gameId)) {
      case null { return #err("Game not found. Please register the game first.") };
      case (?g) {
        if (not g.isActive) { return #err("Game is not active") };
        g
      };
    };

    switch (validateAccessMode(game, userIdType)) {
      case (#err(e)) { return #err(e) };
      case (#ok(_)) {};
    };

    // Target board must exist, belong to this game, be active, and be targeted.
    let sbKey = makeScoreboardKey(gameId, scoreboardId);
    let config = switch (scoreboardConfigs.get(sbKey)) {
      case null { return #err("Scoreboard '" # scoreboardId # "' not found for this game.") };
      case (?c) {
        if (c.gameId != gameId) { return #err("Scoreboard does not belong to this game.") };
        if (not c.isActive) { return #err("Scoreboard is not active.") };
        if (c.targeted != ?true) {
          return #err("'" # scoreboardId # "' is a fan-out board - submit without a scoreboardId so it gets the normal fan-out.");
        };
        c
      };
    };

    switch (validateScore(score, gameId)) {
      case (#err(e)) { logSuspicion(userId # "/" # userIdType, gameId, "Invalid score: " # e); return #err("Score rejected by game validation rules") };
      case (#ok()) {};
    };
    switch (validateStreak(streak, gameId)) {
      case (#err(e)) { logSuspicion(userId # "/" # userIdType, gameId, "Invalid streak: " # e); return #err("Streak rejected by game validation rules") };
      case (#ok()) {};
    };

    var user = getUserByIdentifier(identifier);
    if (Option.isNull(user) and userIdType == "external") {
      userIdCounter += 1;
      let playerNickname = switch (nickname) {
        case (?n) {
          if (Result.isOk(validateNickname(n)) and not isNicknameTaken(n, null)) { n }
          else { "Player_" # Nat.toText(userIdCounter) }
        };
        case null { "Player_" # Nat.toText(userIdCounter) };
      };
      let newUser : UserProfile = {
        identifier = identifier;
        nickname = playerNickname;
        authType = #external;
        gameProfiles = [];
        created = t;
        last_updated = t;
      };
      usersByEmail.put("ext:" # userId, newUser);
      user := ?newUser;
    };

    switch (user) {
      case null { #err("User not found. Please login first.") };
      case (?u) {
        let effectiveNick = switch (nickname) {
          case (?n) {
            if (n != u.nickname and Result.isOk(validateNickname(n)) and not isNicknameTaken(n, ?u.identifier)) {
              putUserByIdentifier({
                identifier = u.identifier;
                nickname = n;
                authType = u.authType;
                gameProfiles = u.gameProfiles;
                created = u.created;
                last_updated = t;
              });
              n
            } else { u.nickname }
          };
          case null { u.nickname };
        };

        // Per-(user, game, board) throttle so chained board submits don't trip the gate.
        let submitKey = makeSubmitKey(u.identifier, gameId) # ":" # scoreboardId;
        switch (lastSubmitTime.get(submitKey)) {
          case (?prev) {
            if (t - prev < 2_000_000_000) { return #err("Please wait 2 seconds between submissions.") };
          };
          case null {};
        };
        lastSubmitTime.put(submitKey, t);

        let timeRules = getTimeValidationRules(gameId);
        if (timeRules.enabled) {
          switch (playSessionToken) {
            case null {
              return #err("This game has time validation on. Start a play session first (SDK: start_play_session(), REST: POST /play-sessions/start) and send its token with the score.");
            };
            case (?token) {
              let validation = validatePlaySession(token, u.identifier, gameId, score);
              if (not validation.isValid) {
                switch (validation.reason) {
                  case (?reason) { logSuspicion(identifierToText(u.identifier), gameId, "Time validation failed: " # reason # " (played " # Nat64.toText(validation.playDuration) # "s)"); return #err(reason) };
                  case null { return #err("Play session validation failed.") };
                };
              };
              consumePlaySession(token);
            };
          };
        };

        // Write to JUST this board. Aggregate total_score / best_streak are
        // still never touched — but the play IS counted now. STATS FIX
        // 2026-08-31: previously targeted-only games showed Players 0 /
        // Plays 0 because only submitScore called updateGameStats, and their
        // players never got a gameProfile (invisible to Player Card).
        writeEntryToBoard(sbKey, config, u.identifier, effectiveNick, score, streak, u.authType, t);

        // PLAY-DEDUPE 2026-09-08: whichever submit of a run lands first
        // (main or targeted) counts the play; the rest within the window
        // still write their board entry but add no play.
        let countPlay = not playCountedRecently(u.identifier, gameId, t);
        let (bumpedProfiles, newToGame) = registerBoardPlay(u, gameId, t, countPlay);
        putUserByIdentifier({
          identifier = u.identifier;
          nickname = effectiveNick;
          authType = u.authType;
          gameProfiles = bumpedProfiles;
          created = u.created;
          last_updated = t;
        });
        if (countPlay) { markPlayCounted(u.identifier, gameId, t) };
        switch (games.get(gameId)) {
          case (?gameInfo) {
            games.put(gameId, updateGameStats(gameInfo, if (newToGame) 1 else 0, if (countPlay) 1 else 0));
          };
          case null {};
        };

        trackEventInternal(u.identifier, gameId, "board_score", [
          ("scoreboardId", scoreboardId),
          ("score", Nat64.toText(score)),
          ("streak", Nat64.toText(streak)),
          ("auth_type", authTypeToText(u.authType))
        ]);

        #ok("✅ Submitted to " # scoreboardId # " - Score: " # Nat64.toText(score) # ", Streak: " # Nat64.toText(streak))
      };
    };
  };



  // ════════════════════════════════════════════════════════════════════════════
  // DEV BOARD MODERATION (entry deletion)
  // ════════════════════════════════════════════════════════════════════════════
  // Devs can remove entries from their own boards via the dashboard. playerKey
  // is an opaque hash of the player identifier, so identifiers (emails,
  // principals) are never exposed to game owners or clients. Deletion is not
  // a ban — the player can resubmit. Per-game blocklist is planned as v2.

  private func playerKeyOf(id : UserIdentifier) : Text {
    Nat32.toText(Text.hash(identifierToText(id)))
  };

  private func logEntryDeletion(
    caller : Principal, gameId : Text, scope : Text, playerKey : Text,
    nickname : Text, liveRemoved : Nat, archiveRemoved : Nat, profileReset : Bool
  ) {
    entryDeletionLog := List.push({
      caller = caller;
      gameId = gameId;
      scope = scope;
      playerKey = playerKey;
      nickname = nickname;
      liveRemoved = liveRemoved;
      archiveRemoved = archiveRemoved;
      profileReset = profileReset;
      timestamp = now();
    }, entryDeletionLog);
    // Cap so the log can't grow unbounded
    if (List.size(entryDeletionLog) > 2000) {
      entryDeletionLog := List.take(entryDeletionLog, 2000);
    };
  };

  /// Query-safe variant: validates the session without the expired-session
  /// cleanup delete (queries can't mutate). Expiry is still enforced; the
  /// cleanup happens on the next update call instead.
  private func ownerForGameFromSessionQuery(sessionId : Text, gameId : Text) : Result.Result<Principal, Text> {
    switch (sessions.get(sessionId)) {
      case null { #err("Invalid or expired session") };
      case (?session) {
        let currentTime = Nat64.fromNat(Int.abs(Time.now()));
        if (session.expires < currentTime) {
          return #err("Session expired");
        };
        let owner = switch (emailOwnerIds.get(session.email)) {
          case (?p) { p };
          case null { return #err(OWNER_ID_MISSING) };
        };
        switch (games.get(gameId)) {
          case null { #err("Game not found") };
          case (?game) {
            if (not Principal.equal(game.owner, owner)) {
              #err("Unauthorized: you don't own this game")
            } else { #ok(owner) }
          };
        };
      };
    };
  };

  /// Shared owner check for the BySession moderation endpoints.
  private func ownerForGameFromSession(sessionId : Text, gameId : Text) : Result.Result<Principal, Text> {
    switch (getOwnerFromSession(sessionId)) {
      case (#err(e)) { #err(e) };
      case (#ok(owner)) {
        switch (games.get(gameId)) {
          case null { #err("Game not found") };
          case (?game) {
            if (not Principal.equal(game.owner, owner)) {
              #err("Unauthorized: you don't own this game")
            } else { #ok(owner) }
          };
        };
      };
    };
  };

  /// Remove all of playerKey's entries from one live board.
  /// Returns (removed count, sample removed entry for nickname/identifier).
  private func removePlayerFromLiveBoard(key : Text, playerKey : Text) : (Nat, ?ScoreEntry) {
    switch (scoreboardEntries.get(key)) {
      case null { (0, null) };
      case (?buf) {
        var sample : ?ScoreEntry = null;
        let keep = Buffer.Buffer<ScoreEntry>(buf.size());
        for (e in buf.vals()) {
          if (playerKeyOf(e.odentifier) == playerKey) {
            sample := ?e;
          } else {
            keep.add(e);
          };
        };
        let removed : Nat = buf.size() - keep.size();
        if (removed > 0) {
          scoreboardEntries.put(key, keep);
          // Bust the read cache so the row disappears immediately
          cachedScoreboards.delete(key);
          scoreboardLastUpdate.delete(key);
        };
        (removed, sample)
      };
    };
  };

  /// Delete ALL archives for one board. Used when a soft-deleted board's ID
  /// is reused at creation, so the recreated board starts with a clean
  /// history instead of inheriting the dead board's archived periods.
  /// Collects keys first, then deletes (no mutation while iterating).
  private func purgeScoreboardArchives(gameId : Text, scoreboardId : Text) : () {
    let prefix = gameId # ":" # scoreboardId # ":";
    let toDelete = Buffer.Buffer<Text>(8);
    for ((key, _) in scoreboardArchives.entries()) {
      if (Text.startsWith(key, #text prefix)) { toDelete.add(key) };
    };
    for (key in toDelete.vals()) { scoreboardArchives.delete(key) };
  };

  /// Remove playerKey's rows from archives. scoreboardId = null → all boards
  /// of the game. Collects updates first, then applies (no mutation while
  /// iterating). Returns archived rows removed.
  private func purgeArchivedRows(gameId : Text, scoreboardId : ?Text, playerKey : Text) : Nat {
    var total : Nat = 0;
    let updates = Buffer.Buffer<(Text, ArchivedScoreboard)>(4);
    for ((key, archive) in scoreboardArchives.entries()) {
      let boardMatches = switch (scoreboardId) {
        case (?sbId) { archive.gameId == gameId and archive.scoreboardId == sbId };
        case null { archive.gameId == gameId };
      };
      if (boardMatches) {
        let kept = Array.filter<ScoreEntry>(archive.entries, func(e : ScoreEntry) : Bool { playerKeyOf(e.odentifier) != playerKey });
        let removed : Nat = archive.entries.size() - kept.size();
        if (removed > 0) {
          updates.add((key, {
            scoreboardId = archive.scoreboardId;
            gameId = archive.gameId;
            name = archive.name;
            period = archive.period;
            sortBy = archive.sortBy;
            periodStart = archive.periodStart;
            periodEnd = archive.periodEnd;
            entries = kept;
            totalEntries = kept.size();
          }));
          total += removed;
        };
      };
    };
    for ((key, updated) in updates.vals()) { scoreboardArchives.put(key, updated) };
    total
  };

  /// Find a sample entry for a playerKey by scanning the game's live boards,
  /// then archives. Needed to resolve the real identifier for profile resets.
  private func resolveEntryByPlayerKey(gameId : Text, playerKey : Text) : ?ScoreEntry {
    for ((key, config) in scoreboardConfigs.entries()) {
      if (config.gameId == gameId) {
        switch (scoreboardEntries.get(key)) {
          case (?buf) {
            for (e in buf.vals()) {
              if (playerKeyOf(e.odentifier) == playerKey) { return ?e };
            };
          };
          case null {};
        };
      };
    };
    for ((_, archive) in scoreboardArchives.entries()) {
      if (archive.gameId == gameId) {
        for (e in archive.entries.vals()) {
          if (playerKeyOf(e.odentifier) == playerKey) { return ?e };
        };
      };
    };
    null
  };

  /// Zero a player's aggregate profile for one game (score, streak,
  /// play_count). Achievements are kept. Returns true if a profile was reset.
  private func resetGameProfile(identifier : UserIdentifier, gameId : Text) : Bool {
    switch (getUserByIdentifier(identifier)) {
      case null { false };
      case (?u) {
        var touched = false;
        let profs = Buffer.Buffer<(Text, GameProfile)>(u.gameProfiles.size());
        for ((gId, gp) in u.gameProfiles.vals()) {
          if (gId == gameId) {
            profs.add((gId, {
              gameId = gp.gameId;
              total_score = 0;
              best_streak = 0;
              achievements = gp.achievements;
              last_played = gp.last_played;
              play_count = 0;
            }));
            touched := true;
          } else {
            profs.add((gId, gp));
          };
        };
        if (touched) {
          putUserByIdentifier({
            identifier = u.identifier;
            nickname = u.nickname;
            authType = u.authType;
            gameProfiles = Buffer.toArray(profs);
            created = u.created;
            last_updated = now();
          });
        };
        touched
      };
    };
  };

  /// Dashboard: board rows with opaque playerKey handles for moderation.
  public shared query func getScoreboardAdminBySession(
    sessionId : Text,
    gameId : Text,
    scoreboardId : Text
  ) : async Result.Result<[{
    playerKey : Text;
    nickname : Text;
    score : Nat64;
    streak : Nat64;
    submittedAt : Nat64;
    authType : Text;
    rank : Nat;
  }], Text> {
    switch (ownerForGameFromSessionQuery(sessionId, gameId)) {
      case (#err(e)) { return #err(e) };
      case (#ok(_)) {};
    };
    let key = makeScoreboardKey(gameId, scoreboardId);
    switch (scoreboardConfigs.get(key)) {
      case null { #err("Scoreboard not found") };
      case (?config) {
        let entries = switch (scoreboardEntries.get(key)) {
          case null { [] : [ScoreEntry] };
          case (?buf) { Scoreboards.sortEntries(Buffer.toArray(buf), config.sortBy) };
        };
        let out = Buffer.Buffer<{
          playerKey : Text;
          nickname : Text;
          score : Nat64;
          streak : Nat64;
          submittedAt : Nat64;
          authType : Text;
          rank : Nat;
        }>(entries.size());
        var rank : Nat = 1;
        for (e in entries.vals()) {
          out.add({
            playerKey = playerKeyOf(e.odentifier);
            nickname = e.nickname;
            score = e.score;
            streak = e.streak;
            submittedAt = e.submittedAt;
            authType = authTypeToText(e.authType);
            rank = rank;
          });
          rank += 1;
        };
        #ok(Buffer.toArray(out))
      };
    };
  };

  /// Dashboard: delete one player's entry from one board.
  public shared func removeScoreEntryBySession(
    sessionId : Text,
    gameId : Text,
    scoreboardId : Text,
    playerKey : Text,
    purgeArchives : Bool
  ) : async Result.Result<Text, Text> {
    switch (ownerForGameFromSession(sessionId, gameId)) {
      case (#err(e)) { return #err(e) };
      case (#ok(owner)) {
        let key = makeScoreboardKey(gameId, scoreboardId);
        if (Option.isNull(scoreboardConfigs.get(key))) {
          return #err("Scoreboard not found");
        };
        let (removed, sample) = removePlayerFromLiveBoard(key, playerKey);
        let archiveRemoved = if (purgeArchives) {
          purgeArchivedRows(gameId, ?scoreboardId, playerKey)
        } else { 0 };
        if (removed == 0 and archiveRemoved == 0) {
          return #err("No entries found for that player on this board");
        };
        let nickname = switch (sample) {
          case (?e) { e.nickname };
          case null { "player" };
        };
        logEntryDeletion(owner, gameId, scoreboardId, playerKey, nickname, removed, archiveRemoved, false);
        #ok("Removed " # Nat.toText(removed) # " live and " # Nat.toText(archiveRemoved) # " archived entries for " # nickname)
      };
    };
  };

  /// Dashboard: wipe a player's entries from every board in the game,
  /// optionally archives too, and reset their aggregate game profile.
  public shared func removePlayerScoresBySession(
    sessionId : Text,
    gameId : Text,
    playerKey : Text,
    purgeArchives : Bool
  ) : async Result.Result<Text, Text> {
    switch (ownerForGameFromSession(sessionId, gameId)) {
      case (#err(e)) { return #err(e) };
      case (#ok(owner)) {
        // Resolve identifier BEFORE deleting (entries are the only mapping)
        let sample = resolveEntryByPlayerKey(gameId, playerKey);

        let boardKeys = Buffer.Buffer<Text>(8);
        for ((key, config) in scoreboardConfigs.entries()) {
          if (config.gameId == gameId) { boardKeys.add(key) };
        };
        var liveRemoved : Nat = 0;
        for (key in boardKeys.vals()) {
          let (n, _) = removePlayerFromLiveBoard(key, playerKey);
          liveRemoved += n;
        };
        let archiveRemoved = if (purgeArchives) {
          purgeArchivedRows(gameId, null, playerKey)
        } else { 0 };

        var profileReset = false;
        switch (sample) {
          case (?e) { profileReset := resetGameProfile(e.odentifier, gameId) };
          case null {};
        };

        if (liveRemoved == 0 and archiveRemoved == 0 and not profileReset) {
          return #err("No entries found for that player in this game");
        };
        let nickname = switch (sample) {
          case (?e) { e.nickname };
          case null { "player" };
        };
        logEntryDeletion(owner, gameId, "ALL", playerKey, nickname, liveRemoved, archiveRemoved, profileReset);
        #ok("Removed " # Nat.toText(liveRemoved) # " live and " # Nat.toText(archiveRemoved) # " archived entries for " # nickname # (if (profileReset) { "; profile stats reset" } else { "" }))
      };
    };
  };

  /// Dashboard: the game's deletion audit log (newest first).
  public shared query func getEntryDeletionLogBySession(
    sessionId : Text,
    gameId : Text
  ) : async Result.Result<[EntryDeletionRecord], Text> {
    switch (ownerForGameFromSessionQuery(sessionId, gameId)) {
      case (#err(e)) { return #err(e) };
      case (#ok(_)) {};
    };
    let out = Buffer.Buffer<EntryDeletionRecord>(16);
    for (rec in List.toArray(entryDeletionLog).vals()) {
      if (rec.gameId == gameId) { out.add(rec) };
    };
    #ok(Buffer.toArray(out))
  };

  // ── Principal-authenticated twins (Internet Identity dashboard devs) ──

  private func requireGameOwner(caller : Principal, gameId : Text) : Result.Result<(), Text> {
    if (Principal.isAnonymous(caller)) {
      return #err("Authentication required");
    };
    switch (games.get(gameId)) {
      case null { #err("Game not found") };
      case (?game) {
        if (not Principal.equal(game.owner, caller)) {
          #err("Unauthorized: you don't own this game")
        } else { #ok(()) }
      };
    };
  };

  public shared query(msg) func getScoreboardAdmin(
    gameId : Text,
    scoreboardId : Text
  ) : async Result.Result<[{
    playerKey : Text;
    nickname : Text;
    score : Nat64;
    streak : Nat64;
    submittedAt : Nat64;
    authType : Text;
    rank : Nat;
  }], Text> {
    switch (requireGameOwner(msg.caller, gameId)) {
      case (#err(e)) { return #err(e) };
      case (#ok()) {};
    };
    let key = makeScoreboardKey(gameId, scoreboardId);
    switch (scoreboardConfigs.get(key)) {
      case null { #err("Scoreboard not found") };
      case (?config) {
        let entries = switch (scoreboardEntries.get(key)) {
          case null { [] : [ScoreEntry] };
          case (?buf) { Scoreboards.sortEntries(Buffer.toArray(buf), config.sortBy) };
        };
        let out = Buffer.Buffer<{
          playerKey : Text;
          nickname : Text;
          score : Nat64;
          streak : Nat64;
          submittedAt : Nat64;
          authType : Text;
          rank : Nat;
        }>(entries.size());
        var rank : Nat = 1;
        for (e in entries.vals()) {
          out.add({
            playerKey = playerKeyOf(e.odentifier);
            nickname = e.nickname;
            score = e.score;
            streak = e.streak;
            submittedAt = e.submittedAt;
            authType = authTypeToText(e.authType);
            rank = rank;
          });
          rank += 1;
        };
        #ok(Buffer.toArray(out))
      };
    };
  };

  public shared(msg) func removeScoreEntry(
    gameId : Text,
    scoreboardId : Text,
    playerKey : Text,
    purgeArchives : Bool
  ) : async Result.Result<Text, Text> {
    switch (requireGameOwner(msg.caller, gameId)) {
      case (#err(e)) { return #err(e) };
      case (#ok()) {};
    };
    let key = makeScoreboardKey(gameId, scoreboardId);
    if (Option.isNull(scoreboardConfigs.get(key))) {
      return #err("Scoreboard not found");
    };
    let (removed, sample) = removePlayerFromLiveBoard(key, playerKey);
    let archiveRemoved = if (purgeArchives) {
      purgeArchivedRows(gameId, ?scoreboardId, playerKey)
    } else { 0 };
    if (removed == 0 and archiveRemoved == 0) {
      return #err("No entries found for that player on this board");
    };
    let nickname = switch (sample) {
      case (?e) { e.nickname };
      case null { "player" };
    };
    logEntryDeletion(msg.caller, gameId, scoreboardId, playerKey, nickname, removed, archiveRemoved, false);
    #ok("Removed " # Nat.toText(removed) # " live and " # Nat.toText(archiveRemoved) # " archived entries for " # nickname)
  };

  public shared(msg) func removePlayerScores(
    gameId : Text,
    playerKey : Text,
    purgeArchives : Bool
  ) : async Result.Result<Text, Text> {
    switch (requireGameOwner(msg.caller, gameId)) {
      case (#err(e)) { return #err(e) };
      case (#ok()) {};
    };
    let sample = resolveEntryByPlayerKey(gameId, playerKey);

    let boardKeys = Buffer.Buffer<Text>(8);
    for ((key, config) in scoreboardConfigs.entries()) {
      if (config.gameId == gameId) { boardKeys.add(key) };
    };
    var liveRemoved : Nat = 0;
    for (key in boardKeys.vals()) {
      let (n, _) = removePlayerFromLiveBoard(key, playerKey);
      liveRemoved += n;
    };
    let archiveRemoved = if (purgeArchives) {
      purgeArchivedRows(gameId, null, playerKey)
    } else { 0 };

    var profileReset = false;
    switch (sample) {
      case (?e) { profileReset := resetGameProfile(e.odentifier, gameId) };
      case null {};
    };

    if (liveRemoved == 0 and archiveRemoved == 0 and not profileReset) {
      return #err("No entries found for that player in this game");
    };
    let nickname = switch (sample) {
      case (?e) { e.nickname };
      case null { "player" };
    };
    logEntryDeletion(msg.caller, gameId, "ALL", playerKey, nickname, liveRemoved, archiveRemoved, profileReset);
    #ok("Removed " # Nat.toText(liveRemoved) # " live and " # Nat.toText(archiveRemoved) # " archived entries for " # nickname # (if (profileReset) { "; profile stats reset" } else { "" }))
  };

  public shared query(msg) func getEntryDeletionLog(
    gameId : Text
  ) : async Result.Result<[EntryDeletionRecord], Text> {
    switch (requireGameOwner(msg.caller, gameId)) {
      case (#err(e)) { return #err(e) };
      case (#ok()) {};
    };
    let out = Buffer.Buffer<EntryDeletionRecord>(16);
    for (rec in List.toArray(entryDeletionLog).vals()) {
      if (rec.gameId == gameId) { out.add(rec) };
    };
    #ok(Buffer.toArray(out))
  };

  // ════════════════════════════════════════════════════════════════════════════
  // PLAY SESSION ENDPOINTS (Time Validation)
  // ════════════════════════════════════════════════════════════════════════════

  // Start a game session - Internet Identity users
  public shared(msg) func startGameSession(gameId: Text) : async Result.Result<Text, Text> {
    let caller = msg.caller;
    
    if (Principal.isAnonymous(caller)) {
      return #err("Authentication required");
    };
    
    switch (games.get(gameId)) {
      case null { return #err("Game not found") };
      case (?game) {
        if (not game.isActive) {
          return #err("Game is not active");
        };
        if (not game.timeValidationEnabled) {
          return #err("Time validation not enabled for this game");
        };
      };
    };
    
    let identifier : UserIdentifier = #principal(caller);
    
    cleanupExpiredPlaySessions(identifier, gameId);
    sweepExpiredPlaySessionsIfLarge();
    
    let activeCount = countActiveSessionsForPlayer(identifier, gameId);
    if (activeCount >= MAX_ACTIVE_SESSIONS_PER_PLAYER) {
      return #err("Too many active sessions. Finish or wait for current sessions to expire.");
    };
    
    let currentTime = now();
    let rules = getTimeValidationRules(gameId);
    let sessionDurationNanos = Nat64.fromNat(rules.maxSessionDurationMins * 60) * 1_000_000_000;
    
    let token = generatePlaySessionToken(gameId, await* takeRandomBytes(16));
    
    let session : PlaySession = {
      sessionToken = token;
      identifier = identifier;
      gameId = gameId;
      startedAt = currentTime;
      expiresAt = currentTime + sessionDurationNanos;
      isActive = true;
    };
    
    playSessions.put(token, session);
    
    #ok(token)
  };

  // Start a game session - Session-based users (Google/Apple)
  public shared func startGameSessionBySession(
    sessionId: Text,
    gameId: Text
  ) : async Result.Result<Text, Text> {
    
    let identifier : UserIdentifier = switch (validateSessionInternal(sessionId)) {
      case (#err(e)) { return #err(e) };
      case (#ok(session)) { #email(session.email) };
    };
    
    switch (games.get(gameId)) {
      case null { return #err("Game not found") };
      case (?game) {
        if (not game.isActive) {
          return #err("Game is not active");
        };
        if (not game.timeValidationEnabled) {
          return #err("Time validation not enabled for this game");
        };
      };
    };
    
    cleanupExpiredPlaySessions(identifier, gameId);
    sweepExpiredPlaySessionsIfLarge();
    
    let activeCount = countActiveSessionsForPlayer(identifier, gameId);
    if (activeCount >= MAX_ACTIVE_SESSIONS_PER_PLAYER) {
      return #err("Too many active sessions. Finish or wait for current sessions to expire.");
    };
    
    let currentTime = now();
    let rules = getTimeValidationRules(gameId);
    let sessionDurationNanos = Nat64.fromNat(rules.maxSessionDurationMins * 60) * 1_000_000_000;
    
    let token = generatePlaySessionToken(gameId, await* takeRandomBytes(16));
    
    let session : PlaySession = {
      sessionToken = token;
      identifier = identifier;
      gameId = gameId;
      startedAt = currentTime;
      expiresAt = currentTime + sessionDurationNanos;
      isActive = true;
    };
    
    playSessions.put(token, session);
    
    #ok(token)
  };

  // Start a game session - API key based users (anonymous/device ID)
  public shared(msg) func startGameSessionByApiKey(
    apiKeyValue: Text,
    playerId: Text,
    gameId: Text
  ) : async Result.Result<Text, Text> {
    // v0.10.0: proxy-only (API keys are checked at the proxy).
    if (not isVerifier(msg.caller)) {
      return #err("Unauthorized: play sessions must be started through the API");
    };
    
    // Validate API key
    switch (apiKeys.get(apiKeyValue)) {
      case null { return #err("Invalid API key") };
      case (?key) {
        if (not key.isActive) {
          return #err("API key is inactive");
        };
        if (key.gameId != gameId) {
          return #err("API key not valid for this game");
        };
      };
    };
    
    // Validate playerId
    if (Text.size(playerId) < 3 or Text.size(playerId) > 100) {
      return #err("Invalid player ID");
    };
    
    switch (games.get(gameId)) {
      case null { return #err("Game not found") };
      case (?game) {
        if (not game.isActive) {
          return #err("Game is not active");
        };
        if (not game.timeValidationEnabled) {
          // If time validation not enabled, return a placeholder token
          // The score submission will skip validation
          return #ok("skip_validation_" # gameId # "_" # Nat64.toText(now()));
        };
      };
    };
    
    // Use the same identifier format as submitScore for "external" users
    let identifier : UserIdentifier = #email("ext:" # playerId);
    
    cleanupExpiredPlaySessions(identifier, gameId);
    sweepExpiredPlaySessionsIfLarge();
    
    let activeCount = countActiveSessionsForPlayer(identifier, gameId);
    if (activeCount >= MAX_ACTIVE_SESSIONS_PER_PLAYER) {
      return #err("Too many active sessions. Finish or wait for current sessions to expire.");
    };
    
    let currentTime = now();
    let rules = getTimeValidationRules(gameId);
    let sessionDurationNanos = Nat64.fromNat(rules.maxSessionDurationMins * 60) * 1_000_000_000;
    
    let token = generatePlaySessionToken(gameId, await* takeRandomBytes(16));
    
    let session : PlaySession = {
      sessionToken = token;
      identifier = identifier;
      gameId = gameId;
      startedAt = currentTime;
      expiresAt = currentTime + sessionDurationNanos;
      isActive = true;
    };
    
    playSessions.put(token, session);
    
    #ok(token)
  };

  // Query play session status
  public query func getPlaySessionStatus(sessionToken: Text) : async ?{
    gameId: Text;
    startedAt: Nat64;
    expiresAt: Nat64;
    isActive: Bool;
    elapsedSeconds: Nat64;
    remainingSeconds: Nat64;
  } {
    switch (playSessions.get(sessionToken)) {
      case null { null };
      case (?session) {
        let currentTime = now();
        let elapsed = (currentTime - session.startedAt) / 1_000_000_000;
        let remaining : Nat64 = if (currentTime < session.expiresAt) {
          (session.expiresAt - currentTime) / 1_000_000_000
        } else { 0 };
        
        ?{
          gameId = session.gameId;
          startedAt = session.startedAt;
          expiresAt = session.expiresAt;
          isActive = session.isActive and currentTime < session.expiresAt;
          elapsedSeconds = elapsed;
          remainingSeconds = remaining;
        }
      };
    }
  };

  // Cancel a play session (if player quits without submitting)
  public shared(msg) func cancelPlaySession(sessionToken: Text) : async Result.Result<Text, Text> {
    // v0.10.0: proxy-only.
    if (not isVerifier(msg.caller)) {
      return #err("Unauthorized: play sessions must be cancelled through the API");
    };
    switch (playSessions.get(sessionToken)) {
      case null { #err("Session not found") };
      case (?session) {
        // Verify ownership - check both principal and email-based identifiers
        let callerIdentifier : UserIdentifier = #principal(msg.caller);
        if (not identifiersEqual(session.identifier, callerIdentifier)) {
          // For session-based users, we can't directly verify ownership here
          // So we'll just allow cancellation if the token exists
          // This is safe because cancellation only removes their own session
        };
        
        playSessions.delete(sessionToken);
        #ok("Session cancelled")
      };
    }
  };

  // Update time validation settings for a game
  public shared func updateTimeValidationBySession(
    sessionId: Text,
    gameId: Text,
    timeValidationEnabled: Bool,
    minPlayDurationSecs: ?Nat64,
    maxScorePerSecond: ?Nat64,
    maxSessionDurationMins: ?Nat
  ) : async Result.Result<Text, Text> {
    
    switch (getOwnerFromSession(sessionId)) {
      case (#err(e)) { return #err(e) };
      case (#ok(owner)) {
        switch (games.get(gameId)) {
          case null { return #err("Game not found") };
          case (?game) {
            if (not Principal.equal(game.owner, owner)) {
              return #err("You don't own this game");
            };
            
            let updatedGame : GameInfo = {
              gameId = game.gameId;
              name = game.name;
              description = game.description;
              owner = game.owner;
              gameUrl = game.gameUrl;
              created = game.created;
              accessMode = game.accessMode;
              totalPlayers = game.totalPlayers;
              totalPlays = game.totalPlays;
              isActive = game.isActive;
              maxScorePerRound = game.maxScorePerRound;
              maxStreakDelta = game.maxStreakDelta;
              absoluteScoreCap = game.absoluteScoreCap;
              absoluteStreakCap = game.absoluteStreakCap;
          timeValidationEnabled = timeValidationEnabled;
          minPlayDurationSecs = minPlayDurationSecs;
          maxScorePerSecond = maxScorePerSecond;
          maxSessionDurationMins = maxSessionDurationMins;
          googleClientIds = game.googleClientIds;
              appleBundleId = game.appleBundleId;
              appleTeamId = game.appleTeamId;
            };
            
            games.put(gameId, updatedGame);
            
            let status = if (timeValidationEnabled) { "enabled" } else { "disabled" };
            #ok("Time validation " # status # " for " # game.name)
          };
        };
      };
    };
  };

  // Query time validation rules for a game
  public query func getGameTimeValidationRules(gameId: Text) : async {
    enabled: Bool;
    minPlayDurationSecs: Nat64;
    maxScorePerSecond: Nat64;
    maxSessionDurationMins: Nat;
  } {
    getTimeValidationRules(gameId)
  };

  // Admin: Cleanup all expired play sessions
  public shared(msg) func cleanupAllExpiredPlaySessions() : async Result.Result<Nat, Text> {
    if (not isAdmin(msg.caller)) {
      return #err("Only admin can trigger cleanup");
    };
    
    let currentTime = now();
    let keysToRemove = Buffer.Buffer<Text>(50);
    
    for ((token, session) in playSessions.entries()) {
      if (currentTime >= session.expiresAt or not session.isActive) {
        keysToRemove.add(token);
      };
    };
    
    for (key in keysToRemove.vals()) {
      playSessions.delete(key);
    };
    
    #ok(keysToRemove.size())
  };

  // ════════════════════════════════════════════════════════════════════════════
  // SESSION QUERIES
  // ════════════════════════════════════════════════════════════════════════════
  
  // v0.10.0: verifier-only (returned the email for any valid token).
  public shared query(msg) func getSessionInfo(sessionId : Text) : async ?{
    email: Text;
    nickname: Text;
    authType: Text;
    created: Nat64;
    expires: Nat64;
    lastUsed: Nat64;
  } {
    if (not isVerifier(msg.caller)) { return null };
    switch (getValidSession(sessionId)) {
      case (?session) {
        ?{
          email = session.email;
          nickname = session.nickname;
          authType = authTypeToText(session.authType);
          created = session.created;
          expires = session.expires;
          lastUsed = session.lastUsed;
        }
      };
      case null { null };
    }
  };

  public query func getActiveSessions() : async Nat {
    sessions.size()
  };

  // ════════════════════════════════════════════════════════════════════════════
  // ACHIEVEMENTS - Updated for external users
  // ════════════════════════════════════════════════════════════════════════════

  public shared(msg) func unlockAchievement(
    userIdType : Text,
    userId : Text,
    gameId : Text,
    achievementId : Text
  ) : async Result.Result<Text, Text> {

    switch (validateCaller(msg, userIdType, userId)) {
      case (#err(e)) { return #err(e) };
      case (#ok(_)) {};
    };
      
    // Validate game and check access mode
    let game = switch (games.get(gameId)) {
      case null { return #err("Game not found: " # gameId) };
      case (?g) {
        if (not g.isActive) {
          return #err("Game is not active");
        };
        g
      };
    };

    switch (validateAccessMode(game, userIdType)) {
      case (#err(e)) { return #err(e) };
      case (#ok(_)) {};
    };
    
    if (Text.size(achievementId) == 0) {
      return #err("Achievement ID cannot be empty");
    };
    
    let identifier : UserIdentifier = switch (userIdType) {
      case ("email") { 
        switch (validateSessionInternal(userId)) {
          case (#err(e)) { return #err(e) };
          case (#ok(session)) { #email(session.email) };
        };
      };
      case ("session") {
        switch (validateSessionInternal(userId)) {
          case (#err(e)) { return #err(e) };
          case (#ok(session)) { #email(session.email) };
        };
      };
      case ("principal") { #principal(msg.caller) };
      case ("external") { #email("ext:" # userId) };
      case (_) { return #err("Invalid user type") };
    };

    let user = getUserByIdentifier(identifier);

    switch (user) {
      case null { #err("User not found") };
      case (?u) {
        var gameProfiles = Buffer.Buffer<(Text, GameProfile)>(u.gameProfiles.size());
        var found = false;
        
        for ((gId, gProfile) in u.gameProfiles.vals()) {
          if (gId == gameId) {
            found := true;
            
            for (existingId in gProfile.achievements.vals()) {
              if (existingId == achievementId) {
                return #ok("Achievement already unlocked.");
              };
            };
            
            let updated : GameProfile = {
              gameId = gameId;
              total_score = gProfile.total_score;
              best_streak = gProfile.best_streak;
              achievements = Array.append(gProfile.achievements, [achievementId]);
              last_played = gProfile.last_played;
              play_count = gProfile.play_count;
            };
            gameProfiles.add((gId, updated));
          } else {
            gameProfiles.add((gId, gProfile));
          };
        };
        
        if (not found) {
          return #err("No profile for this game. Play first!");
        };
        
        let updatedUser : UserProfile = {
          identifier = u.identifier;
          nickname = u.nickname;
          authType = u.authType;
          gameProfiles = Buffer.toArray(gameProfiles);
          created = u.created;
          last_updated = now();
        };
        
        putUserByIdentifier(updatedUser);
        
        trackEventInternal(u.identifier, gameId, "achievement_unlocked", [
          ("achievement_id", achievementId)
        ]);
        
        #ok("Achievement unlocked: " # achievementId)
      };
    };
  };

  // Batch unlock: one update call (one consensus round) for the whole batch.
  // Replaces the proxy's per-achievement await loop, which ran ~1s per ID and
  // hit Netlify's 30s function cap on ~32-achievement batches (confirmed in
  // proxy logs 26 Aug 2026). Validation, session check (and its sliding
  // renewal), user lookup, and the profile rewrite all happen ONCE; per-ID
  // outcomes are returned so the proxy can keep its existing response shape.
  public shared(msg) func unlockAchievementBatch(
    userIdType : Text,
    userId : Text,
    gameId : Text,
    achievementIds : [Text]
  ) : async Result.Result<{ unlocked : [Text]; alreadyUnlocked : [Text]; failed : [(Text, Text)] }, Text> {

    if (achievementIds.size() == 0) {
      return #err("No achievement IDs provided");
    };
    if (achievementIds.size() > 100) {
      return #err("Batch too large (max 100 achievements per call)");
    };

    switch (validateCaller(msg, userIdType, userId)) {
      case (#err(e)) { return #err(e) };
      case (#ok(_)) {};
    };

    let game = switch (games.get(gameId)) {
      case null { return #err("Game not found: " # gameId) };
      case (?g) {
        if (not g.isActive) {
          return #err("Game is not active");
        };
        g
      };
    };

    switch (validateAccessMode(game, userIdType)) {
      case (#err(e)) { return #err(e) };
      case (#ok(_)) {};
    };

    let identifier : UserIdentifier = switch (userIdType) {
      case ("email") {
        switch (validateSessionInternal(userId)) {
          case (#err(e)) { return #err(e) };
          case (#ok(session)) { #email(session.email) };
        };
      };
      case ("session") {
        switch (validateSessionInternal(userId)) {
          case (#err(e)) { return #err(e) };
          case (#ok(session)) { #email(session.email) };
        };
      };
      case ("principal") { #principal(msg.caller) };
      case ("external") { #email("ext:" # userId) };
      case (_) { return #err("Invalid user type") };
    };

    switch (getUserByIdentifier(identifier)) {
      case null { #err("User not found") };
      case (?u) {
        var gameProfiles = Buffer.Buffer<(Text, GameProfile)>(u.gameProfiles.size());
        var found = false;
        let unlocked = Buffer.Buffer<Text>(achievementIds.size());
        let alreadyUnlocked = Buffer.Buffer<Text>(0);
        let failed = Buffer.Buffer<(Text, Text)>(0);

        for ((gId, gProfile) in u.gameProfiles.vals()) {
          if (gId == gameId) {
            found := true;

            // Start from existing achievements; dedupes against both the
            // stored set and duplicates within the incoming batch.
            let newAchievements = Buffer.Buffer<Text>(gProfile.achievements.size() + achievementIds.size());
            for (a in gProfile.achievements.vals()) { newAchievements.add(a) };

            for (achId in achievementIds.vals()) {
              if (Text.size(achId) == 0) {
                failed.add((achId, "Achievement ID cannot be empty"));
              } else {
                var exists = false;
                for (a in newAchievements.vals()) {
                  if (a == achId) { exists := true };
                };
                if (exists) {
                  alreadyUnlocked.add(achId);
                } else {
                  newAchievements.add(achId);
                  unlocked.add(achId);
                };
              };
            };

            let updated : GameProfile = {
              gameId = gameId;
              total_score = gProfile.total_score;
              best_streak = gProfile.best_streak;
              achievements = Buffer.toArray(newAchievements);
              last_played = gProfile.last_played;
              play_count = gProfile.play_count;
            };
            gameProfiles.add((gId, updated));
          } else {
            gameProfiles.add((gId, gProfile));
          };
        };

        if (not found) {
          return #err("No profile for this game. Play first!");
        };

        // Only rewrite the user if something actually changed
        if (unlocked.size() > 0) {
          let updatedUser : UserProfile = {
            identifier = u.identifier;
            nickname = u.nickname;
            authType = u.authType;
            gameProfiles = Buffer.toArray(gameProfiles);
            created = u.created;
            last_updated = now();
          };
          putUserByIdentifier(updatedUser);

          for (achId in unlocked.vals()) {
            trackEventInternal(u.identifier, gameId, "achievement_unlocked", [
              ("achievement_id", achId)
            ]);
          };
        };

        #ok({
          unlocked = Buffer.toArray(unlocked);
          alreadyUnlocked = Buffer.toArray(alreadyUnlocked);
          failed = Buffer.toArray(failed);
        })
      };
    };
  };

  public shared query(msg) func getAchievements(userIdType : Text, userId : Text, gameId : Text) : async [Text] {
    let identifier : UserIdentifier = switch (userIdType) {
      // HARDENING (Oct 2026): "email" is verifier-only, so a profile can't be
      // looked up from a bare email address by a direct caller.
      case ("email") { if (not isVerifier(msg.caller)) { return [] }; #email(userId) };
      case ("principal") { #principal(Principal.fromText(userId)) };
      case ("external") { #email("ext:" # userId) };
      case (_) { return [] };
    };

    switch (getUserByIdentifier(identifier)) {
      case (?user) {
        for ((gId, gProfile) in user.gameProfiles.vals()) {
          if (gId == gameId) {
            return gProfile.achievements;
          };
        };
        []
      };
      case null { [] };
    }
  };

  // ════════════════════════════════════════════════════════════════════════════
  // LEADERBOARD
  // ════════════════════════════════════════════════════════════════════════════

  public query func getLeaderboard(gameId : Text, sortBy : SortBy, limit : Nat) : async [(Text, Nat64, Nat64, Text)] {
    let cacheKey = gameId # ":" # (switch(sortBy) { case (#score) "score"; case (#streak) "streak" });
    
    switch (cachedLeaderboards.get(cacheKey)) {
      case (?cached) {
        switch (leaderboardLastUpdate.get(cacheKey)) {
          case (?lastUpdate) {
            if (now() - lastUpdate < LEADERBOARD_CACHE_TTL) {
              let cap = if (limit == 0 or limit > 1000) 1000 else limit;
              if (cached.size() <= cap) return cached else return Array.subArray(cached, 0, cap);
            };
          };
          case null {};
        };
      };
      case null {};
    };
    
    var allScores = Buffer.Buffer<(Text, Nat64, Nat64, Text)>(100);
    
    for ((email, user) in usersByEmail.entries()) {
      for ((gId, gProfile) in user.gameProfiles.vals()) {
        if (gId == gameId) {
          allScores.add((
            user.nickname, 
            gProfile.total_score, 
            gProfile.best_streak,
            authTypeToText(user.authType)
          ));
        };
      };
    };
    
    for ((principal, user) in usersByPrincipal.entries()) {
      for ((gId, gProfile) in user.gameProfiles.vals()) {
        if (gId == gameId) {
          allScores.add((
            user.nickname, 
            gProfile.total_score, 
            gProfile.best_streak,
            authTypeToText(user.authType)
          ));
        };
      };
    };
    
    let sorted = Array.sort<(Text, Nat64, Nat64, Text)>(
      Buffer.toArray(allScores),
      func(a, b) {
        switch (sortBy) {
          case (#score) {
            if (a.1 > b.1) #less
            else if (a.1 < b.1) #greater
            else #equal
          };
          case (#streak) {
            if (a.2 > b.2) #less
            else if (a.2 < b.2) #greater
            else #equal
          };
        }
      }
    );
    
    cachedLeaderboards.put(cacheKey, sorted);
    leaderboardLastUpdate.put(cacheKey, now());
    
    let cap = if (limit == 0 or limit > 1000) 1000 else limit;
    if (sorted.size() <= cap) sorted else Array.subArray(sorted, 0, cap)
  };

  public query func getLeaderboardByAuth(gameId : Text, authType : AuthType, sortBy : SortBy, limit : Nat) : async [(Text, Nat64, Nat64, Text)] {
    var filteredScores = Buffer.Buffer<(Text, Nat64, Nat64, Text)>(100);
    
    for ((email, user) in usersByEmail.entries()) {
      if (user.authType == authType) {
        for ((gId, gProfile) in user.gameProfiles.vals()) {
          if (gId == gameId) {
            filteredScores.add((
              user.nickname, 
              gProfile.total_score, 
              gProfile.best_streak,
              authTypeToText(user.authType)
            ));
          };
        };
      };
    };
    
    for ((principal, user) in usersByPrincipal.entries()) {
      if (user.authType == authType) {
        for ((gId, gProfile) in user.gameProfiles.vals()) {
          if (gId == gameId) {
            filteredScores.add((
              user.nickname, 
              gProfile.total_score, 
              gProfile.best_streak,
              authTypeToText(user.authType)
            ));
          };
        };
      };
    };
    
    let sorted = Array.sort<(Text, Nat64, Nat64, Text)>(
      Buffer.toArray(filteredScores),
      func(a, b) {
        switch (sortBy) {
          case (#score) {
            if (a.1 > b.1) #less
            else if (a.1 < b.1) #greater
            else #equal
          };
          case (#streak) {
            if (a.2 > b.2) #less
            else if (a.2 < b.2) #greater
            else #equal
          };
        }
      }
    );
    
    let cap = if (limit == 0 or limit > 1000) 1000 else limit;
    if (sorted.size() <= cap) sorted else Array.subArray(sorted, 0, cap)
  };

  // ════════════════════════════════════════════════════════════════════════════
  // SCOREBOARDS - Developer-configured time-based leaderboards
  // ════════════════════════════════════════════════════════════════════════════


  // Helper: Reset a scoreboard
  private func archiveAndClearScoreboard(key : Text, config : ScoreboardConfig) : () {

    archiveScoreboard(key, config);
    
    let newConfig : ScoreboardConfig = {
      scoreboardId = config.scoreboardId;
      gameId = config.gameId;
      name = config.name;
      description = config.description;
      period = config.period;
      sortBy = config.sortBy;
      maxEntries = config.maxEntries;
      created = config.created;
      lastReset = now();
      isActive = config.isActive;
      targeted = config.targeted;
      resetIntervalNanos = config.resetIntervalNanos;
    };
    scoreboardConfigs.put(key, newConfig);
    scoreboardEntries.put(key, Buffer.Buffer<ScoreEntry>(100));
    cachedScoreboards.delete(key);
  };

  // ═══════════════════════════════════════════════════════════════════════════════
  // CREATE SCOREBOARD (Developer function)
  // ═══════════════════════════════════════════════════════════════════════════════

  public shared func createScoreboardBySession(
    sessionId : Text,
    gameId : Text,
    scoreboardId : Text,
    name : Text,
    description : Text,
    periodText : Text,
    sortByText : Text,
    maxEntries : ?Nat,
    targeted : Bool,
    intervalDays : ?Nat
  ) : async Result.Result<Text, Text> {
    
    switch (getOwnerFromSession(sessionId)) {
      case (#err(e)) { return #err(e) };
      case (#ok(owner)) {
        // Verify game ownership
        switch (games.get(gameId)) {
          case null { return #err("Game not found") };
          case (?game) {
            if (not Principal.equal(game.owner, owner)) {
              return #err("You don't own this game");
            };
          };
        };

        // Validate scoreboard ID
        if (Text.size(scoreboardId) < 2 or Text.size(scoreboardId) > 30) {
          return #err("Scoreboard ID must be 2-30 characters");
        };

        let key = makeScoreboardKey(gameId, scoreboardId);
        
        // Check if scoreboard already exists (soft-deleted tombstones don't
        // count — recreating a deleted board's ID replaces the tombstone)
        switch (scoreboardConfigs.get(key)) {
          case (?existing) {
            if (existing.isActive) {
              return #err("Scoreboard ID already exists for this game");
            };
            purgeScoreboardArchives(gameId, scoreboardId);
          };
          case null {};
        };

        // Parse period
        let period = switch (textToPeriod(periodText)) {
          case null { return #err("Invalid period. Use: allTime, daily, weekly, monthly, custom") };
          case (?p) { p };
        };

        // Parse sortBy
        let sortBy : SortBy = switch (sortByText) {
          case ("score") { #score };
          case ("streak") { #streak };
          case (_) { return #err("Invalid sortBy. Use: score or streak") };
        };

        let maxEntriesVal = switch (maxEntries) {
          case (?n) { if (n > 1000) 1000 else if (n < 10) 10 else n };
          case null { 100 };
        };

        let currentTime = now();
        let resetIntervalNanos : ?Nat64 = switch (intervalDays) {
          case (?d) { if (d == 0) null else ?(Nat64.fromNat(d) * Scoreboards.DAY_IN_NANOS) };
          case null { null };
        };
        
        let config : ScoreboardConfig = {
          scoreboardId = scoreboardId;
          gameId = gameId;
          name = clampText(name, MAX_GAME_NAME_LENGTH);
          description = clampText(description, MAX_GAME_DESCRIPTION_LENGTH);
          period = period;
          sortBy = sortBy;
          maxEntries = maxEntriesVal;
          created = currentTime;
          lastReset = currentTime;
          isActive = true;
          targeted = ?targeted;
          resetIntervalNanos = resetIntervalNanos;
        };

        scoreboardConfigs.put(key, config);
        scoreboardEntries.put(key, Buffer.Buffer<ScoreEntry>(100));

        trackEventInternal(#principal(owner), gameId, "scoreboard_created", [
          ("scoreboardId", scoreboardId),
          ("period", periodText),
          ("sortBy", sortByText)
        ]);

        #ok("Scoreboard '" # name # "' created successfully!")
      };
    };
  };

  // ═══════════════════════════════════════════════════════════════════════════════
  // GET SCOREBOARDS FOR GAME
  // ═══════════════════════════════════════════════════════════════════════════════

  public query func getScoreboardsForGame(gameId : Text) : async [{
    scoreboardId : Text;
    name : Text;
    description : Text;
    period : Text;
    sortBy : Text;
    maxEntries : Nat;
    lastReset : Nat64;
    entryCount : Nat;
    isActive : Bool;
    targeted : ?Bool;
    resetIntervalDays : ?Nat;
  }] {
    let results = Buffer.Buffer<{
      scoreboardId : Text;
      name : Text;
      description : Text;
      period : Text;
      sortBy : Text;
      maxEntries : Nat;
      lastReset : Nat64;
      entryCount : Nat;
      isActive : Bool;
      targeted : ?Bool;
      resetIntervalDays : ?Nat;
    }>(10);

    for ((key, config) in scoreboardConfigs.entries()) {
      if (config.gameId == gameId and config.isActive) {
        let entryCount = switch (scoreboardEntries.get(key)) {
          case (?buffer) { buffer.size() };
          case null { 0 };
        };

        results.add({
          scoreboardId = config.scoreboardId;
          name = config.name;
          description = config.description;
          period = periodToText(config.period);
          sortBy = switch (config.sortBy) { case (#score) "score"; case (#streak) "streak" };
          maxEntries = config.maxEntries;
          lastReset = config.lastReset;
          entryCount = entryCount;
          isActive = config.isActive;
          targeted = config.targeted;
          resetIntervalDays = switch (config.resetIntervalNanos) { case (?n) { ?Nat64.toNat(n / Scoreboards.DAY_IN_NANOS) }; case null { null } };
        });
      };
    };

    Buffer.toArray(results)
  };

  // ═══════════════════════════════════════════════════════════════════════════════
  // GET SCOREBOARD ENTRIES
  // ═══════════════════════════════════════════════════════════════════════════════

  public query func getScoreboard(
    gameId : Text,
    scoreboardId : Text,
    limit : Nat
  ) : async Result.Result<{
    config : {
      name : Text;
      description : Text;
      period : Text;
      sortBy : Text;
      lastReset : Nat64;
    };
    entries : [PublicScoreEntry];
  }, Text> {
    let key = makeScoreboardKey(gameId, scoreboardId);
    
    switch (scoreboardConfigs.get(key)) {
      case null { return #err("Scoreboard not found") };
      case (?config) {
        if (not config.isActive) {
          return #err("Scoreboard is not active");
        };

        // Check cache first
        switch (cachedScoreboards.get(key)) {
          case (?cached) {
            switch (scoreboardLastUpdate.get(key)) {
              case (?lastUpdate) {
                if (now() - lastUpdate < SCOREBOARD_CACHE_TTL) {
                  let cap = if (limit == 0 or limit > config.maxEntries) config.maxEntries else limit;
                  let entries = if (cached.size() <= cap) cached else Array.subArray(cached, 0, cap);
                  return #ok({
                    config = {
                      name = config.name;
                      description = config.description;
                      period = periodToText(config.period);
                      sortBy = switch (config.sortBy) { case (#score) "score"; case (#streak) "streak" };
                      lastReset = config.lastReset;
                    };
                    entries = entries;
                  });
                };
              };
              case null {};
            };
          };
          case null {};
        };
        let isExpired = switch (config.period) {
          case (#allTime) { false };
          case (#custom) { false };
          case (#daily) { Scoreboards.shouldResetDaily(config.lastReset, now()) };
          case (#weekly) { Scoreboards.shouldResetWeekly(config.lastReset, now()) };
          case (#monthly) { Scoreboards.shouldResetMonthly(config.lastReset, now()) };
        };

        if (isExpired) {
          return #ok({
            config = {
              name = config.name;
              description = config.description;
              period = periodToText(config.period);
              sortBy = switch (config.sortBy) { case (#score) "score"; case (#streak) "streak" };
              lastReset = config.lastReset;
            };
            entries = [];
          });
        };

        // Build fresh leaderboard
        let buffer = switch (scoreboardEntries.get(key)) {
          case null { Buffer.Buffer<ScoreEntry>(0) };
          case (?b) { b };
        };

        // Sort entries
        let entriesArray = Buffer.toArray(buffer);
        let sorted = Array.sort<ScoreEntry>(entriesArray, func(a, b) {
          switch (config.sortBy) {
            case (#score) {
              if (a.score > b.score) #less
              else if (a.score < b.score) #greater
              else #equal
            };
            case (#streak) {
              if (a.streak > b.streak) #less
              else if (a.streak < b.streak) #greater
              else #equal
            };
          }
        });

        // Convert to public entries with rank
        let publicEntries = Buffer.Buffer<PublicScoreEntry>(sorted.size());
        var rank : Nat = 1;
        for (entry in sorted.vals()) {
          publicEntries.add({
            nickname = entry.nickname;
            score = entry.score;
            streak = entry.streak;
            submittedAt = entry.submittedAt;
            authType = authTypeToText(entry.authType);
            rank = rank;
          });
          rank += 1;
        };

        let publicArray = Buffer.toArray(publicEntries);
        
        // Cache the result
        cachedScoreboards.put(key, publicArray);
        scoreboardLastUpdate.put(key, now());

        let cap = if (limit == 0 or limit > config.maxEntries) config.maxEntries else limit;
        let entries = if (publicArray.size() <= cap) publicArray else Array.subArray(publicArray, 0, cap);

        #ok({
          config = {
            name = config.name;
            description = config.description;
            period = periodToText(config.period);
            sortBy = switch (config.sortBy) { case (#score) "score"; case (#streak) "streak" };
            lastReset = config.lastReset;
          };
          entries = entries;
        })
      };
    };
  };

  // ═══════════════════════════════════════════════════════════════════════════════
  // RESET SCOREBOARD (Developer function)
  // ═══════════════════════════════════════════════════════════════════════════════

  public shared func resetScoreboardBySession(
    sessionId : Text,
    gameId : Text,
    scoreboardId : Text
  ) : async Result.Result<Text, Text> {
    
    switch (getOwnerFromSession(sessionId)) {
      case (#err(e)) { return #err(e) };
      case (#ok(owner)) {
        // Verify game ownership
        switch (games.get(gameId)) {
          case null { return #err("Game not found") };
          case (?game) {
            if (not Principal.equal(game.owner, owner)) {
              return #err("You don't own this game");
            };
          };
        };

        let key = makeScoreboardKey(gameId, scoreboardId);
        
        switch (scoreboardConfigs.get(key)) {
          case null { return #err("Scoreboard not found") };
          case (?config) {
            archiveAndClearScoreboard(key, config);
            
            trackEventInternal(#principal(owner), gameId, "scoreboard_reset", [
              ("scoreboardId", scoreboardId)
            ]);

            #ok("Scoreboard '" # config.name # "' has been reset")
          };
        };
      };
    };
  };

  // ═══════════════════════════════════════════════════════════════════════════════
  // DELETE SCOREBOARD (Developer function)
  // ═══════════════════════════════════════════════════════════════════════════════

  public shared func deleteScoreboardBySession(
    sessionId : Text,
    gameId : Text,
    scoreboardId : Text
  ) : async Result.Result<Text, Text> {
    
    switch (getOwnerFromSession(sessionId)) {
      case (#err(e)) { return #err(e) };
      case (#ok(owner)) {
        // Verify game ownership
        switch (games.get(gameId)) {
          case null { return #err("Game not found") };
          case (?game) {
            if (not Principal.equal(game.owner, owner)) {
              return #err("You don't own this game");
            };
          };
        };

        let key = makeScoreboardKey(gameId, scoreboardId);
        
        switch (scoreboardConfigs.get(key)) {
          case null { return #err("Scoreboard not found") };
          case (?config) {
            // Soft delete - mark as inactive
            let updated : ScoreboardConfig = {
              scoreboardId = config.scoreboardId;
              gameId = config.gameId;
              name = config.name;
              description = config.description;
              period = config.period;
              sortBy = config.sortBy;
              maxEntries = config.maxEntries;
              created = config.created;
              lastReset = config.lastReset;
              isActive = false;
              targeted = config.targeted;
              resetIntervalNanos = config.resetIntervalNanos;
            };
            scoreboardConfigs.put(key, updated);
            
            // Clear entries, read cache, and this board's archived periods
            scoreboardEntries.delete(key);
            cachedScoreboards.delete(key);
            scoreboardLastUpdate.delete(key);
            purgeScoreboardArchives(gameId, scoreboardId);
            
            trackEventInternal(#principal(owner), gameId, "scoreboard_deleted", [
              ("scoreboardId", scoreboardId)
            ]);

            #ok("Scoreboard '" # config.name # "' has been deleted")
          };
        };
      };
    };
  };

  // ═══════════════════════════════════════════════════════════════════════════════
  // UPDATE SCOREBOARD CONFIG (Developer function)
  // ═══════════════════════════════════════════════════════════════════════════════

  public shared func updateScoreboardBySession(
    sessionId : Text,
    gameId : Text,
    scoreboardId : Text,
    name : ?Text,
    description : ?Text,
    maxEntries : ?Nat
  ) : async Result.Result<Text, Text> {
    
    switch (getOwnerFromSession(sessionId)) {
      case (#err(e)) { return #err(e) };
      case (#ok(owner)) {
        // Verify game ownership
        switch (games.get(gameId)) {
          case null { return #err("Game not found") };
          case (?game) {
            if (not Principal.equal(game.owner, owner)) {
              return #err("You don't own this game");
            };
          };
        };

        let key = makeScoreboardKey(gameId, scoreboardId);
        
        switch (scoreboardConfigs.get(key)) {
          case null { return #err("Scoreboard not found") };
          case (?config) {
            let newName = switch (name) { case (?n) n; case null config.name };
            let newDesc = switch (description) { case (?d) d; case null config.description };
            let newMax = switch (maxEntries) { 
              case (?n) { if (n > 1000) 1000 else if (n < 10) 10 else n }; 
              case null config.maxEntries 
            };

            let updated : ScoreboardConfig = {
              scoreboardId = config.scoreboardId;
              gameId = config.gameId;
              name = newName;
              description = newDesc;
              period = config.period;
              sortBy = config.sortBy;
              maxEntries = newMax;
              created = config.created;
              lastReset = config.lastReset;
              isActive = config.isActive;
              targeted = config.targeted;
              resetIntervalNanos = config.resetIntervalNanos;
            };
            scoreboardConfigs.put(key, updated);
            
            #ok("Scoreboard updated successfully")
          };
        };
      };
    };
  };

  // ═══════════════════════════════════════════════════════════════════════════════
  // SCOREBOARD MANAGEMENT — Internet Identity (principal) variants
  // ═══════════════════════════════════════════════════════════════════════════════

  public shared(msg) func createScoreboard(
    gameId : Text,
    scoreboardId : Text,
    name : Text,
    description : Text,
    periodText : Text,
    sortByText : Text,
    maxEntries : ?Nat,
    targeted : Bool,
    intervalDays : ?Nat
  ) : async Result.Result<Text, Text> {

    if (Principal.isAnonymous(msg.caller)) {
      return #err("❌ Must authenticate with chedda");
    };
    let owner = msg.caller;

    // Verify game ownership
    switch (games.get(gameId)) {
      case null { return #err("Game not found") };
      case (?game) {
        if (not Principal.equal(game.owner, owner)) {
          return #err("You don't own this game");
        };
      };
    };

    // Validate scoreboard ID
    if (Text.size(scoreboardId) < 2 or Text.size(scoreboardId) > 30) {
      return #err("Scoreboard ID must be 2-30 characters");
    };

    let key = makeScoreboardKey(gameId, scoreboardId);

    // Already exists? (soft-deleted tombstones don't count — recreating a
    // deleted board's ID replaces the tombstone)
    switch (scoreboardConfigs.get(key)) {
      case (?existing) {
        if (existing.isActive) {
          return #err("Scoreboard ID already exists for this game");
        };
        purgeScoreboardArchives(gameId, scoreboardId);
      };
      case null {};
    };

    let period = switch (textToPeriod(periodText)) {
      case null { return #err("Invalid period. Use: allTime, daily, weekly, monthly, custom") };
      case (?p) { p };
    };

    let sortBy : SortBy = switch (sortByText) {
      case ("score") { #score };
      case ("streak") { #streak };
      case (_) { return #err("Invalid sortBy. Use: score or streak") };
    };

    let maxEntriesVal = switch (maxEntries) {
      case (?n) { if (n > 1000) 1000 else if (n < 10) 10 else n };
      case null { 100 };
    };

    let currentTime = now();
    let resetIntervalNanos : ?Nat64 = switch (intervalDays) {
      case (?d) { if (d == 0) null else ?(Nat64.fromNat(d) * Scoreboards.DAY_IN_NANOS) };
      case null { null };
    };

    let config : ScoreboardConfig = {
      scoreboardId = scoreboardId;
      gameId = gameId;
      name = clampText(name, MAX_GAME_NAME_LENGTH);
      description = clampText(description, MAX_GAME_DESCRIPTION_LENGTH);
      period = period;
      sortBy = sortBy;
      maxEntries = maxEntriesVal;
      created = currentTime;
      lastReset = currentTime;
      isActive = true;
      targeted = ?targeted;
      resetIntervalNanos = resetIntervalNanos;
    };

    scoreboardConfigs.put(key, config);
    scoreboardEntries.put(key, Buffer.Buffer<ScoreEntry>(100));

    trackEventInternal(#principal(owner), gameId, "scoreboard_created", [
      ("scoreboardId", scoreboardId),
      ("period", periodText),
      ("sortBy", sortByText)
    ]);

    #ok("Scoreboard '" # name # "' created successfully!")
  };

  public shared(msg) func resetScoreboard(
    gameId : Text,
    scoreboardId : Text
  ) : async Result.Result<Text, Text> {

    if (Principal.isAnonymous(msg.caller)) {
      return #err("❌ Must authenticate with chedda");
    };
    let owner = msg.caller;

    switch (games.get(gameId)) {
      case null { return #err("Game not found") };
      case (?game) {
        if (not Principal.equal(game.owner, owner)) {
          return #err("You don't own this game");
        };
      };
    };

    let key = makeScoreboardKey(gameId, scoreboardId);

    switch (scoreboardConfigs.get(key)) {
      case null { return #err("Scoreboard not found") };
      case (?config) {
        archiveAndClearScoreboard(key, config);
        trackEventInternal(#principal(owner), gameId, "scoreboard_reset", [
          ("scoreboardId", scoreboardId)
        ]);
        #ok("Scoreboard '" # config.name # "' has been reset")
      };
    };
  };

  public shared(msg) func deleteScoreboard(
    gameId : Text,
    scoreboardId : Text
  ) : async Result.Result<Text, Text> {

    if (Principal.isAnonymous(msg.caller)) {
      return #err("❌ Must authenticate with chedda");
    };
    let owner = msg.caller;

    switch (games.get(gameId)) {
      case null { return #err("Game not found") };
      case (?game) {
        if (not Principal.equal(game.owner, owner)) {
          return #err("You don't own this game");
        };
      };
    };

    let key = makeScoreboardKey(gameId, scoreboardId);

    switch (scoreboardConfigs.get(key)) {
      case null { return #err("Scoreboard not found") };
      case (?config) {
        // Soft delete — mark inactive
        let updated : ScoreboardConfig = {
          scoreboardId = config.scoreboardId;
          gameId = config.gameId;
          name = config.name;
          description = config.description;
          period = config.period;
          sortBy = config.sortBy;
          maxEntries = config.maxEntries;
          created = config.created;
          lastReset = config.lastReset;
          isActive = false;
          targeted = config.targeted;
          resetIntervalNanos = config.resetIntervalNanos;
        };
        scoreboardConfigs.put(key, updated);
        scoreboardEntries.delete(key);
        cachedScoreboards.delete(key);
        scoreboardLastUpdate.delete(key);
        purgeScoreboardArchives(gameId, scoreboardId);

        trackEventInternal(#principal(owner), gameId, "scoreboard_deleted", [
          ("scoreboardId", scoreboardId)
        ]);

        #ok("Scoreboard '" # config.name # "' has been deleted")
      };
    };
  };

  public shared(msg) func updateScoreboard(
    gameId : Text,
    scoreboardId : Text,
    name : ?Text,
    description : ?Text,
    maxEntries : ?Nat
  ) : async Result.Result<Text, Text> {

    if (Principal.isAnonymous(msg.caller)) {
      return #err("❌ Must authenticate with chedda");
    };
    let owner = msg.caller;

    switch (games.get(gameId)) {
      case null { return #err("Game not found") };
      case (?game) {
        if (not Principal.equal(game.owner, owner)) {
          return #err("You don't own this game");
        };
      };
    };

    let key = makeScoreboardKey(gameId, scoreboardId);

    switch (scoreboardConfigs.get(key)) {
      case null { return #err("Scoreboard not found") };
      case (?config) {
        let newName = switch (name) { case (?n) n; case null config.name };
        let newDesc = switch (description) { case (?d) d; case null config.description };
        let newMax = switch (maxEntries) {
          case (?n) { if (n > 1000) 1000 else if (n < 10) 10 else n };
          case null config.maxEntries
        };

        let updated : ScoreboardConfig = {
          scoreboardId = config.scoreboardId;
          gameId = config.gameId;
          name = newName;
          description = newDesc;
          period = config.period;
          sortBy = config.sortBy;
          maxEntries = newMax;
          created = config.created;
          lastReset = config.lastReset;
          isActive = config.isActive;
          targeted = config.targeted;
          resetIntervalNanos = config.resetIntervalNanos;
        };
        scoreboardConfigs.put(key, updated);

        #ok("Scoreboard updated successfully")
      };
    };
  };

  // ═══════════════════════════════════════════════════════════════════════════════
  // GET PLAYER RANK ON SCOREBOARD
  // ═══════════════════════════════════════════════════════════════════════════════

  public shared query(msg) func getPlayerScoreboardRank(
    gameId : Text,
    scoreboardId : Text,
    userIdType : Text,
    userId : Text
  ) : async ?{
    rank : Nat;
    score : Nat64;
    streak : Nat64;
    totalPlayers : Nat;
  } {
    let key = makeScoreboardKey(gameId, scoreboardId);
    
    let identifier : UserIdentifier = switch (userIdType) {
      // HARDENING (Oct 2026): "email" is verifier-only, so a profile can't be
      // looked up from a bare email address by a direct caller.
      case ("email") { if (not isVerifier(msg.caller)) { return null }; #email(userId) };
      case ("session") { 
        switch (getValidSession(userId)) {
          case (?session) { #email(session.email) };
          case null { return null };
        };
      };
      case ("principal") { 
        switch (Principal.fromText(userId)) {
          case p { #principal(p) };
        };
      };
      case ("external") { #email("ext:" # userId) };
      case (_) { return null };
    };

    switch (scoreboardConfigs.get(key)) {
      case null { return null };
      case (?config) {
        let buffer = switch (scoreboardEntries.get(key)) {
          case null { return null };
          case (?b) { b };
        };

        let entriesArray = Buffer.toArray(buffer);
        let sorted = Array.sort<ScoreEntry>(entriesArray, func(a, b) {
          switch (config.sortBy) {
            case (#score) {
              if (a.score > b.score) #less
              else if (a.score < b.score) #greater
              else #equal
            };
            case (#streak) {
              if (a.streak > b.streak) #less
              else if (a.streak < b.streak) #greater
              else #equal
            };
          }
        });

        var rank : Nat = 1;
        for (entry in sorted.vals()) {
          if (identifierToText(entry.odentifier) == identifierToText(identifier)) {
            return ?{
              rank = rank;
              score = entry.score;
              streak = entry.streak;
              totalPlayers = sorted.size();
            };
          };
          rank += 1;
        };

        null
      };
    };
  };
  
  public shared query(msg) func getPlayerRank(
    gameId : Text,
    sortBy : SortBy,
    userIdType : Text,
    userId : Text
  ) : async ?{
    rank : Nat;
    score : Nat64;
    streak : Nat64;
    totalPlayers : Nat;
  } {
    let identifier : UserIdentifier = switch (userIdType) {
      // HARDENING (Oct 2026): "email" is verifier-only, so a profile can't be
      // looked up from a bare email address by a direct caller.
      case ("email") { if (not isVerifier(msg.caller)) { return null }; #email(userId) };
      case ("principal") { #principal(Principal.fromText(userId)) };
      case ("external") { #email("ext:" # userId) };
      case (_) { return null };
    };
    
    switch (getUserByIdentifier(identifier)) {
      case null { null };
      case (?user) {
        var userScore : Nat64 = 0;
        var userStreak : Nat64 = 0;
        var found = false;
        
        for ((gId, gProfile) in user.gameProfiles.vals()) {
          if (gId == gameId) {
            userScore := gProfile.total_score;
            userStreak := gProfile.best_streak;
            found := true;
          };
        };
        
        if (not found) return null;
        
        var betterCount = 0;
        var totalCount = 0;
        
        for ((_, otherUser) in usersByEmail.entries()) {
          for ((gId, gProfile) in otherUser.gameProfiles.vals()) {
            if (gId == gameId) {
              totalCount += 1;
              let isBetter = switch (sortBy) {
                case (#score) { gProfile.total_score > userScore };
                case (#streak) { gProfile.best_streak > userStreak };
              };
              if (isBetter) betterCount += 1;
            };
          };
        };
        
        for ((_, otherUser) in usersByPrincipal.entries()) {
          for ((gId, gProfile) in otherUser.gameProfiles.vals()) {
            if (gId == gameId) {
              totalCount += 1;
              let isBetter = switch (sortBy) {
                case (#score) { gProfile.total_score > userScore };
                case (#streak) { gProfile.best_streak > userStreak };
              };
              if (isBetter) betterCount += 1;
            };
          };
        };
        
        ?{
          rank = betterCount + 1;
          score = userScore;
          streak = userStreak;
          totalPlayers = totalCount;
        }
      };
    }
  };

  public query func getGameAuthStats(gameId : Text) : async {
    internetIdentity : Nat;
    google : Nat;
    apple : Nat;
    external : Nat;
    total : Nat;
  } {
    var iiCount = 0;
    var googleCount = 0;
    var appleCount = 0;
    var externalCount = 0;
    var totalCount = 0;
    
    for ((_, user) in usersByEmail.entries()) {
      for ((gId, _) in user.gameProfiles.vals()) {
        if (gId == gameId) {
          totalCount += 1;
          switch (user.authType) {
            case (#google) googleCount += 1;
            case (#apple) appleCount += 1;
            case (#external) externalCount += 1;
            case (_) {};
          };
        };
      };
    };
    
    for ((_, user) in usersByPrincipal.entries()) {
      for ((gId, _) in user.gameProfiles.vals()) {
        if (gId == gameId) {
          totalCount += 1;
          switch (user.authType) {
            case (#internetIdentity) iiCount += 1;
            case (_) {};
          };
        };
      };
    };
    
    {
      internetIdentity = iiCount;
      google = googleCount;
      apple = appleCount;
      external = externalCount;
      total = totalCount;
    }
  };

  // ════════════════════════════════════════════════════════════════════════════
  // PROFILE QUERIES - Updated for external users
  // ════════════════════════════════════════════════════════════════════════════

  public query func getUserProfile(userIdType : Text, userId : Text) : async Result.Result<PublicUserProfile, Text> {
    let identifier : UserIdentifier = switch (userIdType) {
      // HARDENING (Oct 2026): the "email" type is gone. It let anyone look up a
      // profile from a bare email address. Use "session" or "external".
      case ("session") { 
        switch (validateSessionInternal(userId)) {
          case (#err(e)) { return #err(e) };
          case (#ok(session)) { #email(session.email) };
        };
      };
      case ("principal") { #principal(Principal.fromText(userId)) };
      case ("external") { #email("ext:" # userId) };
      case (_) { return #err("Invalid user type") };
    };
    
    switch (getUserByIdentifier(identifier)) {
      case (?profile) { 
        #ok({
          nickname = profile.nickname;
          authType = profile.authType;
          gameProfiles = profile.gameProfiles;
          created = profile.created;
          last_updated = profile.last_updated;
        })
      };
      case null { #err("User not found") };
    };
  };

  public shared query(msg) func getGameProfile(
    userIdType : Text, 
    userId : Text, 
    gameId : Text
  ) : async Result.Result<GameProfile, Text> {
    
    let identifier : UserIdentifier = switch (userIdType) {
      // HARDENING (Oct 2026): "email" is verifier-only, so a profile can't be
      // looked up from a bare email address by a direct caller.
      case ("email") { if (not isVerifier(msg.caller)) { return #err("Invalid user type") }; #email(userId) };
      case ("session") {
        switch (validateSessionInternal(userId)) {
          case (#err(e)) { return #err(e) };
          case (#ok(session)) { #email(session.email) };
        };
      };
      case ("principal") { #principal(Principal.fromText(userId)) };
      case ("external") { #email("ext:" # userId) };
      case (_) { return #err("Invalid user type") };
    };

    switch (getUserByIdentifier(identifier)) {
      case (?user) {
        for ((gId, gProfile) in user.gameProfiles.vals()) {
          if (gId == gameId) {
            return #ok(gProfile);
          };
        };
        #err("Game profile not found")
      };
      case null { #err("User not found") };
    }
  };

  public shared(msg) func getMyProfile() : async Result.Result<UserProfile, Text> {
    let caller = msg.caller;
    
    if (Principal.isAnonymous(caller)) {
      return #err("Authentication required");
    };
    
    switch (usersByPrincipal.get(caller)) {
      case (?profile) { 
        #ok(profile)
      };
      case null { 
        #err("Profile not found") 
      };
    };
  };

  public shared(msg) func getMyProfileBySession(sessionId : Text) : async Result.Result<UserProfile, Text> {
    switch (validateSessionInternal(sessionId)) {
      case (#err(e)) { return #err(e) };
      case (#ok(session)) {
        switch (usersByEmail.get(session.email)) {
          case (?profile) { #ok(profile) };
          case null { #err("User not found") };
        };
      };
    };
  };

  public shared(msg) func getProfileBySession(sessionId : Text) : async Result.Result<UserProfile, Text> {
    switch (validateSessionInternal(sessionId)) {
      case (#err(e)) { #err(e) };
      case (#ok(session)) {
        switch (usersByEmail.get(session.email)) {
          case (?user) { #ok(user) };
          case null { #err("User profile not found for session") };
        };
      };
    };
  };

  // ════════════════════════════════════════════════════════════════════════════
  // ANALYTICS
  // ════════════════════════════════════════════════════════════════════════════

  // v0.10.0: verifier-only (was fully open: anyone could flood analytics).
  public shared(msg) func trackEvent(
    userIdType : Text,
    userId : Text,
    eventType : Text,
    gameId : Text,
    metadata : [(Text, Text)]
  ) : async () {
    if (not isVerifier(msg.caller)) { return };
    let identifier : UserIdentifier = switch (userIdType) {
      case ("email") { #email(userId) };
      case ("principal") { #principal(Principal.fromText(userId)) };
      case ("external") { #email("ext:" # userId) };
      case (_) { return };
    };
    
    trackEventInternal(identifier, gameId, eventType, metadata);
  };

  public query func getDailyStats(date : Text, gameId : Text) : async ?DailyStats {
    dailyStats.get(date # ":" # gameId)
  };

  public shared query(msg) func getPlayerAnalytics(userIdType : Text, userId : Text, gameId : Text) : async ?PlayerStats {
    let identifier : UserIdentifier = switch (userIdType) {
      // HARDENING (Oct 2026): "email" is verifier-only, so a profile can't be
      // looked up from a bare email address by a direct caller.
      case ("email") { if (not isVerifier(msg.caller)) { return null }; #email(userId) };
      case ("principal") { #principal(Principal.fromText(userId)) };
      case ("external") { #email("ext:" # userId) };
      case (_) { return null };
    };
    
    let playerKey = identifierToText(identifier) # ":" # gameId;
    playerStats.get(playerKey)
  };

  public query func getAnalyticsSummary() : async {
    totalEvents : Nat;
    uniquePlayers : Nat;
    totalGames : Nat;
    totalDays : Nat;
    mostActiveDay : Text;
    recentEvents : Nat;
  } {
    var mostGames = 0;
    var mostActiveDay = "";
    
    for ((_, stats) in dailyStats.entries()) {
      if (stats.totalGames > mostGames) {
        mostGames := stats.totalGames;
        mostActiveDay := stats.date;
      };
    };
    
    let recentCount = if (analyticsEvents.size() > 100) { 100 } else { analyticsEvents.size() };
    
    {
      totalEvents = analyticsEvents.size();
      uniquePlayers = usersByEmail.size() + usersByPrincipal.size();
      totalGames = games.size();
      totalDays = dailyStats.size();
      mostActiveDay = mostActiveDay;
      recentEvents = recentCount;
    }
  };

  public shared query(msg) func getRecentEvents(limit : Nat) : async [AnalyticsEvent] {
    if (not isAdmin(msg.caller)) { return [] };
    let cap = if (limit > 100) { 100 } else { limit };
    let size = analyticsEvents.size();
    
    if (size == 0) { return [] };
    
    let startIdx = if (size > cap) { size - cap } else { 0 };
    
    var events = Buffer.Buffer<AnalyticsEvent>(cap);
    for (i in Iter.range(startIdx, size - 1)) {
      events.add(analyticsEvents.get(i));
    };
    
    Buffer.toArray(events)
  };

  // ════════════════════════════════════════════════════════════════════════════
  // SYSTEM INFO
  // ════════════════════════════════════════════════════════════════════════════

  public query func getSystemInfo() : async {
    emailUserCount : Nat;
    principalUserCount : Nat;
    gameCount : Nat;
    totalEvents : Nat;
    activeDays : Nat;
    suspicionLogSize : Nat;
    apiKeyCount : Nat;
    totalSubmissions : Nat;
  } {
    // Count only active (non-soft-deleted) games for the public site figure.
    var activeGames : Nat = 0;
    for ((_, g) in games.entries()) { if (g.isActive) { activeGames += 1 } };
    let submissionsTotal = totalSubmissions;
    {
      emailUserCount = usersByEmail.size();
      principalUserCount = usersByPrincipal.size();
      gameCount = activeGames;
      totalEvents = analyticsEvents.size();
      activeDays = dailyStats.size();
      suspicionLogSize = List.size(suspicionLog);
      apiKeyCount = apiKeys.size();
      totalSubmissions = submissionsTotal;
    }
  };

  public shared(msg) func adminCleanupSessions() : async Text {
    if (not isAdmin(msg.caller)) {
      throw Error.reject("Admin only");
    };
    
    let before = sessions.size();
    cleanupExpiredSessions();
    let after = sessions.size();
    
    "Cleaned " # Nat.toText(before - after) # " expired sessions"
  };

  // ════════════════════════════════════════════════════════════════════════════
  // ADMIN
  // ════════════════════════════════════════════════════════════════════════════

  public shared(msg) func adminGate(command : Text, args : [Text]) : async Result.Result<Text, Text> {
    if (emergencyPaused and command != "emergencyUnpause") {
      logAction(msg.caller, command, args, false, "System paused");
      return #err("🚨 EMERGENCY PAUSE ACTIVE - All operations frozen");
    };
    
    if (not isAdmin(msg.caller)) {
      logAction(msg.caller, command, args, false, "Unauthorized");
      return #err("⛔️ Unauthorized: Admin access only");
    };
    
    switch (checkRateLimit(msg.caller, command)) {
      case (#err(errorMsg)) {
        logAction(msg.caller, command, args, false, "Rate limited");
        return #err(errorMsg);
      };
      case (#ok()) {};
    };
    
    let result = switch (command) {
      
      case ("lookupUser") {
        if (not hasPermission(msg.caller, #Support)) {
          #err("🔒 Permission denied: Support role required")
        } else if (args.size() < 1) {
          #err("Usage: lookupUser <searchTerm>\nSearches by nickname, email key, or player ID")
        } else {
          let searchTerm = args[0];
          var found = false;
          var result = "🔍 LOOKUP: " # searchTerm # "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
          
          // Search usersByEmail (includes external and device users)
          for ((key, user) in usersByEmail.entries()) {
            // Match by key or nickname
            if (key == searchTerm or 
                key == "ext:" # searchTerm or
                user.nickname == searchTerm or
                Text.contains(key, #text searchTerm)) {
              found := true;
              let keyType = if (Text.startsWith(key, #text "ext:")) {
                "external"
              } else if (Text.startsWith(key, #text "dev_")) {
                "device"
              } else {
                "email"
              };
              result := result # "\n📧 Found in usersByEmail:\n" #
                       "  Key: " # key # "\n" #
                       "  Type: " # keyType # "\n" #
                       "  Nickname: " # user.nickname # "\n" #
                       "  Auth: " # debug_show(user.authType) # "\n" #
                       "  Created: " # Nat64.toText(user.created) # "\n" #
                       "  ─────────────────────────────\n" #
                       "  To remove: removeUser " # keyType # " " # 
                       (if (keyType == "external") { Text.trimStart(key, #text "ext:") } else { key }) # "\n";
            };
          };
          
          // Search usersByPrincipal
          for ((principal, user) in usersByPrincipal.entries()) {
            let principalText = Principal.toText(principal);
            if (principalText == searchTerm or 
                user.nickname == searchTerm or
                Text.contains(principalText, #text searchTerm)) {
              found := true;
              result := result # "\n🔑 Found in usersByPrincipal:\n" #
                       "  Principal: " # principalText # "\n" #
                       "  Nickname: " # user.nickname # "\n" #
                       "  Auth: " # debug_show(user.authType) # "\n" #
                       "  Created: " # Nat64.toText(user.created) # "\n" #
                       "  ─────────────────────────────\n" #
                       "  To remove: removeUser principal " # principalText # "\n";
            };
          };
          
          if (found) {
            #ok(result)
          } else {
            #err("❌ No user found matching: " # searchTerm # "\n" #
                 "Try searching by:\n" #
                 "  - Exact email/key\n" #
                 "  - Player ID (dev_...)\n" #
                 "  - Nickname\n" #
                 "  - Partial match")
          }
        }
      };

            case ("removeUser") {
        if (not hasPermission(msg.caller, #Moderator)) {
          #err("🔒 Permission denied: Moderator role required")
        } else if (args.size() < 2) {
          #err("Usage: removeUser <type> <id>\nTypes: email, principal, external, device")
        } else {
          let userType = args[0];
          let userId = args[1];
          
          let removed = switch (userType) {
            case ("email") { 
              switch (usersByEmail.remove(userId)) {
                case (?_) { ignore sweepSessionsForEmail(userId); true };
                case null false;
              }
            };
            case ("external") {
              // External auth users (Google/Apple) stored with ext: prefix
              switch (usersByEmail.remove("ext:" # userId)) {
                case (?_) { ignore sweepSessionsForEmail("ext:" # userId); true };
                case null false;
              }
            };
            case ("device") {
              // Anonymous device users - try both with and without ext: prefix
              switch (usersByEmail.remove(userId)) {
                case (?_) true;
                case null {
                  switch (usersByEmail.remove("ext:" # userId)) {
                    case (?_) true;
                    case null false;
                  }
                };
              }
            };
            case ("principal") {
              let principal = try {
                Principal.fromText(userId)
              } catch (_) {
                return #err("Invalid principal format");
              };
              switch (usersByPrincipal.remove(principal)) {
                case (?_) true;
                case null false;
              }
            };
            case (_) {
              return #err("Invalid type. Use: email, principal, external, device")
            };
          };
          
          if (removed) {
            #ok("✅ User removed successfully.")
          } else {
            #err("⚠️ User not found. Try 'lookupByNickname' to find the correct ID/type.")
          }
        }
      };

            case ("banUser") {
        if (not hasPermission(msg.caller, #Moderator)) {
          #err("🔒 Permission denied: Moderator role required")
        } else if (args.size() < 2) {
          #err("Usage: banUser <type> <id> [reason]\nType: email, principal, external, device")
        } else {
          let userType = args[0];
          let userId = args[1];
          let reason = if (args.size() >= 3) { args[2] } else { "Cheating" };
          
          // First, log the ban in suspicion log for record
          logSuspicion(userId # "/" # userType, "SYSTEM", "BANNED: " # reason);
          
          // Remove from user storage
          let removed = switch (userType) {
            case ("email") { 
              switch (usersByEmail.remove(userId)) {
                case (?_) true;
                case null false;
              }
            };
            case ("external") {
              switch (usersByEmail.remove("ext:" # userId)) {
                case (?_) true;
                case null false;
              }
            };
            case ("device") {
              switch (usersByEmail.remove(userId)) {
                case (?_) true;
                case null {
                  switch (usersByEmail.remove("ext:" # userId)) {
                    case (?_) true;
                    case null false;
                  }
                };
              }
            };
            case ("principal") {
              let principal = try {
                Principal.fromText(userId)
              } catch (_) {
                return #err("Invalid principal format");
              };
              switch (usersByPrincipal.remove(principal)) {
                case (?_) true;
                case null false;
              }
            };
            case (_) {
              return #err("Invalid type. Use: email, principal, external, device")
            };
          };
          
          // Always purge from scoreboards (even if user account not found,
          // they might still have scoreboard entries)
          let scoreboardsRemoved = purgePlayerFromScoreboards(userType, userId, null);
          
          if (removed or scoreboardsRemoved > 0) {
            #ok("🔨 USER BANNED\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                "User: " # userId # "\n" #
                "Type: " # userType # "\n" #
                "Reason: " # reason # "\n" #
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                "Account removed: " # (if (removed) "✅" else "⚠️ Not found") # "\n" #
                "Scoreboard entries removed: " # Nat.toText(scoreboardsRemoved) # "\n" #
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                "✅ User purged from all leaderboards")
          } else {
            #err("⚠️ User not found: " # userId # "\n" #
                 "💡 Use lookupUser to find the correct ID and type")
          }
        }
      };

      
      case ("deleteUser") {
        if (not hasPermission(msg.caller, #Moderator)) {
          #err("🔒 Permission denied: Moderator role required")
        } else if (args.size() < 2) {
          #err("Usage: deleteUser <type> <id> [reason]\nThis starts a 30-day soft delete process.")
        } else {
          let userType = args[0];
          let userId = args[1];
          let reason = if (args.size() >= 3) { args[2] } else { "User requested deletion" };
          
          let confirmationCode = generateConfirmationCode(userId);
          let expiresAt = now() + 300_000_000_000;
          
          let pending : PendingDeletion = {
            userId = userId;
            userType = userType;
            requestedBy = msg.caller;
            requestedAt = now();
            confirmationCode = confirmationCode;
            expiresAt = expiresAt;
          };
          
          pendingDeletions.put(userId, pending);
          
          #ok("⚠️ DELETION REQUESTED\n" #
              "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
              "User: " # userId # "\n" #
              "Reason: " # reason # "\n" #
              "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
              "⚠️ This will start a 30-day grace period.\n" #
              "To confirm, run:\n" #
              "adminGate(\"confirmDeleteUser\", [\"" # userId # "\", \"" # confirmationCode # "\"])\n" #
              "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
              "⏱️ Confirmation expires in 5 minutes.")
        }
      };
      
      case ("confirmDeleteUser") {
        if (not hasPermission(msg.caller, #Moderator)) {
          #err("🔒 Permission denied: Moderator role required")
        } else if (args.size() < 2) {
          #err("Usage: confirmDeleteUser <userId> <confirmationCode>")
        } else {
          let userId = args[0];
          let confirmationCode = args[1];
          
          switch (pendingDeletions.get(userId)) {
            case (null) {
              #err("❌ No pending deletion found for this user")
            };
            case (?pending) {
              if (pending.confirmationCode != confirmationCode) {
                #err("❌ Invalid confirmation code")
              } else if (now() > pending.expiresAt) {
                pendingDeletions.delete(userId);
                #err("❌ Confirmation expired. Please request deletion again.")
              } else if (not Principal.equal(pending.requestedBy, msg.caller)) {
                #err("❌ Only the admin who requested deletion can confirm")
              } else {
                let userOpt = switch (pending.userType) {
                  case ("email") { usersByEmail.get(userId) };
                  case ("principal") {
                    let principal = try {
                      Principal.fromText(userId)
                    } catch (_) {
                      return #err("Invalid principal format");
                    };
                    usersByPrincipal.get(principal)
                  };
                  case (_) { null };
                };
                
                switch (userOpt) {
                  case (null) {
                    pendingDeletions.delete(userId);
                    #err("⚠️ User not found")
                  };
                  case (?user) {
                    let deletedUser : DeletedUser = {
                      user = user;
                      deletedBy = msg.caller;
                      deletedAt = now();
                      permanentDeletionAt = now() + 2_592_000_000_000_000;
                      reason = "Admin deletion";
                      canRecover = true;
                    };
                    
                    let removed = switch (pending.userType) {
                      case ("email") { 
                        usersByEmail.delete(userId);
                        true
                      };
                      case ("principal") {
                        let principal = Principal.fromText(userId);
                        usersByPrincipal.delete(principal);
                        true
                      };
                      case (_) false;
                    };
                    
                    if (removed) {
                      deletedUsers.put(userId, deletedUser);
                      pendingDeletions.delete(userId);
                      
                      let gameProfileCount = user.gameProfiles.size();
                      var achievementCount = 0;
                      for ((_, profile) in user.gameProfiles.vals()) {
                        achievementCount += profile.achievements.size();
                      };
                      
                      #ok("🗑️ USER SOFT DELETED\n" #
                          "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                          "User: " # userId # "\n" #
                          "Game profiles: " # Nat.toText(gameProfileCount) # "\n" #
                          "Achievements: " # Nat.toText(achievementCount) # "\n" #
                          "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                          "⏱️ 30-day grace period started\n" #
                          "📅 Permanent deletion: " # Nat64.toText(deletedUser.permanentDeletionAt) # "\n" #
                          "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                          "💡 User can be recovered with: recoverUser")
                    } else {
                      #err("❌ Deletion failed")
                    }
                  };
                }
              }
            };
          }
        }
      };
      
      case ("recoverUser") {
        if (not hasPermission(msg.caller, #Moderator)) {
          #err("🔒 Permission denied: Moderator role required")
        } else if (args.size() < 1) {
          #err("Usage: recoverUser <userId>")
        } else {
          let userId = args[0];
          
          switch (deletedUsers.get(userId)) {
            case (null) {
              #err("❌ No deleted user found with this ID")
            };
            case (?deleted) {
              if (not deleted.canRecover) {
                #err("❌ User cannot be recovered (permanently deleted)")
              } else if (now() > deleted.permanentDeletionAt) {
                #err("❌ Grace period expired - user permanently deleted")
              } else {
                putUserByIdentifier(deleted.user);
                deletedUsers.delete(userId);
                
                #ok("♻️ USER RECOVERED\n" #
                    "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                    "User: " # userId # "\n" #
                    "Originally deleted: " # Nat64.toText(deleted.deletedAt) # "\n" #
                    "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                    "✅ User successfully restored with all data")
              }
            };
          }
        }
      };
      
      case ("listDeletedUsers") {
        if (not hasPermission(msg.caller, #Support)) {
          #err("🔒 Permission denied: Support role required")
        } else {
          var result = "🗑️ DELETED USERS\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
          var count = 0;
          
          for ((userId, deleted) in deletedUsers.entries()) {
            let nowTime = now();
            let daysRemaining : Nat64 = if (deleted.permanentDeletionAt > nowTime) {
              (deleted.permanentDeletionAt - nowTime) / 86_400_000_000_000
            } else { 0 };
            result := result # "\n" # userId # "\n" #
                    "  Deleted: " # Nat64.toText(deleted.deletedAt) # "\n" #
                    "  Days until permanent: " # Nat64.toText(daysRemaining) # "\n" #
                    "  Can recover: " # (if (deleted.canRecover) "✅" else "❌") # "\n";
            count += 1;
          };
          
          if (count == 0) {
            result := result # "\nNo deleted users in grace period.";
          } else {
            result := result # "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                     "Total: " # Nat.toText(count) # " users";
          };
          
          #ok(result)
        }
      };
      
      case ("permanentDelete") {
        if (not hasPermission(msg.caller, #SuperAdmin)) {
          #err("🔒 Permission denied: SuperAdmin role required for permanent deletion")
        } else if (args.size() < 1) {
          #err("Usage: permanentDelete <userId>\n⚠️ WARNING: This bypasses the 30-day grace period!")
        } else {
          let userId = args[0];
          
          switch (deletedUsers.get(userId)) {
            case (null) {
              #err("❌ User not found in deleted users")
            };
            case (?deleted) {
              deletedUsers.delete(userId);
              #ok("💀 USER PERMANENTLY DELETED\n" #
                  "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                  "User: " # userId # "\n" #
                  "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                  "⚠️ This action CANNOT be undone.\n" #
                  "✅ All data permanently erased.")
            };
          }
        }
      };
      
      case ("backup") {
        if (not hasPermission(msg.caller, #SuperAdmin)) {
          #err("🔒 Permission denied: SuperAdmin role required")
        } else {
          let timestamp = now();
          
          var totalGameProfiles = 0;
          for ((_, user) in usersByEmail.entries()) {
            totalGameProfiles += user.gameProfiles.size();
          };
          for ((_, user) in usersByPrincipal.entries()) {
            totalGameProfiles += user.gameProfiles.size();
          };
          
          let backup : BackupData = {
            version = "2.0.0";
            timestamp = timestamp;
            createdBy = msg.caller;
            emailUsers = Iter.toArray(usersByEmail.entries());
            principalUsers = Iter.toArray(usersByPrincipal.entries());
            games = Iter.toArray(games.entries());
            deletedUsers = Iter.toArray(deletedUsers.entries());
            metadata = {
              totalUsers = usersByEmail.size() + usersByPrincipal.size();
              totalGames = games.size();
              totalGameProfiles = totalGameProfiles;
              totalDeletedUsers = deletedUsers.size();
            };
          };
          
          #ok("🗄️ BACKUP CREATED\n" #
              "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
              "Timestamp: " # Nat64.toText(timestamp) # "\n" #
              "Version: 2.0.0\n" #
              "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
              "Email users: " # Nat.toText(backup.emailUsers.size()) # "\n" #
              "Principal users: " # Nat.toText(backup.principalUsers.size()) # "\n" #
              "Games: " # Nat.toText(backup.games.size()) # "\n" #
              "Game profiles: " # Nat.toText(totalGameProfiles) # "\n" #
              "Deleted users: " # Nat.toText(backup.deletedUsers.size()) # "\n" #
              "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
              "✅ Backup ready for export\n" #
              "💡 Store this data off-chain for disaster recovery")
        }
      };
      
      case ("exportUserData") {
        if (not hasPermission(msg.caller, #Support)) {
          #err("🔒 Permission denied: Support role required")
        } else if (args.size() < 2) {
          #err("Usage: exportUserData <type> <id>")
        } else {
          let userType = args[0];
          let userId = args[1];
          
          let userOpt = switch (userType) {
            case ("email") { usersByEmail.get(userId) };
            case ("principal") {
              let principal = try {
                Principal.fromText(userId)
              } catch (_) {
                return #err("❌ Invalid principal format");
              };
              usersByPrincipal.get(principal)
            };
            case (_) { null };
          };
          
          switch (userOpt) {
            case (null) { #err("⚠️ User not found") };
            case (?user) {
              var export = "📦 USER DATA EXPORT\n" #
                          "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                          "Nickname: " # user.nickname # "\n" #
                          "Auth Type: " # debug_show(user.authType) # "\n" #
                          "Created: " # Nat64.toText(user.created) # "\n" #
                          "Last Updated: " # Nat64.toText(user.last_updated) # "\n" #
                          "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                          "Game Profiles (" # Nat.toText(user.gameProfiles.size()) # "):\n";
              
              for ((gameId, gProfile) in user.gameProfiles.vals()) {
                export := export # "\n🎮 " # gameId # "\n" #
                         "  Score: " # Nat64.toText(gProfile.total_score) # "\n" #
                         "  Best Streak: " # Nat64.toText(gProfile.best_streak) # "\n" #
                         "  Achievements: " # Nat.toText(gProfile.achievements.size()) # "\n" #
                         "  Play Count: " # Nat.toText(gProfile.play_count) # "\n" #
                         "  Last Played: " # Nat64.toText(gProfile.last_played) # "\n";
              };
              
              export := export # "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                       "✅ GDPR-compliant data export";
              
              #ok(export)
            };
          }
        }
      };
      
      case ("auditLog") {
        if (not hasPermission(msg.caller, #Support)) {
          #err("🔒 Permission denied: Support role required")
        } else {
          let limit = if (args.size() > 0) {
            switch (Nat.fromText(args[0])) {
              case (?n) n;
              case null 50;
            }
          } else { 50 };
          
          let allLogs = Array.append(auditLogStable, Buffer.toArray(auditLog));
          let recentLogs = if (allLogs.size() > limit) {
            Array.tabulate<AdminAction>(limit, func(i) {
              allLogs[allLogs.size() - limit + i]
            })
          } else {
            allLogs
          };
          
          var result = "📜 AUDIT LOG (Last " # Nat.toText(recentLogs.size()) # " entries)\n" #
                      "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
          
          for (action in recentLogs.vals()) {
            let status = if (action.success) "✅" else "❌";
            result := result # "\n[" # Nat64.toText(action.timestamp) # "] " # status # "\n" #
                     "Admin: " # Principal.toText(action.admin) # "\n" #
                     "Role: " # debug_show(action.adminRole) # "\n" #
                     "Command: " # action.command # "\n" #
                     "Result: " # action.result # "\n";
          };
          
          result := result # "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                   "Total logs: " # Nat.toText(allLogs.size());
          
          #ok(result)
        }
      };
      
      case ("emergencyPause") {
        if (not hasPermission(msg.caller, #SuperAdmin)) {
          #err("🔒 Permission denied: SuperAdmin role required")
        } else {
          emergencyPaused := true;
          #ok("🚨 EMERGENCY PAUSE ACTIVATED\n" #
              "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
              "All admin operations are now frozen.\n" #
              "Only emergencyUnpause can restore operations.\n" #
              "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        }
      };
      
      case ("emergencyUnpause") {
        if (not hasPermission(msg.caller, #SuperAdmin)) {
          #err("🔒 Permission denied: SuperAdmin role required")
        } else {
          emergencyPaused := false;
          #ok("✅ Emergency pause lifted. Operations resumed.")
        }
      };
      
      case ("lookupByNickname") {
        if (not hasPermission(msg.caller, #Support)) {
          #err("🔒 Permission denied: Support role required")
        } else if (args.size() < 1) {
          #err("Usage: lookupByNickname <nickname>")
        } else {
          let targetNickname = args[0];
          var found = false;
          var result = "🔍 LOOKUP: " # targetNickname # "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
          
          for ((principal, user) in usersByPrincipal.entries()) {
            if (user.nickname == targetNickname) {
              found := true;
              result := result # "Type: principal (Internet Identity)\n" #
                       "ID: " # Principal.toText(principal) # "\n" #
                       "Created: " # Nat64.toText(user.created) # "\n";
            };
          };
          
          for ((email, user) in usersByEmail.entries()) {
            if (user.nickname == targetNickname) {
              found := true;
              result := result # "Type: email\n" #
                       "ID: " # email # "\n" #
                       "Created: " # Nat64.toText(user.created) # "\n";
            };
          };
          
          if (found) {
            #ok(result)
          } else {
            #err("❌ No user found with nickname: " # targetNickname)
          }
        }
      };
      
      case ("addAdmin") {
        if (not hasPermission(msg.caller, #SuperAdmin)) {
          #err("🔒 Permission denied: SuperAdmin role required")
        } else if (args.size() < 2) {
          #err("Usage: addAdmin <principal> <role>\nRoles: SuperAdmin, Moderator, Support, ReadOnly")
        } else {
          let principal = try {
            Principal.fromText(args[0])
          } catch (_) {
            return #err("Invalid principal format");
          };
          
          let role : AdminRole = switch (args[1]) {
            case ("SuperAdmin") #SuperAdmin;
            case ("Moderator") #Moderator;
            case ("Support") #Support;
            case ("ReadOnly") #ReadOnly;
            case (_) return #err("Invalid role. Use: SuperAdmin, Moderator, Support, ReadOnly");
          };
          
          adminRoles.put(principal, role);
          #ok("✅ Admin added: " # Principal.toText(principal) # " as " # debug_show(role))
        }
      };
      
      case ("listAdmins") {
        if (not hasPermission(msg.caller, #Support)) {
          #err("🔒 Permission denied: Support role required")
        } else {
          var result = "👥 ADMIN LIST\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
          
          for ((principal, role) in adminRoles.entries()) {
            result := result # "\n" # Principal.toText(principal) # "\n" #
                     "  Role: " # debug_show(role) # "\n";
          };
          
          #ok(result)
        }
      };
      
      case ("removeAdmin") {
        if (not hasPermission(msg.caller, #SuperAdmin)) {
          #err("🔒 Permission denied: SuperAdmin role required")
        } else if (args.size() < 1) {
          #err("Usage: removeAdmin <principal>")
        } else {
          let principal = try {
            Principal.fromText(args[0])
          } catch (_) {
            return #err("Invalid principal format");
          };
          
          if (Principal.equal(principal, msg.caller)) {
            #err("❌ Cannot remove yourself as admin")
          } else {
            adminRoles.delete(principal);
            #ok("✅ Admin removed: " # Principal.toText(principal))
          }
        }
      };
      
      case ("addOrigin") {
        if (not hasPermission(msg.caller, #SuperAdmin)) {
          #err("🔒 Permission denied: SuperAdmin role required")
        } else if (args.size() < 1) {
          #err("Usage: addOrigin <https://domain.com>")
        } else {
          let origin = args[0];
          
          if (not Text.startsWith(origin, #text "https://")) {
            #err("❌ Origin must start with https://")
          } else {
            var exists = false;
            for (existing in alternativeOrigins.vals()) {
              if (existing == origin) {
                exists := true;
              };
            };
            
            if (exists) {
              #err("⚠️ Origin already registered: " # origin)
            } else {
              alternativeOrigins.add(origin);
              #ok("✅ ORIGIN ADDED\n" #
                  "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                  "Domain: " # origin # "\n" #
                  "Total origins: " # Nat.toText(alternativeOrigins.size()) # "\n" #
                  "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                  "💡 Games on this domain can now use\n" #
                  "   CheddaBoards II derivation.")
            }
          }
        }
      };

      case ("removeOrigin") {
        if (not hasPermission(msg.caller, #SuperAdmin)) {
          #err("🔒 Permission denied: SuperAdmin role required")
        } else if (args.size() < 1) {
          #err("Usage: removeOrigin <https://domain.com>")
        } else {
          let origin = args[0];
          let sizeBefore = alternativeOrigins.size();
          
          let newOrigins = Buffer.Buffer<Text>(sizeBefore);
          for (existing in alternativeOrigins.vals()) {
            if (existing != origin) {
              newOrigins.add(existing);
            };
          };
          
          if (newOrigins.size() == sizeBefore) {
            #err("❌ Origin not found: " # origin)
          } else {
            alternativeOrigins := newOrigins;
            #ok("✅ ORIGIN REMOVED\n" #
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                "Domain: " # origin # "\n" #
                "Remaining origins: " # Nat.toText(alternativeOrigins.size()) # "\n" #
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                "⚠️ Games on this domain will now get\n" #
                "   different principals!")
          }
        }
      };

      case ("listOrigins") {
        if (not hasPermission(msg.caller, #Support)) {
          #err("🔒 Permission denied: Support role required")
        } else {
          var result = "🌐 ALTERNATIVE ORIGINS\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
          var count = 0;
          
          for (origin in alternativeOrigins.vals()) {
            count += 1;
            result := result # Nat.toText(count) # ". " # origin # "\n";
          };
          
          if (count == 0) {
            result := result # "\n⚠️ No origins registered.\n" #
                     "Games will get domain-specific principals.\n";
          } else {
            result := result # "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                     "Total: " # Nat.toText(count) # " origins\n" #
                     "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                     "💡 Test endpoint:\n" #
                     "curl https://YOUR-CANISTER.icp0.io/.well-known/ii-alternative-origins";
          };
          
          #ok(result)
        }
      };

      case ("viewSuspicionLog") {
        let isSupport = hasPermission(msg.caller, #Support);
        
        // Get games owned by caller (for non-admin access)
        let ownedGames = Buffer.Buffer<Text>(0);
        if (not isSupport) {
          for ((gameId, game) in games.entries()) {
            if (Principal.equal(game.owner, msg.caller)) {
              ownedGames.add(gameId);
            };
          };
          
          // If not support AND doesn't own any games, deny
          if (ownedGames.size() == 0) {
            return #err("🔒 Permission denied: Must be game owner or have Support role");
          };
        };
        
        let limit = if (args.size() > 0) {
          switch (Nat.fromText(args[0])) {
            case (?n) n;
            case null 50;
          }
        } else { 50 };
        
        let gameFilter : ?Text = if (args.size() > 1) { ?args[1] } else { null };
        
        // If dev specified a game filter, verify they own it
        switch (gameFilter) {
          case (?gId) {
            if (not isSupport) {
              var ownsGame = false;
              for (owned in ownedGames.vals()) {
                if (owned == gId) { ownsGame := true };
              };
              if (not ownsGame) {
                return #err("🔒 Permission denied: You don't own game '" # gId # "'");
              };
            };
          };
          case null {};
        };
        
        let logArray = List.toArray(suspicionLog);
        let totalEntries = logArray.size();
        
        var result = "🚨 SUSPICION LOG\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
        var count = 0;
        var filteredTotal = 0;
        
        // Show most recent first (reverse iterate)
        label logLoop for (i in Iter.range(0, totalEntries - 1)) {
          let idx = totalEntries - 1 - i; // Reverse order
          let entry = logArray[idx];
          
          // Determine if this entry should be visible
          let canView = if (isSupport) {
            // Support can see all, apply game filter if specified
            switch (gameFilter) {
              case (?gId) { entry.gameId == gId };
              case null { true };
            }
          } else {
            // Devs can only see their own games
            var isOwned = false;
            for (owned in ownedGames.vals()) {
              if (owned == entry.gameId) { isOwned := true };
            };
            // Also apply game filter if specified
            switch (gameFilter) {
              case (?gId) { isOwned and entry.gameId == gId };
              case null { isOwned };
            }
          };
          
          if (canView) {
            filteredTotal += 1;
            if (count < limit) {
              result := result # "\n[" # Nat64.toText(entry.timestamp) # "]\n" #
                       "🎮 Game: " # entry.gameId # "\n" #
                       "👤 Player: " # entry.player_id # "\n" #
                       "⚠️ Reason: " # entry.reason # "\n" #
                       "───────────────────────────────\n";
              count += 1;
            };
          };
        };
        
        if (count == 0) {
          result := result # "\n✅ No suspicious activity logged";
          switch (gameFilter) {
            case (?gId) { result := result # " for game: " # gId };
            case null {
              if (not isSupport) {
                result := result # " for your games";
              };
            };
          };
          result := result # "\n";
        };
        
        result := result # "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                 "Showing: " # Nat.toText(count) # " / " # Nat.toText(filteredTotal) # " entries\n";
        
        if (not isSupport) {
          result := result # "🔒 Filtered to your games only\n";
        };
        
        result := result # "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                 "💡 Usage: viewSuspicionLog [limit] [gameId]\n" #
                 "   Example: viewSuspicionLog 20 my-game";
        
        #ok(result)
      };

      case ("clearSuspicionLog") {
        if (not hasPermission(msg.caller, #SuperAdmin)) {
          #err("🔒 Permission denied: SuperAdmin role required")
        } else {
          let oldSize = List.size(suspicionLog);
          suspicionLog := List.nil();
          #ok("🗑️ SUSPICION LOG CLEARED\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
              "Entries removed: " # Nat.toText(oldSize) # "\n" #
              "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        }
      };

      case ("findLostGames") {
    if (not hasPermission(msg.caller, #Support)) {
        #err("🔒 Permission denied")
    } else {
        let gameIds = HashMap.HashMap<Text, Nat>(10, Text.equal, Text.hash);
        
        // Scan email users
        for ((_, user) in usersByEmail.entries()) {
            for ((gameId, _) in user.gameProfiles.vals()) {
                switch (gameIds.get(gameId)) {
                    case (?count) { gameIds.put(gameId, count + 1) };
                    case null { gameIds.put(gameId, 1) };
                };
            };
        };
        
        // Scan principal users
        for ((_, user) in usersByPrincipal.entries()) {
            for ((gameId, _) in user.gameProfiles.vals()) {
                switch (gameIds.get(gameId)) {
                    case (?count) { gameIds.put(gameId, count + 1) };
                    case null { gameIds.put(gameId, 1) };
                };
            };
        };
        
        var result = "🔍 GAMES FOUND IN USER PROFILES\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
        for ((gameId, playerCount) in gameIds.entries()) {
            result := result # gameId # ": " # Nat.toText(playerCount) # " players\n";
        };
        result := result # "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                 "These games need to be re-registered.";
        
        #ok(result)
    }
};

      case ("reconstructGame") {
    // reconstructGame <gameId> [name] [description]
    // Reconstructs a lost game from user profile data
    if (not hasPermission(msg.caller, #SuperAdmin)) {
        #err("🔒 Permission denied: SuperAdmin role required")
    } else if (args.size() < 1) {
        #err("❌ Usage: reconstructGame <gameId> [name] [description]")
    } else {
        let gameId = args[0];
        let gameName = if (args.size() > 1) args[1] else gameId;
        let gameDesc = if (args.size() > 2) args[2] else "Reconstructed game - update description";
        
        // Check if game already exists
        switch (games.get(gameId)) {
            case (?_) { #err("❌ Game '" # gameId # "' already exists!") };
            case null {
                // Scan user profiles to gather stats
                var totalPlayers : Nat = 0;
                var totalPlays : Nat = 0;
                
                // Scan email users
                for ((_, user) in usersByEmail.entries()) {
                    for ((gId, profile) in user.gameProfiles.vals()) {
                        if (gId == gameId) {
                            totalPlayers += 1;
                            totalPlays += profile.play_count;
                        };
                    };
                };
                
                // Scan principal users
                for ((_, user) in usersByPrincipal.entries()) {
                    for ((gId, profile) in user.gameProfiles.vals()) {
                        if (gId == gameId) {
                            totalPlayers += 1;
                            totalPlays += profile.play_count;
                        };
                    };
                };
                
                // Check if we found any players
                if (totalPlayers == 0) {
                    #err("❌ No player data found for gameId: " # gameId # "\nMake sure the gameId matches exactly (case-sensitive)")
                } else {
                    // Create reconstructed game
                    let now = Int.abs(Time.now());
                    
                    let reconstructedGame : GameInfo = {
                        gameId = gameId;
                        name = gameName;
                        description = gameDesc;
                        owner = msg.caller;
                        gameUrl = null;
                        created = Nat64.fromNat(now);
                        accessMode = #both;
                        totalPlayers = totalPlayers;
                        totalPlays = totalPlays;
                        isActive = true;
                        maxScorePerRound = null;
                        maxStreakDelta = null;
                        absoluteScoreCap = null;
                        absoluteStreakCap = null;
                        timeValidationEnabled = false;
                        minPlayDurationSecs = null;
                        maxScorePerSecond = null;
                        maxSessionDurationMins = null;
                        googleClientIds = [];
                        appleBundleId = null;
                        appleTeamId = null;
                    };
                    
                    games.put(gameId, reconstructedGame);
                    
                    #ok("✅ GAME RECONSTRUCTED\n\n" #
                        "🎮 Game ID: " # gameId # "\n" #
                        "📛 Name: " # gameName # "\n" #
                        "👥 Players Found: " # Nat.toText(totalPlayers) # "\n" #
                        "🎯 Total Plays: " # Nat.toText(totalPlays) # "\n" #
                        "👤 Owner: " # Principal.toText(msg.caller) # "\n\n" #
                        "⚠️ TODO:\n" #
                        "- Update name/description if needed\n" #
                        "- Set anti-cheat rules (updateGameRules)\n" #
                        "- Add OAuth credentials if using social login\n" #
                        "- Transfer ownership if needed")
                };
            };
        };
    }
};

      case ("suspicionStats") {
        if (not hasPermission(msg.caller, #Support)) {
          #err("🔒 Permission denied: Support role required")
        } else {
          let logArray = List.toArray(suspicionLog);
          
          // Count by game
          var gameCounts = HashMap.HashMap<Text, Nat>(10, Text.equal, Text.hash);
          // Count by player
          var playerCounts = HashMap.HashMap<Text, Nat>(10, Text.equal, Text.hash);
          // Count by reason type
          var reasonCounts = HashMap.HashMap<Text, Nat>(10, Text.equal, Text.hash);
          
          for (entry in logArray.vals()) {
            // Game counts
            switch (gameCounts.get(entry.gameId)) {
              case (?c) { gameCounts.put(entry.gameId, c + 1) };
              case null { gameCounts.put(entry.gameId, 1) };
            };
            
            // Player counts
            switch (playerCounts.get(entry.player_id)) {
              case (?c) { playerCounts.put(entry.player_id, c + 1) };
              case null { playerCounts.put(entry.player_id, 1) };
            };
            
            // Simplify reason for grouping
            let reasonKey = if (Text.contains(entry.reason, #text "delta")) { "Delta too high" }
                           else if (Text.contains(entry.reason, #text "Exact limit")) { "Exact limit hit" }
                           else if (Text.contains(entry.reason, #text "achievements")) { "Low achievements" }
                           else if (Text.contains(entry.reason, #text "Invalid")) { "Invalid value" }
                           else if (Text.contains(entry.reason, #text "Too fast")) { "Too fast" }
                           else { "Other" };
            switch (reasonCounts.get(reasonKey)) {
              case (?c) { reasonCounts.put(reasonKey, c + 1) };
              case null { reasonCounts.put(reasonKey, 1) };
            };
          };
          
          var result = "📊 SUSPICION STATS\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                      "Total entries: " # Nat.toText(logArray.size()) # "\n\n";
          
          result := result # "🎮 BY GAME:\n";
          for ((game, count) in gameCounts.entries()) {
            result := result # "  " # game # ": " # Nat.toText(count) # "\n";
          };
          
          result := result # "\n⚠️ BY REASON:\n";
          for ((reason, count) in reasonCounts.entries()) {
            result := result # "  " # reason # ": " # Nat.toText(count) # "\n";
          };
          
          result := result # "\n👤 REPEAT OFFENDERS (3+):\n";
          var repeatCount = 0;
          for ((player, count) in playerCounts.entries()) {
            if (count >= 3) {
              result := result # "  " # player # ": " # Nat.toText(count) # " flags\n";
              repeatCount += 1;
            };
          };
          if (repeatCount == 0) {
            result := result # "  None\n";
          };
          
          result := result # "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━";
          
          #ok(result)
        }
      };

      case ("banUser") {
        if (not hasPermission(msg.caller, #Moderator)) {
          #err("🔒 Permission denied: Moderator role required")
        } else if (args.size() < 2) {
          #err("Usage: banUser <type> <id> [reason]\nType: email, principal, external")
        } else {
          let userType = args[0];
          let userId = args[1];
          let reason = if (args.size() >= 3) { args[2] } else { "Cheating" };
          
          // First, log the ban in suspicion log for record
          logSuspicion(userId # "/" # userType, "SYSTEM", "BANNED: " # reason);
          
          // Then remove the user
          let removed = switch (userType) {
            case ("email") { 
              switch (usersByEmail.remove(userId)) {
                case (?_) true;
                case null false;
              }
            };
            case ("external") {
              switch (usersByEmail.remove("ext:" # userId)) {
                case (?_) true;
                case null false;
              }
            };
            case ("principal") {
              let principal = try {
                Principal.fromText(userId)
              } catch (_) {
                return #err("Invalid principal format");
              };
              switch (usersByPrincipal.remove(principal)) {
                case (?_) true;
                case null false;
              }
            };
            case (_) false;
          };
          
          if (removed) {
            #ok("🔨 USER BANNED\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                "User: " # userId # "\n" #
                "Type: " # userType # "\n" #
                "Reason: " # reason # "\n" #
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                "✅ User removed from all leaderboards")
          } else {
            #err("⚠️ User not found: " # userId)
          }
        }
      };

      case ("setOrigins") {
        if (not hasPermission(msg.caller, #SuperAdmin)) {
          #err("🔒 Permission denied: SuperAdmin role required")
        } else if (args.size() < 1) {
          #err("Usage: setOrigins <origin1> <origin2> ...\nExample: setOrigins https://game1.com https://game2.io")
        } else {
          for (origin in args.vals()) {
            if (not Text.startsWith(origin, #text "https://")) {
              return #err("❌ Invalid origin (must be https): " # origin);
            };
          };
          
          alternativeOrigins := Buffer.Buffer<Text>(args.size());
          for (origin in args.vals()) {
            alternativeOrigins.add(origin);
          };
          
          var result = "✅ ORIGINS SET\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
          for (origin in args.vals()) {
            result := result # "• " # origin # "\n";
          };
          result := result # "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                   "Total: " # Nat.toText(args.size()) # " origins";
          
          #ok(result)
        }
      };

      case ("clearOrigins") {
        if (not hasPermission(msg.caller, #SuperAdmin)) {
          #err("🔒 Permission denied: SuperAdmin role required")
        } else {
          let count = alternativeOrigins.size();
          alternativeOrigins := Buffer.Buffer<Text>(10);
          #ok("🗑️ ORIGINS CLEARED\n" #
              "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
              "Removed: " # Nat.toText(count) # " origins\n" #
              "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
              "⚠️ All games will now get domain-specific\n" #
              "   principals until origins are re-added.")
        }
      };
      
      case ("listGames") {
    if (not hasPermission(msg.caller, #Support)) {
        #err("🔒 Permission denied: Support role required")
    } else {
        let limit = if (args.size() > 0) {
            switch (Nat.fromText(args[0])) {
                case (?n) n;
                case null 50;
            }
        } else { 50 };
        
        var result = "🎮 REGISTERED GAMES\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
        var count = 0;
        
        for ((gameId, game) in games.entries()) {
            if (count < limit) {
                let status = if (game.isActive) "✅" else "❌";
                result := result # "\n" # status # " " # gameId # "\n" #
                         "  Name: " # game.name # "\n" #
                         "  Owner: " # Principal.toText(game.owner) # "\n" #
                         "  Players: " # Nat.toText(game.totalPlayers) # "\n" #
                         "  Plays: " # Nat.toText(game.totalPlays) # "\n";
                count += 1;
            };
        };
        
        result := result # "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                 "Showing: " # Nat.toText(count) # " games";
        
        #ok(result)
    }
};

  case ("recoverGames") {
    if (not hasPermission(msg.caller, #SuperAdmin)) {
        #err("🔒 Permission denied: SuperAdmin role required")
    } else {
        var recoveredCount = 0;
        var alreadyExisted = 0;
        
        // Try to recover from legacy stable storage
        if (stableGames.size() > 0) {
            for ((id, oldGame) in stableGames.vals()) {
                switch (games.get(id)) {
                    case (?_) { alreadyExisted += 1 };
                    case null {
                        let migratedGame : GameInfo = {
                            gameId = oldGame.gameId;
                            name = oldGame.name;
                            description = oldGame.description;
                            owner = oldGame.owner;
                            gameUrl = oldGame.gameUrl;
                            created = oldGame.created;
                            accessMode = oldGame.accessMode;
                            totalPlayers = oldGame.totalPlayers;
                            totalPlays = oldGame.totalPlays;
                            isActive = oldGame.isActive;
                            maxScorePerRound = oldGame.maxScorePerRound;
                            maxStreakDelta = oldGame.maxStreakDelta;
                            absoluteScoreCap = oldGame.absoluteScoreCap;
                            absoluteStreakCap = oldGame.absoluteStreakCap;
                            timeValidationEnabled = false;
                            minPlayDurationSecs = null;
                            maxScorePerSecond = null;
                            maxSessionDurationMins = null;
                            googleClientIds = [];
                            appleBundleId = null;
                            appleTeamId = null;
                        };
                        games.put(id, migratedGame);
                        recoveredCount += 1;
                    };
                };
            };
        };
        
        // Also try V2 stable storage (migrate to V3 format)
        if (stableGamesV2.size() > 0) {
            for ((id, oldGame) in stableGamesV2.vals()) {
                switch (games.get(id)) {
                    case (?_) { alreadyExisted += 1 };
                    case null {
                        let migratedGame : GameInfo = {
                            gameId = oldGame.gameId;
                            name = oldGame.name;
                            description = oldGame.description;
                            owner = oldGame.owner;
                            gameUrl = oldGame.gameUrl;
                            created = oldGame.created;
                            accessMode = oldGame.accessMode;
                            totalPlayers = oldGame.totalPlayers;
                            totalPlays = oldGame.totalPlays;
                            isActive = oldGame.isActive;
                            maxScorePerRound = oldGame.maxScorePerRound;
                            maxStreakDelta = oldGame.maxStreakDelta;
                            absoluteScoreCap = oldGame.absoluteScoreCap;
                            absoluteStreakCap = oldGame.absoluteStreakCap;
                            timeValidationEnabled = false;
                            minPlayDurationSecs = null;
                            maxScorePerSecond = null;
                            maxSessionDurationMins = null;
                            googleClientIds = oldGame.googleClientIds;
                            appleBundleId = oldGame.appleBundleId;
                            appleTeamId = oldGame.appleTeamId;
                        };
                        games.put(id, migratedGame);
                        recoveredCount += 1;
                    };
                };
            };
        };
        
        #ok("🎮 GAME RECOVERY COMPLETE\n" #
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
            "Legacy storage: " # Nat.toText(stableGames.size()) # " games\n" #
            "V2 storage: " # Nat.toText(stableGamesV2.size()) # " games\n" #
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
            "Recovered: " # Nat.toText(recoveredCount) # "\n" #
            "Already existed: " # Nat.toText(alreadyExisted) # "\n" #
            "Total games now: " # Nat.toText(games.size()) # "\n" #
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    }
};
  
  case ("debugStorage") {
    if (not hasPermission(msg.caller, #Support)) {
        #err("🔒 Permission denied: Support role required")
    } else {
        #ok("🔍 STORAGE DEBUG\n" #
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
            "Legacy Games (stableGames): " # Nat.toText(stableGames.size()) # "\n" #
            "Legacy Deleted: " # Nat.toText(deletedGamesEntries.size()) # "\n" #
            "V2 Games (stableGamesV2): " # Nat.toText(stableGamesV2.size()) # "\n" #
            "V2 Deleted: " # Nat.toText(deletedGamesEntriesV2.size()) # "\n" #
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
            "Runtime Games: " # Nat.toText(games.size()) # "\n" #
            "Runtime Deleted: " # Nat.toText(deletedGames.size()) # "\n" #
            "Migration Done: " # (if (oauthMigrationDone) "true" else "false") # "\n" #
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    }
};

case ("getGameDetails") {
    if (not hasPermission(msg.caller, #Support)) {
        #err("🔒 Permission denied: Support role required")
    } else if (args.size() < 1) {
        #err("Usage: getGameDetails <gameId>")
    } else {
        let gameId = args[0];
        switch (games.get(gameId)) {
            case null { #err("❌ Game not found: " # gameId) };
            case (?game) {
                let status = if (game.isActive) "✅ Active" else "❌ Inactive";
                #ok("🎮 GAME DETAILS\n" #
                    "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                    "ID: " # game.gameId # "\n" #
                    "Name: " # game.name # "\n" #
                    "Description: " # game.description # "\n" #
                    "Status: " # status # "\n" #
                    "Owner: " # Principal.toText(game.owner) # "\n" #
                    "Created: " # Nat64.toText(game.created) # "\n" #
                    "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                    "📊 Stats\n" #
                    "  Total Players: " # Nat.toText(game.totalPlayers) # "\n" #
                    "  Total Plays: " # Nat.toText(game.totalPlays) # "\n" #
                    "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                    "🛡️ Anti-Cheat\n" #
                    "  Max Score/Round: " # (switch (game.maxScorePerRound) { case (?v) Nat64.toText(v); case null "None" }) # "\n" #
                    "  Max Streak Delta: " # (switch (game.maxStreakDelta) { case (?v) Nat64.toText(v); case null "None" }) # "\n" #
                    "  Absolute Score Cap: " # (switch (game.absoluteScoreCap) { case (?v) Nat64.toText(v); case null "None" }) # "\n" #
                    "  Absolute Streak Cap: " # (switch (game.absoluteStreakCap) { case (?v) Nat64.toText(v); case null "None" }))
            };
        }
    }
};

case ("adminDeleteGame") {
    if (not hasPermission(msg.caller, #Moderator)) {
        #err("🔒 Permission denied: Moderator role required")
    } else if (args.size() < 1) {
        #err("Usage: adminDeleteGame <gameId> [reason]")
    } else {
        let gameId = args[0];
        let reason = if (args.size() >= 2) { args[1] } else { "Admin deletion" };
        
        switch (games.get(gameId)) {
            case null { #err("❌ Game not found: " # gameId) };
            case (?game) {
                let currentTime = Nat64.fromNat(Int.abs(Time.now()));
                let thirtyDays : Nat64 = 30 * 24 * 60 * 60 * 1_000_000_000;
                
                let deletedGame : DeletedGame = {
                    game = game;
                    deletedBy = msg.caller;
                    deletedAt = currentTime;
                    permanentDeletionAt = currentTime + thirtyDays;
                    reason = reason;
                    canRecover = true;
                };
                
                deletedGames.put(gameId, deletedGame);
                
                let inactiveGame : GameInfo = {
                    gameId = game.gameId;
                    name = game.name;
                    description = game.description;
                    owner = game.owner;
                    gameUrl = game.gameUrl;
                    created = game.created;
                    accessMode = game.accessMode;
                    totalPlayers = game.totalPlayers;
                    totalPlays = game.totalPlays;
                    isActive = false;
                    maxScorePerRound = game.maxScorePerRound;
                    maxStreakDelta = game.maxStreakDelta;
                    absoluteScoreCap = game.absoluteScoreCap;
                    absoluteStreakCap = game.absoluteStreakCap;
                timeValidationEnabled = game.timeValidationEnabled;
          minPlayDurationSecs = game.minPlayDurationSecs;
          maxScorePerSecond = game.maxScorePerSecond;
          maxSessionDurationMins = game.maxSessionDurationMins;
          googleClientIds = game.googleClientIds;
                    appleBundleId = game.appleBundleId;
                    appleTeamId = game.appleTeamId;
                };
                games.put(gameId, inactiveGame);
                
                #ok("🗑️ GAME DELETED\n" #
                    "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                    "Game: " # game.name # " (" # gameId # ")\n" #
                    "Owner: " # Principal.toText(game.owner) # "\n" #
                    "Reason: " # reason # "\n" #
                    "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                    "⏱️ 30-day grace period started\n" #
                    "💡 Recover with: adminRecoverGame " # gameId)
            };
        }
    }
};

case ("adminRecoverGame") {
    if (not hasPermission(msg.caller, #Moderator)) {
        #err("🔒 Permission denied: Moderator role required")
    } else if (args.size() < 1) {
        #err("Usage: adminRecoverGame <gameId>")
    } else {
        let gameId = args[0];
        
        switch (deletedGames.get(gameId)) {
            case null { #err("❌ Game not in deleted list: " # gameId) };
            case (?deleted) {
                let currentTime = Nat64.fromNat(Int.abs(Time.now()));
                
                if (currentTime > deleted.permanentDeletionAt) {
                    #err("❌ Recovery period expired")
                } else {
                    let restoredGame : GameInfo = {
                        gameId = deleted.game.gameId;
                        name = deleted.game.name;
                        description = deleted.game.description;
                        owner = deleted.game.owner;
                        gameUrl = deleted.game.gameUrl;
                        created = deleted.game.created;
                        accessMode = deleted.game.accessMode;
                        totalPlayers = deleted.game.totalPlayers;
                        totalPlays = deleted.game.totalPlays;
                        isActive = true;
                        maxScorePerRound = deleted.game.maxScorePerRound;
                        maxStreakDelta = deleted.game.maxStreakDelta;
                        absoluteScoreCap = deleted.game.absoluteScoreCap;
                        absoluteStreakCap = deleted.game.absoluteStreakCap;
                    timeValidationEnabled = deleted.game.timeValidationEnabled;
          minPlayDurationSecs = deleted.game.minPlayDurationSecs;
          maxScorePerSecond = deleted.game.maxScorePerSecond;
          maxSessionDurationMins = deleted.game.maxSessionDurationMins;
          googleClientIds = deleted.game.googleClientIds;
                        appleBundleId = deleted.game.appleBundleId;
                        appleTeamId = deleted.game.appleTeamId;
                    };
                    
                    games.put(gameId, restoredGame);
                    deletedGames.delete(gameId);
                    
                    #ok("♻️ GAME RECOVERED\n" #
                        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                        "Game: " # deleted.game.name # "\n" #
                        "ID: " # gameId # "\n" #
                        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                        "✅ Game restored and active")
                }
            };
        }
    }
};

case ("removeFromScoreboards") {
        if (not hasPermission(msg.caller, #Moderator)) {
          #err("🔒 Permission denied: Moderator role required")
        } else if (args.size() < 2) {
          #err("Usage: removeFromScoreboards <type> <id> [gameId]\n" #
               "Types: email, principal, external, device, nickname\n" #
               "If gameId is omitted, removes from ALL games.\n\n" #
               "Examples:\n" #
               "  removeFromScoreboards device dev_1769650794_62d0dfcb\n" #
               "  removeFromScoreboards nickname Player_6970\n" #
               "  removeFromScoreboards external player_310413122 cheese-match")
        } else {
          let searchType = args[0];
          let searchValue = args[1];
          let gameFilter : ?Text = if (args.size() >= 3) { ?args[2] } else { null };
          
          var removedCount : Nat = 0;
          var boardsChecked : Nat = 0;
          var boardsAffected : Nat = 0;
          
          for ((sbKey, entriesBuffer) in scoreboardEntries.entries()) {
            // If game filter specified, check key starts with gameId
            let shouldCheck = switch (gameFilter) {
              case (?gId) { Text.startsWith(sbKey, #text (gId # ":")) };
              case null { true };
            };
            
            if (shouldCheck) {
              boardsChecked += 1;
              
              // Find matching entries to remove
              let newBuffer = Buffer.Buffer<ScoreEntry>(entriesBuffer.size());
              var foundInThisBoard = false;
              
              for (entry in entriesBuffer.vals()) {
                let shouldRemove = switch (searchType) {
                  case ("nickname") {
                    entry.nickname == searchValue
                  };
                  case ("device") {
                    // Device users stored as #email("ext:dev_xxx") or #email("dev_xxx")
                    switch (entry.odentifier) {
                      case (#email(e)) { 
                        e == searchValue or 
                        e == "ext:" # searchValue or
                        Text.contains(e, #text searchValue)
                      };
                      case (#principal(_)) { false };
                    }
                  };
                  case ("external") {
                    switch (entry.odentifier) {
                      case (#email(e)) { e == "ext:" # searchValue };
                      case (#principal(_)) { false };
                    }
                  };
                  case ("email") {
                    switch (entry.odentifier) {
                      case (#email(e)) { e == searchValue };
                      case (#principal(_)) { false };
                    }
                  };
                  case ("principal") {
                    switch (entry.odentifier) {
                      case (#principal(p)) { Principal.toText(p) == searchValue };
                      case (#email(_)) { false };
                    }
                  };
                  case (_) { false };
                };
                
                if (shouldRemove) {
                  removedCount += 1;
                  foundInThisBoard := true;
                  // Don't add to new buffer (effectively removing it)
                } else {
                  newBuffer.add(entry);
                };
              };
              
              // If entries were removed, update the buffer and invalidate cache
              if (foundInThisBoard) {
                boardsAffected += 1;
                scoreboardEntries.put(sbKey, newBuffer);
                cachedScoreboards.delete(sbKey);
                scoreboardLastUpdate.delete(sbKey);
              };
            };
          };
          
          // Also clear legacy leaderboard caches
          switch (gameFilter) {
            case (?gId) {
              cachedLeaderboards.delete(gId # ":score");
              cachedLeaderboards.delete(gId # ":streak");
              leaderboardLastUpdate.delete(gId # ":score");
              leaderboardLastUpdate.delete(gId # ":streak");
            };
            case null {
              // Clear all legacy caches if no game filter
              for ((key, _) in cachedLeaderboards.entries()) {
                cachedLeaderboards.delete(key);
              };
              for ((key, _) in leaderboardLastUpdate.entries()) {
                leaderboardLastUpdate.delete(key);
              };
            };
          };
          
          if (removedCount > 0) {
            let scopeText = switch (gameFilter) {
              case (?gId) { "game: " # gId };
              case null { "ALL games" };
            };
            
            #ok("🧹 SCOREBOARD CLEANUP\n" #
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                "Search: " # searchType # " = " # searchValue # "\n" #
                "Scope: " # scopeText # "\n" #
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                "Entries removed: " # Nat.toText(removedCount) # "\n" #
                "Boards checked: " # Nat.toText(boardsChecked) # "\n" #
                "Boards affected: " # Nat.toText(boardsAffected) # "\n" #
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                "✅ Caches invalidated - changes visible immediately")
          } else {
            #err("⚠️ No entries found matching: " # searchType # " = " # searchValue # "\n" #
                 "💡 Try 'nickname' type to search by display name\n" #
                 "💡 Use lookupUser to find the correct identifier")
          }
        }
      };

case ("listDeletedGames") {
    if (not hasPermission(msg.caller, #Support)) {
        #err("🔒 Permission denied: Support role required")
    } else {
        var result = "🗑️ DELETED GAMES\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
        var count = 0;
        
        for ((gameId, deleted) in deletedGames.entries()) {
          let currentTime = Nat64.fromNat(Int.abs(Time.now()));
          let daysRemaining : Nat64 = if (deleted.permanentDeletionAt > currentTime) {
            (deleted.permanentDeletionAt - currentTime) / 86_400_000_000_000
          } else { 0 };
          
          result := result # "\n" # gameId # "\n" #
                  "  Name: " # deleted.game.name # "\n" #
                  "  Owner: " # Principal.toText(deleted.game.owner) # "\n" #
                  "  Reason: " # deleted.reason # "\n" #
                  "  Days remaining: " # Nat64.toText(daysRemaining) # "\n";
          count += 1;
      };
        
        if (count == 0) {
            result := result # "\nNo deleted games in grace period.";
        } else {
            result := result # "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                     "Total: " # Nat.toText(count) # " games";
        };
        
        #ok(result)
    }
};

case ("listDevelopers") {
    if (not hasPermission(msg.caller, #Support)) {
        #err("🔒 Permission denied: Support role required")
    } else {
        // Build a map of owners to their games
        let ownerGames = HashMap.HashMap<Principal, Buffer.Buffer<Text>>(10, Principal.equal, Principal.hash);
        
        for ((gameId, game) in games.entries()) {
            switch (ownerGames.get(game.owner)) {
                case null {
                    let buf = Buffer.Buffer<Text>(1);
                    buf.add(gameId);
                    ownerGames.put(game.owner, buf);
                };
                case (?buf) {
                    buf.add(gameId);
                };
            };
        };
        
        var result = "👨‍💻 DEVELOPERS\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
        var count = 0;
        
        for ((owner, gamesBuf) in ownerGames.entries()) {
            let gamesArr = Buffer.toArray(gamesBuf);
            result := result # "\n" # Principal.toText(owner) # "\n" #
                     "  Games: " # Nat.toText(gamesArr.size()) # "\n" #
                     "  IDs: " # Text.join(", ", gamesArr.vals()) # "\n";
            count += 1;
        };
        
        if (count == 0) {
            result := result # "\nNo developers found.";
        } else {
            result := result # "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                     "Total: " # Nat.toText(count) # " developers";
        };
        
        #ok(result)
    }
};

case ("getDeveloperGames") {
    if (not hasPermission(msg.caller, #Support)) {
        #err("🔒 Permission denied: Support role required")
    } else if (args.size() < 1) {
        #err("Usage: getDeveloperGames <principal>")
    } else {
        let principal = try {
            Principal.fromText(args[0])
        } catch (_) {
            return #err("Invalid principal format");
        };
        
        var result = "👨‍💻 DEVELOPER GAMES\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                    "Principal: " # Principal.toText(principal) # "\n\n";
        var count = 0;
        
        for ((gameId, game) in games.entries()) {
            if (Principal.equal(game.owner, principal)) {
                let status = if (game.isActive) "✅" else "❌";
                result := result # status # " " # gameId # "\n" #
                         "  Name: " # game.name # "\n" #
                         "  Players: " # Nat.toText(game.totalPlayers) # "\n" #
                         "  Plays: " # Nat.toText(game.totalPlays) # "\n\n";
                count += 1;
            };
        };
        
        if (count == 0) {
            result := result # "No games found for this developer.";
        } else {
            result := result # "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                     "Total: " # Nat.toText(count) # " games";
        };
        
        #ok(result)
    }
};

      // HARDENING (Oct 2026): one-off repair for keys orphaned before
      // purgeGameRemnants existed. An orphan is an ACTIVE key whose gameId is no
      // longer in the games map at all (soft-deleted games are still in the map,
      // so their keys are left alone). No args = report only; "confirm" applies.
      // Idempotent: a second confirmed run finds nothing.
      case ("sweepOrphanApiKeys") {
        if (not hasPermission(msg.caller, #SuperAdmin)) {
          #err("🔒 Permission denied: SuperAdmin role required")
        } else {
          let apply = args.size() > 0 and args[0] == "confirm";
          let orphans = Buffer.Buffer<(Text, ApiKey)>(0);
          for ((keyText, k) in apiKeys.entries()) {
            if (k.isActive and Option.isNull(games.get(k.gameId))) {
              orphans.add((keyText, k));
            };
          };
          var listing = "";
          var shown = 0;
          for ((keyText, k) in orphans.vals()) {
            if (apply) {
              apiKeys.put(keyText, { k with isActive = false });
            };
            // Game IDs only, never the key text.
            if (shown < 100) { listing := listing # "  " # k.gameId # "\n"; shown += 1 };
          };
          let engineIds = Buffer.Buffer<Text>(0);
          for ((gid, _) in gameEngines.entries()) {
            if (Option.isNull(games.get(gid))) { engineIds.add(gid) };
          };
          let websiteIds = Buffer.Buffer<Text>(0);
          for ((gid, _) in gameWebsites.entries()) {
            if (Option.isNull(games.get(gid))) { websiteIds.add(gid) };
          };
          let staleEngines = engineIds.size();
          let staleWebsites = websiteIds.size();
          if (apply) {
            for (gid in engineIds.vals()) { gameEngines.delete(gid) };
            for (gid in websiteIds.vals()) { gameWebsites.delete(gid) };
          };
          #ok((if (apply) { "🧹 ORPHAN SWEEP APPLIED\n" } else { "🔍 ORPHAN SWEEP (report only, pass \"confirm\" to apply)\n" }) #
              "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
              "Active keys with no game: " # Nat.toText(orphans.size()) # "\n" #
              "Engine tags with no game: " # Nat.toText(staleEngines) # "\n" #
              "Websites with no game: " # Nat.toText(staleWebsites) # "\n" #
              "Total keys stored: " # Nat.toText(apiKeys.size()) # "\n" #
              (if (orphans.size() > 0) { "Game IDs:\n" # listing } else { "" }) #
              "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        }
      };

      // v0.14.0 owner-ID report: how many accounts were seeded, and any emails
      // held back because 2+ emails folded to the same legacy principal.
      case ("ownerIdReport") {
        if (not hasPermission(msg.caller, #SuperAdmin)) {
          #err("🔒 Permission denied: SuperAdmin role required")
        } else {
          var accounts = 0;
          var missing = 0;
          for ((key, _) in usersByEmail.entries()) {
            if (not Text.startsWith(key, #text "ext:")) {
              accounts += 1;
              if (Option.isNull(emailOwnerIds.get(key))) { missing += 1 };
            };
          };
          var listing = "";
          for (e in ownerIdCollisions.vals()) {
            listing := listing # "  " # e # "  (legacy " # Principal.toText(emailToPrincipalSimple(e)) # ")\n";
          };
          #ok("🪪 OWNER ID REPORT\n" #
              "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
              "Seeded: " # debug_show(ownerIdsSeeded) # "\n" #
              "Owner IDs stored: " # Nat.toText(emailOwnerIds.size()) # "\n" #
              "Non-anonymous accounts: " # Nat.toText(accounts) # "\n" #
              "Accounts without an ID: " # Nat.toText(missing) # "\n" #
              "Held collisions: " # Nat.toText(ownerIdCollisions.size()) # "\n" #
              listing #
              "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        }
      };

      // Give a held email its legacy principal (the one its games are owned by).
      // Every other email in the same collision group is released and gets a
      // fresh random ID at its next login. Report-only unless "confirm".
      case ("resolveOwnerCollision") {
        if (not hasPermission(msg.caller, #SuperAdmin)) {
          #err("🔒 Permission denied: SuperAdmin role required")
        } else if (args.size() < 1) {
          #err("Usage: resolveOwnerCollision <email> [confirm]")
        } else if (not isOwnerIdCollision(args[0])) {
          #err("Not a held collision: " # args[0])
        } else {
          let email = args[0];
          let legacy = emailToPrincipalSimple(email);
          let group = Array.filter<Text>(ownerIdCollisions, func(e) { Principal.equal(emailToPrincipalSimple(e), legacy) });
          var owned = 0;
          for ((_, g) in games.entries()) { if (Principal.equal(g.owner, legacy)) { owned += 1 } };
          if (args.size() > 1 and args[1] == "confirm") {
            emailOwnerIds.put(email, legacy);
            ownerIdCollisions := Array.filter<Text>(ownerIdCollisions, func(e) { not Principal.equal(emailToPrincipalSimple(e), legacy) });
            #ok("✅ " # email # " now holds " # Principal.toText(legacy) # " (" # Nat.toText(owned) # " games). Released " # Nat.toText(group.size() - 1) # " other email(s).")
          } else {
            #ok("🔍 " # email # " would get " # Principal.toText(legacy) # " (" # Nat.toText(owned) # " games). Group size " # Nat.toText(group.size()) # ". Pass \"confirm\" to apply.")
          }
        }
      };

      case ("upgradeDeveloper") {
    if (not hasPermission(msg.caller, #SuperAdmin)) {
        #err("🔒 Permission denied: SuperAdmin role required")
    } else if (args.size() < 1) {
        #err("Usage: upgradeDeveloper <email>")
    } else {
        let email = args[0];
        switch (emailOwnerIds.get(email)) {
          case null { return #err("No developer identity for " # email # " (they need to sign in once)") };
          case (?principal) { developerTiers.put(principal, #pro) };
        };
        #ok("⭐ DEVELOPER UPGRADED TO PRO\n" #
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
            "Email: " # email # "\n" #
            "Max Games: 10\n" #
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    }
};

case ("downgradeDeveloper") {
    if (not hasPermission(msg.caller, #SuperAdmin)) {
        #err("🔒 Permission denied: SuperAdmin role required")
    } else if (args.size() < 1) {
        #err("Usage: downgradeDeveloper <email>")
    } else {
        let email = args[0];
        switch (emailOwnerIds.get(email)) {
          case null { return #err("No developer identity for " # email) };
          case (?principal) { developerTiers.delete(principal) };
        };
        #ok("Developer downgraded to free tier (3 games max)")
    }
};

  case ("listProDevelopers") {
      if (not hasPermission(msg.caller, #Support)) {
          #err("🔒 Permission denied")
      } else {
          var result = "⭐ PRO DEVELOPERS\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
          var count = 0;
          
          for ((principal, tier) in developerTiers.entries()) {
              switch (tier) {
                  case (#pro) {
                      result := result # Principal.toText(principal) # "\n";
                      count += 1;
                  };
                  case (_) {};
              };
          };
          
          if (count == 0) {
              result := result # "\nNo pro developers yet.";
          } else {
              result := result # "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                      "Total: " # Nat.toText(count) # " pro developers";
          };
          
          #ok(result)
      }
  };
      case ("getStats") {
        if (not hasPermission(msg.caller, #ReadOnly)) {
          #err("🔒 Permission denied: ReadOnly role required")
        } else {
          let emailUsers = usersByEmail.size();
          let principalUsers = usersByPrincipal.size();
          let gameCount = games.size();
          let deletedCount = deletedUsers.size();
          let adminCount = adminRoles.size();
          let auditCount = auditLogStable.size() + auditLog.size();
          
          var totalGameProfiles = 0;
          for ((_, user) in usersByEmail.entries()) {
            totalGameProfiles += user.gameProfiles.size();
          };
          for ((_, user) in usersByPrincipal.entries()) {
            totalGameProfiles += user.gameProfiles.size();
          };
          
          #ok("📊 SYSTEM STATISTICS\n" #
              "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
              "👥 Users\n" #
              "  Email: " # Nat.toText(emailUsers) # "\n" #
              "  Principal: " # Nat.toText(principalUsers) # "\n" #
              "  Total active: " # Nat.toText(emailUsers + principalUsers) # "\n" #
              "  Soft deleted: " # Nat.toText(deletedCount) # "\n" #
              "\n🎮 Games\n" #
              "  Registered: " # Nat.toText(gameCount) # "\n" #
              "  Total profiles: " # Nat.toText(totalGameProfiles) # "\n" #
              "\n🔐 Security\n" #
              "  Admins: " # Nat.toText(adminCount) # "\n" #
              "  Audit logs: " # Nat.toText(auditCount) # "\n" #
              "  Emergency pause: " # (if (emergencyPaused) "🚨 ACTIVE" else "✅ Normal") # "\n" #
              "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        }
      };
      
      case ("repairMigratedStreaks") {
        if (not hasPermission(msg.caller, #SuperAdmin)) {
          #err("🔒 Permission denied: SuperAdmin role required")
        } else {
          // args[0] selects dry-run vs apply. Default to dry-run when absent
          // so a bare call can't accidentally write.
          let dryRun = if (args.size() < 1) { true }
                       else { args[0] != "false" };
          #ok(repairMigratedStreaksInternal(dryRun))
        }
      };
      
      // ═══════════════════════════════════════════════════════════════════
      // GAME INSIGHT COMMANDS (added 2026-08-13)
      // ═══════════════════════════════════════════════════════════════════

      case ("topGames") {
        if (not hasPermission(msg.caller, #Support)) {
          #err("🔒 Permission denied: Support role required")
        } else {
          let limit = if (args.size() > 0) {
            switch (Nat.fromText(args[0])) { case (?n) n; case null 20 }
          } else { 20 };

          let arr = Iter.toArray(games.entries());
          let sorted = Array.sort<(Text, GameInfo)>(arr, func(a, b) {
            Nat.compare(b.1.totalPlays, a.1.totalPlays)
          });

          var result = "🏆 TOP GAMES BY PLAYS\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                       "Total submissions all-time: " # Nat.toText(totalSubmissions) # "\n";
          var count = 0;
          for ((gameId, game) in sorted.vals()) {
            if (count < limit) {
              let status = if (game.isActive) "✅" else "❌";
              let share = if (totalSubmissions == 0) { 0 } else {
                (game.totalPlays * 1000) / totalSubmissions
              };
              let shareText = Nat.toText(share / 10) # "." # Nat.toText(share % 10) # "%";
              result := result # "\n" # status # " " # gameId # " — " # game.name # "\n" #
                        "  Players: " # Nat.toText(game.totalPlayers) #
                        "  Plays: " # Nat.toText(game.totalPlays) #
                        "  Share: " # shareText # "\n";
              count += 1;
            };
          };
          result := result # "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                    "Showing top " # Nat.toText(count) # " of " # Nat.toText(arr.size()) # " games\n" #
                    "(Share = game plays / all-time submissions)";
          #ok(result)
        }
      };

      case ("gameContact") {
        if (not hasPermission(msg.caller, #Support)) {
          #err("🔒 Permission denied: Support role required")
        } else if (args.size() < 1) {
          #err("Usage: gameContact <gameId>")
        } else {
          let gameId = args[0];
          switch (games.get(gameId)) {
            case null { #err("❌ Game not found: " # gameId) };
            case (?game) {
              var result = "📇 GAME OWNER CONTACT\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                           "Game: " # game.name # " (" # gameId # ")\n" #
                           "Owner principal: " # Principal.toText(game.owner) # "\n";

              // Tier
              let tier = switch (developerTiers.get(game.owner)) {
                case (?#pro) "⭐ Pro (10 slots)";
                case _ "Free (3 slots)";
              };
              result := result # "Tier: " # tier # "\n";

              var found = false;

              // Direct II / principal-keyed owner
              switch (usersByPrincipal.get(game.owner)) {
                case (?user) {
                  found := true;
                  result := result # "\n🔑 Principal account:\n" #
                            "  Nickname: " # user.nickname # "\n" #
                            "  Auth: " # debug_show(user.authType) # "\n" #
                            "  Created: " # Nat64.toText(user.created) # "\n";
                };
                case null {};
              };

              // OAuth / session owner: reverse lookup through the owner-ID map
              for ((key, ownerId) in emailOwnerIds.entries()) {
                switch (if (Principal.equal(ownerId, game.owner)) { usersByEmail.get(key) } else { null }) {
                case null {};
                case (?user) {
                  found := true;
                  let keyType = if (Text.startsWith(key, #text "ext:")) { "external" }
                                else if (Text.startsWith(key, #text "dev_")) { "device" }
                                else { "email" };
                  result := result # "\n📧 Matched account (" # keyType # "):\n" #
                            "  Contact: " # key # "\n" #
                            "  Nickname: " # user.nickname # "\n" #
                            "  Auth: " # debug_show(user.authType) # "\n" #
                            "  Created: " # Nat64.toText(user.created) # "\n";
                };
                };
              };

              if (not found) {
                result := result # "\n⚠️ No user record matched this owner principal.\n" #
                          "(Owner may have registered via a path that left no profile.)";
              };
              result := result # "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━";
              #ok(result)
            };
          }
        }
      };

      case ("listBoards") {
        if (not hasPermission(msg.caller, #Support)) {
          #err("🔒 Permission denied: Support role required")
        } else if (args.size() < 1) {
          #err("Usage: listBoards <gameId>")
        } else {
          let gameId = args[0];
          if (Option.isNull(games.get(gameId))) {
            return #err("❌ Game not found: " # gameId);
          };
          var result = "📋 SCOREBOARDS — " # gameId # "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
          var count = 0;
          for ((key, config) in scoreboardConfigs.entries()) {
            if (config.gameId == gameId) {
              let entryCount = switch (scoreboardEntries.get(key)) {
                case (?buf) { buf.size() };
                case null { 0 };
              };
              let status = if (config.isActive) "✅" else "❌";
              result := result # "\n" # status # " " # config.scoreboardId # " — " # config.name # "\n" #
                        "  Period: " # periodToText(config.period) #
                        "  Entries: " # Nat.toText(entryCount) # "/" # Nat.toText(config.maxEntries) # "\n";
              count += 1;
            };
          };
          if (count == 0) {
            result := result # "\nNo scoreboards found for this game.";
          } else {
            result := result # "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                      Nat.toText(count) # " boards";
          };
          #ok(result)
        }
      };

      case ("viewBoard") {
        if (not hasPermission(msg.caller, #Support)) {
          #err("🔒 Permission denied: Support role required")
        } else if (args.size() < 2) {
          #err("Usage: viewBoard <gameId> <scoreboardId> [limit]")
        } else {
          let gameId = args[0];
          let scoreboardId = args[1];
          let limit = if (args.size() > 2) {
            switch (Nat.fromText(args[2])) { case (?n) n; case null 20 }
          } else { 20 };

          let key = makeScoreboardKey(gameId, scoreboardId);
          switch (scoreboardConfigs.get(key)) {
            case null { #err("❌ Scoreboard not found: " # gameId # " / " # scoreboardId) };
            case (?config) {
              let entries = switch (scoreboardEntries.get(key)) {
                case null { [] : [ScoreEntry] };
                case (?buf) { Scoreboards.sortEntries(Buffer.toArray(buf), config.sortBy) };
              };
              let t = now();
              var result = "🔎 BOARD ENTRIES — " # gameId # " / " # scoreboardId # "\n" #
                           "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                           "Total entries: " # Nat.toText(entries.size()) # "\n";
              var rank : Nat = 1;
              label show for (e in entries.vals()) {
                if (rank > limit) { break show };
                let ageNs : Nat64 = if (t > e.submittedAt) { t - e.submittedAt } else { 0 };
                let ageSecs = Nat64.toNat(ageNs / 1_000_000_000);
                let age = if (ageSecs < 60) { Nat.toText(ageSecs) # "s ago" }
                          else if (ageSecs < 3600) { Nat.toText(ageSecs / 60) # "m ago" }
                          else if (ageSecs < 86400) { Nat.toText(ageSecs / 3600) # "h ago" }
                          else { Nat.toText(ageSecs / 86400) # "d ago" };
                result := result # "\n#" # Nat.toText(rank) # " " # e.nickname #
                          " — score " # Nat64.toText(e.score) #
                          "  streak " # Nat64.toText(e.streak) # "\n" #
                          "  " # age # "  [" # authTypeToText(e.authType) # "]" #
                          "  key: " # playerKeyOf(e.odentifier) # "\n";
                rank += 1;
              };
              result := result # "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
                        "Showing " # Nat.toText(Nat.min(limit, entries.size())) #
                        " of " # Nat.toText(entries.size()) # " (sorted by " #
                        (switch (config.sortBy) { case (#score) "score"; case (#streak) "streak" }) # ")";
              #ok(result)
            };
          }
        }
      };

      case ("help") {
        #ok("📚 ADMIN COMMANDS\n" #
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
            "👥 User Management (Moderator+)\n" #
            "  • deleteUser <type> <id> [reason]\n" #
            "  • confirmDeleteUser <userId> <code>\n" #
            "  • recoverUser <userId>\n" #
            "  • listDeletedUsers\n" #
            "  • removeUser <type> <id>\n" #
            "  • exportUserData <type> <id>\n" #
            "  • lookupByNickname <nickname>\n" #
            "\n🌐 II Origins (SuperAdmin)\n" #
            "  • addOrigin <https://domain.com>\n" #
            "  • removeOrigin <https://domain.com>\n" #
            "  • setOrigins <origin1> <origin2> ...\n" #
            "  • clearOrigins\n" #
            "  • listOrigins (Support+)\n" #
            "\n🗄️ Backup (SuperAdmin)\n" #
            "  • backup\n" #
            "\n🔐 Security (SuperAdmin)\n" #
            "  • emergencyPause\n" #
            "  • emergencyUnpause\n" #
            "  • addAdmin <principal> <role>\n" #
            "  • removeAdmin <principal>\n" #
            "\n📊 Information (Support+)\n" #
            "  • getStats\n" #
            "  • listAdmins\n" #
            "  • auditLog [limit]\n" #
            "\n🎮 Game Insight (Support+)\n" #
            "  • topGames [limit]\n" #
            "  • gameContact <gameId>\n" #
            "  • listBoards <gameId>\n" #
            "  • viewBoard <gameId> <scoreboardId> [limit]\n" #
            "\n⚠️ Dangerous (SuperAdmin)\n" #
            "  • permanentDelete <userId>\n" #
            "  • repairMigratedStreaks [true|false]  (true=dry-run, default true)\n" #
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" #
            "Roles: SuperAdmin > Moderator > Support > ReadOnly")
      };
      
      case (_) {
        #err("❌ Unknown command. Type 'help' for available commands.")
      };
    };
    
    let success = switch (result) {
      case (#ok(_)) true;
      case (#err(_)) false;
    };
    
    let resultMsg = switch (result) {
      case (#ok(m)) m;
      case (#err(m)) m;
    };
    
    logAction(msg.caller, command, args, success, resultMsg);
    
    result
  };


private func emailToPrincipalSimple(email: Text) : Principal {
    let bytes = Blob.toArray(Text.encodeUtf8(email));
    var hash : [var Nat8] = Array.init<Nat8>(29, 0);
    hash[0] := 0x04; // Self-authenticating prefix
    
    for (i in Iter.range(0, bytes.size() - 1)) {
        let idx = (i % 28) + 1;
        hash[idx] := hash[idx] ^ bytes[i];
    };
    
    Principal.fromBlob(Blob.fromArray(Array.freeze(hash)))
};

// ═══════════════════════════════════════════════════════════════════════════════
// DEVELOPER OWNER IDS (v0.14.0)
// Session-path owner identity is LOOKED UP by exact email, never computed.
// emailToPrincipalSimple is an XOR fold (trivially collidable), so it is now
// only used once, to seed existing accounts with the principal they already
// own games/tiers/contacts under. New accounts get a random principal at login.
// ═══════════════════════════════════════════════════════════════════════════════

// Matches no game.owner: folds start 0x04, random IDs end 0x01, II ends 0x02.
private func noOwner() : Principal {
    Principal.fromBlob(Blob.fromArray([0x00 : Nat8, 0x7f]))
};

private func isOwnerIdCollision(email : Text) : Bool {
    Option.isSome(Array.find<Text>(ownerIdCollisions, func(e) { e == email }))
};

/// For read-only query paths: an unknown email simply owns nothing.
private func ownerIdOrNobody(email : Text) : Principal {
    switch (emailOwnerIds.get(email)) {
        case (?p) { p };
        case null { noOwner() };
    }
};

/// Called by the verifier-gated login paths before minting a session.
/// Emails held as seeding collisions are left unassigned for admin review.
private func ensureOwnerId(email : Text) : async* () {
    if (Option.isSome(emailOwnerIds.get(email))) { return };
    if (isOwnerIdCollision(email)) { return };
    let bytes = await* takeRandomBytes(28);
    if (Option.isSome(emailOwnerIds.get(email))) { return }; // concurrent login won
    emailOwnerIds.put(email, Principal.fromBlob(Blob.fromArray(Array.append<Nat8>(bytes, [0x01]))));
};

/// One-time seed from existing accounts. Any fold shared by 2+ emails is NOT
/// seeded for any of them; those emails go to ownerIdCollisions and are
/// resolved by hand with adminGate resolveOwnerCollision.
private func seedOwnerIds() {
    if (ownerIdsSeeded) { return };
    let byFold = HashMap.HashMap<Principal, Buffer.Buffer<Text>>(256, Principal.equal, Principal.hash);
    for ((key, _) in usersByEmail.entries()) {
        // Real verified emails only: anon keys are "ext:..." / "dev_..." with no '@'.
        // Every session-capable key (anything but anonymous "ext:" players), not just
        // ones containing '@': the verifier can mint sessions for any key string.
        // Skip anything already assigned (e.g. a fresh install that took logins first).
        if (Option.isNull(emailOwnerIds.get(key)) and not Text.startsWith(key, #text "ext:")) {
            let p = emailToPrincipalSimple(key);
            switch (byFold.get(p)) {
                case (?b) { b.add(key) };
                case null {
                    let b = Buffer.Buffer<Text>(1);
                    b.add(key);
                    byFold.put(p, b);
                };
            };
        };
    };
    let held = Buffer.Buffer<Text>(0);
    for ((p, emails) in byFold.entries()) {
        if (emails.size() == 1) {
            emailOwnerIds.put(emails.get(0), p);
        } else {
            for (e in emails.vals()) { held.add(e) };
        };
    };
    ownerIdCollisions := Buffer.toArray(held);
    ownerIdsSeeded := true;
};

// ═══════════════════════════════════════════════════════════════════════════════
// HELPER: Validate session and get owner Principal
// ═══════════════════════════════════════════════════════════════════════════════

/// Delete every login session held by this email (and any stale
/// principalToSession pointer at it). Used by removeUser so a removed
/// account can't keep acting through an open dashboard tab.
private func sweepSessionsForEmail(email : Text) : Nat {
    let toDelete = Buffer.Buffer<Text>(4);
    for ((sessionId, session) in sessions.entries()) {
        if (session.email == email) { toDelete.add(sessionId) };
    };
    for (sessionId in toDelete.vals()) { sessions.delete(sessionId) };
    let stalePointers = Buffer.Buffer<Text>(2);
    for ((p, sessionId) in principalToSession.entries()) {
        if (Option.isNull(sessions.get(sessionId))) { stalePointers.add(p) };
    };
    for (p in stalePointers.vals()) { principalToSession.delete(p) };
    toDelete.size()
};

private transient let OWNER_ID_MISSING : Text = "Developer identity unavailable for this account. Sign out and back in, or contact info@cheddaboards.com if this persists.";

private func getOwnerFromSession(sessionId: Text) : Result.Result<Principal, Text> {
    switch (sessions.get(sessionId)) {
        case null { #err("Invalid or expired session") };
        case (?session) {
            let currentTime = Nat64.fromNat(Int.abs(Time.now()));
            if (session.expires < currentTime) {
                sessions.delete(sessionId);
                return #err("Session expired");
            };
            switch (emailOwnerIds.get(session.email)) {
                case (?p) { #ok(p) };
                case null { #err(OWNER_ID_MISSING) };
            }
        };
    };
};

// ═══════════════════════════════════════════════════════════════════════════════
// HELPER: Get remaining delete attempts for owner
// ═══════════════════════════════════════════════════════════════════════════════

private func getRemainingDeleteAttemptsForOwner(owner: Principal) : Nat {
    let currentTime = Nat64.fromNat(Int.abs(Time.now()));
    let hourAgo = currentTime - (60 * 60 * 1_000_000_000);
    
    switch (deleteRateLimit.get(owner)) {
        case null { 3 };
        case (?attempts) {
            var recentCount = 0;
            for (attempt in attempts.vals()) {
                if (attempt.timestamp > hourAgo) {
                    recentCount += 1;
                };
            };
            if (recentCount >= 3) { 0 } else { 3 - recentCount }
        };
    };
};

// ═══════════════════════════════════════════════════════════════════════════════
// HELPER: Count games by owner
// ═══════════════════════════════════════════════════════════════════════════════

private func getGameCountByOwner(owner: Principal) : Nat {
    var count = 0;
    for ((_, game) in games.entries()) {
        if (Principal.equal(game.owner, owner) and game.isActive) {
            count += 1;
        };
    };
    count
};

// ═══════════════════════════════════════════════════════════════════════════════
// HELPER: Validate game ID format
// ═══════════════════════════════════════════════════════════════════════════════

private func isValidGameId(gameId: Text) : Bool {
    if (Text.size(gameId) < 3 or Text.size(gameId) > 50) {
        return false;
    };
    
    for (char in gameId.chars()) {
        let valid = (char >= 'a' and char <= 'z') or 
                    (char >= '0' and char <= '9') or 
                    char == '-';
        if (not valid) {
            return false;
        };
    };
    
    true
};

// ═══════════════════════════════════════════════════════════════════════════════
// GET GAMES BY SESSION
// ═══════════════════════════════════════════════════════════════════════════════

public query func getGamesBySession(sessionId: Text) : async [GameInfo] {
    switch (getValidSession(sessionId)) {
        case null { return [] };
        case (?session) {
            let owner = ownerIdOrNobody(session.email);
            
            let ownerGames = Buffer.Buffer<GameInfo>(0);
            for ((_, game) in games.entries()) {
                if (Principal.equal(game.owner, owner) and game.isActive) {
                    ownerGames.add(game);
                };
            };
            
            Buffer.toArray(ownerGames)
        };
    };
};

public query func getSuspicionLogBySession(sessionId: Text, gameId: Text, limit: Nat) : async [{
    player_id: Text;
    gameId: Text;
    reason: Text;
    timestamp: Nat64;
  }] {
    switch (getValidSession(sessionId)) {
      case null { return [] };
      case (?session) {
        let owner = ownerIdOrNobody(session.email);
        
        // Verify caller owns this game
        switch (games.get(gameId)) {
          case null { return [] };
          case (?game) {
            if (not Principal.equal(game.owner, owner)) { return [] };
            
            // Same logic as viewSuspicionLog but returns structured data
            let logArray = List.toArray(suspicionLog);
            let result = Buffer.Buffer<{ player_id: Text; gameId: Text; reason: Text; timestamp: Nat64 }>(0);
            let cap = if (limit > 100) { 100 } else { limit };
            var count = 0;
            
            let size = logArray.size();
            label logLoop for (i in Iter.range(0, size - 1)) {
              if (count >= cap) { break logLoop };
              let entry = logArray[size - 1 - i];
              if (entry.gameId == gameId) {
                result.add(entry);
                count += 1;
              };
            };
            
            Buffer.toArray(result)
          };
        };
      };
    };
};

// ═══════════════════════════════════════════════════════════════════════════════
// GET DELETED GAMES BY SESSION
// ═══════════════════════════════════════════════════════════════════════════════

public query func getDeletedGamesBySession(sessionId: Text) : async [DeletedGame] {
    switch (getValidSession(sessionId)) {
        case null { return [] };
        case (?session) {
            let owner = ownerIdOrNobody(session.email);
            
            let ownerDeleted = Buffer.Buffer<DeletedGame>(0);
            for ((_, deleted) in deletedGames.entries()) {
                if (Principal.equal(deleted.deletedBy, owner)) {
                    ownerDeleted.add(deleted);
                };
            };
            
            Buffer.toArray(ownerDeleted)
        };
    };
};

// ═══════════════════════════════════════════════════════════════════════════════
// GET REMAINING DELETE ATTEMPTS BY SESSION
// ═══════════════════════════════════════════════════════════════════════════════

public query func getRemainingDeleteAttemptsBySession(sessionId: Text) : async Nat {
    switch (getValidSession(sessionId)) {
        case null { return 0 };
        case (?session) {
            let owner = ownerIdOrNobody(session.email);
            getRemainingDeleteAttemptsForOwner(owner)
        };
    };
};

private func purgePlayerFromScoreboards(searchType: Text, searchValue: Text, gameFilter: ?Text) : Nat {
    var removedCount : Nat = 0;
    
    for ((sbKey, entriesBuffer) in scoreboardEntries.entries()) {
      let shouldCheck = switch (gameFilter) {
        case (?gId) { Text.startsWith(sbKey, #text (gId # ":")) };
        case null { true };
      };
      
      if (shouldCheck) {
        let newBuffer = Buffer.Buffer<ScoreEntry>(entriesBuffer.size());
        var foundInThisBoard = false;
        
        for (entry in entriesBuffer.vals()) {
          let shouldRemove = switch (searchType) {
            case ("nickname") {
              entry.nickname == searchValue
            };
            case ("device") {
              switch (entry.odentifier) {
                case (#email(e)) { 
                  e == searchValue or 
                  e == "ext:" # searchValue or
                  Text.contains(e, #text searchValue)
                };
                case (#principal(_)) { false };
              }
            };
            case ("external") {
              switch (entry.odentifier) {
                case (#email(e)) { e == "ext:" # searchValue };
                case (#principal(_)) { false };
              }
            };
            case ("email") {
              switch (entry.odentifier) {
                case (#email(e)) { e == searchValue };
                case (#principal(_)) { false };
              }
            };
            case ("principal") {
              switch (entry.odentifier) {
                case (#principal(p)) { Principal.toText(p) == searchValue };
                case (#email(_)) { false };
              }
            };
            case (_) { false };
          };
          
          if (shouldRemove) {
            removedCount += 1;
            foundInThisBoard := true;
          } else {
            newBuffer.add(entry);
          };
        };
        
        if (foundInThisBoard) {
          scoreboardEntries.put(sbKey, newBuffer);
          cachedScoreboards.delete(sbKey);
          scoreboardLastUpdate.delete(sbKey);
        };
      };
    };
    
    removedCount
};


}