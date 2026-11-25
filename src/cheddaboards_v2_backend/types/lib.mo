// ════════════════════════════════════════════════════════════════════════════════
// CheddaBoards Types Module
// All shared type definitions for the CheddaBoards backend
// ════════════════════════════════════════════════════════════════════════════════

import Principal "mo:base/Principal";
import Result "mo:base/Result";

module {

  // ════════════════════════════════════════════════════════════════════════════
  // CORE IDENTITY TYPES
  // ════════════════════════════════════════════════════════════════════════════

  /// Identifies a user - either by email (OAuth) or principal (Internet Identity)
  public type UserIdentifier = {
    #email : Text;
    #principal : Principal;
  };

  /// Authentication method used by a user
  public type AuthType = {
    #internetIdentity;
    #google;
    #apple;
    #external;  // API key / server-to-server
  };

  /// Developer subscription tier
  public type DeveloperTier = {
    #free;  // 3 games
    #pro;   // 10 games
  };

  // ════════════════════════════════════════════════════════════════════════════
  // SESSION TYPES
  // ════════════════════════════════════════════════════════════════════════════

  /// Active user session (for OAuth users)
  public type Session = {
    sessionId : Text;
    email : Text;
    nickname : Text;
    authType : AuthType;
    created : Nat64;
    expires : Nat64;
    lastUsed : Nat64;
  };

  /// Play session for time-validated score submission
  public type PlaySession = {
    sessionToken : Text;        // Unique token for this play session
    identifier : UserIdentifier; // Who's playing
    gameId : Text;              // Which game
    startedAt : Nat64;          // When they started (server timestamp)
    expiresAt : Nat64;          // Auto-expire if not submitted
    isActive : Bool;            // Still valid for submission
  };

  /// Result of time validation check
  public type TimeValidationResult = {
    isValid : Bool;
    playDuration : Nat64;       // Actual seconds played
    reason : ?Text;             // Why it failed (if invalid)
  };

  // ════════════════════════════════════════════════════════════════════════════
  // USER / PLAYER TYPES
  // ════════════════════════════════════════════════════════════════════════════

  /// Player's stats for a specific game
  public type GameProfile = {
    gameId : Text;
    total_score : Nat64;
    best_streak : Nat64;
    achievements : [Text];
    last_played : Nat64;
    play_count : Nat;
  };

  /// Full user profile (internal use)
  public type UserProfile = {
    identifier : UserIdentifier;
    nickname : Text;
    authType : AuthType;
    gameProfiles : [(Text, GameProfile)];
    created : Nat64;
    last_updated : Nat64;
  };

  /// Public user profile (no sensitive data)
  public type PublicUserProfile = {
    nickname : Text;
    authType : AuthType;
    gameProfiles : [(Text, GameProfile)];
    created : Nat64;
    last_updated : Nat64;
  };

  // ════════════════════════════════════════════════════════════════════════════
  // GAME TYPES
  // ════════════════════════════════════════════════════════════════════════════

  /// How a game can be accessed
  public type AccessMode = {
    #webOnly;
    #apiOnly;
    #both;
  };

  /// Current game info structure (v3 - with time validation + OAuth)
  public type GameInfo = {
    gameId : Text;
    name : Text;
    description : Text;
    owner : Principal;
    gameUrl : ?Text;
    created : Nat64;
    accessMode : AccessMode;
    totalPlayers : Nat;
    totalPlays : Nat;
    isActive : Bool;
    // Anti-cheat: score limits
    maxScorePerRound : ?Nat64;
    maxStreakDelta : ?Nat64;
    absoluteScoreCap : ?Nat64;
    absoluteStreakCap : ?Nat64;
    // Anti-cheat: time validation
    timeValidationEnabled : Bool;
    minPlayDurationSecs : ?Nat64;
    maxScorePerSecond : ?Nat64;
    maxSessionDurationMins : ?Nat;
    // OAuth credentials
    googleClientIds : [Text];
    appleBundleId : ?Text;
    appleTeamId : ?Text;
  };

  /// Legacy game info (v1 - no OAuth, no time validation)
  public type GameInfoLegacy = {
    gameId : Text;
    name : Text;
    description : Text;
    owner : Principal;
    created : Nat64;
    isActive : Bool;
    totalPlayers : Nat;
    totalPlays : Nat;
    accessMode : AccessMode;
    maxScorePerRound : ?Nat64;
    maxStreakDelta : ?Nat64;
    absoluteScoreCap : ?Nat64;
    absoluteStreakCap : ?Nat64;
    gameUrl : ?Text;
  };

  /// Game info v2 (with OAuth, no time validation)
  public type GameInfoV2 = {
    gameId : Text;
    name : Text;
    description : Text;
    owner : Principal;
    created : Nat64;
    isActive : Bool;
    totalPlayers : Nat;
    totalPlays : Nat;
    accessMode : AccessMode;
    maxScorePerRound : ?Nat64;
    maxStreakDelta : ?Nat64;
    absoluteScoreCap : ?Nat64;
    absoluteStreakCap : ?Nat64;
    gameUrl : ?Text;
    googleClientIds : [Text];
    appleBundleId : ?Text;
    appleTeamId : ?Text;
  };

  /// Soft-deleted game (current version)
  public type DeletedGame = {
    game : GameInfo;
    deletedBy : Principal;
    deletedAt : Nat64;
    permanentDeletionAt : Nat64;
    reason : Text;
    canRecover : Bool;
  };

  /// Soft-deleted game (legacy v1)
  public type DeletedGameLegacy = {
    game : GameInfoLegacy;
    deletedBy : Principal;
    deletedAt : Nat64;
    permanentDeletionAt : Nat64;
    reason : Text;
    canRecover : Bool;
  };

  /// Soft-deleted game (v2)
  public type DeletedGameV2 = {
    game : GameInfoV2;
    deletedBy : Principal;
    deletedAt : Nat64;
    permanentDeletionAt : Nat64;
    reason : Text;
    canRecover : Bool;
  };

  /// Rate limiting for game deletion
  public type DeletionAttempt = {
    timestamp : Nat64;
    gameId : Text;
  };

  // ════════════════════════════════════════════════════════════════════════════
  // SCOREBOARD TYPES
  // ════════════════════════════════════════════════════════════════════════════

  /// How to sort leaderboard entries
  public type SortBy = {
    #score;
    #streak;
  };

  /// Reset period for time-based scoreboards
  public type ScoreboardPeriod = {
    #allTime;   // Never resets
    #daily;     // Resets daily at midnight UTC
    #weekly;    // Resets weekly on Monday midnight UTC
    #monthly;   // Resets on 1st of each month
    #custom;    // Configurable cadence: never, or every N (see ScoreboardConfig.resetIntervalNanos)
  };

  /// Scoreboard configuration (set by developer)
  public type ScoreboardConfig = {
    scoreboardId : Text;
    gameId : Text;
    name : Text;
    description : Text;
    period : ScoreboardPeriod;
    sortBy : SortBy;
    maxEntries : Nat;
    created : Nat64;
    lastReset : Nat64;
    isActive : Bool;
    // Both OPTIONAL so existing persisted configs upgrade cleanly (old data → null).
    targeted : ?Bool;             // ?true = targeted-only (category) board; null/?false = fan-out
    resetIntervalNanos : ?Nat64;  // when period == #custom: reset every N nanos; null = never
  };

  /// Individual score entry (internal - includes identifier)
  public type ScoreEntry = {
    odentifier : UserIdentifier;  // Named for backwards compat (typo preserved)
    nickname : Text;
    score : Nat64;
    streak : Nat64;
    submittedAt : Nat64;
    authType : AuthType;
  };

  /// Public score entry (no identifier exposed)
  public type PublicScoreEntry = {
    nickname : Text;
    displayName : ?Text;
    score : Nat64;
    streak : Nat64;
    submittedAt : Nat64;
    authType : Text;
    rank : Nat;
  };

  /// Full scoreboard with config and entries
  public type Scoreboard = {
    config : ScoreboardConfig;
    entries : [ScoreEntry];
  };

  /// Archived scoreboard (frozen at reset time)
  public type ArchivedScoreboard = {
    scoreboardId : Text;
    gameId : Text;
    name : Text;
    period : ScoreboardPeriod;
    sortBy : SortBy;
    periodStart : Nat64;
    periodEnd : Nat64;
    entries : [ScoreEntry];
    totalEntries : Nat;
  };

  /// Lightweight archive info for listing
  public type ArchiveInfo = {
    archiveId : Text;        // "gameId:scoreboardId:timestamp"
    scoreboardId : Text;
    periodStart : Nat64;
    periodEnd : Nat64;
    entryCount : Nat;
    topPlayer : ?Text;
    topScore : Nat64;
  };

  // ════════════════════════════════════════════════════════════════════════════
  // API KEY TYPES
  // ════════════════════════════════════════════════════════════════════════════

  /// API key for server-to-server access
  public type ApiKey = {
    key : Text;
    gameId : Text;
    owner : Principal;
    created : Int;
    lastUsed : Int;
    tier : Text;
    requestsToday : Nat;
    isActive : Bool;
  };

  // ════════════════════════════════════════════════════════════════════════════
  // ANALYTICS TYPES
  // ════════════════════════════════════════════════════════════════════════════

  /// Tracked analytics event
  public type AnalyticsEvent = {
    eventType : Text;
    gameId : Text;
    identifier : UserIdentifier;
    timestamp : Nat64;
    metadata : [(Text, Text)];
  };

  /// Daily aggregated stats for a game
  public type DailyStats = {
    date : Text;
    gameId : Text;
    uniquePlayers : Nat;
    totalGames : Nat;
    totalScore : Nat64;
    newUsers : Nat;
    authenticatedPlays : Nat;
  };

  /// Player-specific analytics
  public type PlayerStats = {
    gameId : Text;
    identifier : UserIdentifier;
    totalGames : Nat;
    avgScore : Nat64;
    playStreak : Nat;
    lastPlayed : Nat64;
    favoriteTime : Text;
  };

  // ════════════════════════════════════════════════════════════════════════════
  // ADMIN / SECURITY TYPES
  // ════════════════════════════════════════════════════════════════════════════

  /// Admin permission level
  public type AdminRole = {
    #SuperAdmin;
    #Moderator;
    #Support;
    #ReadOnly;
  };

  /// Audit log entry for admin actions
  public type AdminAction = {
    timestamp : Nat64;
    admin : Principal;
    adminRole : AdminRole;
    command : Text;
    args : [Text];
    success : Bool;
    result : Text;
    ipAddress : ?Text;
  };

  /// Soft-deleted user
  public type DeletedUser = {
    user : UserProfile;
    deletedBy : Principal;
    deletedAt : Nat64;
    permanentDeletionAt : Nat64;
    reason : Text;
    canRecover : Bool;
  };

  /// Pending user deletion (requires confirmation)
  public type PendingDeletion = {
    userId : Text;
    userType : Text;
    requestedBy : Principal;
    requestedAt : Nat64;
    confirmationCode : Text;
    expiresAt : Nat64;
  };

  /// Full system backup
  public type BackupData = {
    version : Text;
    timestamp : Nat64;
    createdBy : Principal;
    emailUsers : [(Text, UserProfile)];
    principalUsers : [(Principal, UserProfile)];
    games : [(Text, GameInfo)];
    deletedUsers : [(Text, DeletedUser)];
    metadata : {
      totalUsers : Nat;
      totalGames : Nat;
      totalGameProfiles : Nat;
      totalDeletedUsers : Nat;
    };
  };

  /// Suspicion log entry (anti-cheat)
  public type SuspicionLogEntry = {
    player_id : Text;
    gameId : Text;
    reason : Text;
    timestamp : Nat64;
  };

  // ════════════════════════════════════════════════════════════════════════════
  // HTTP TYPES (for HTTP Gateway / API)
  // ════════════════════════════════════════════════════════════════════════════

  public type HeaderField = (Text, Text);

  public type HttpRequest = {
    method : Text;
    url : Text;
    headers : [HeaderField];
    body : Blob;
  };

  public type HttpResponse = {
    status_code : Nat16;
    headers : [HeaderField];
    body : Blob;
    streaming_strategy : ?StreamingStrategy;
  };

  public type StreamingStrategy = {
    #Callback : {
      callback : shared query StreamingCallbackToken -> async StreamingCallbackResponse;
      token : StreamingCallbackToken;
    };
  };

  public type StreamingCallbackToken = {
    key : Text;
    index : Nat;
    content_encoding : Text;
  };

  public type StreamingCallbackResponse = {
    body : Blob;
    token : ?StreamingCallbackToken;
  };

};
