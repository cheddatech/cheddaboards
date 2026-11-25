// ════════════════════════════════════════════════════════════════════════════════
// CheddaBoards Scoreboards Module
// Scoreboard logic, period management, and entry helpers
// ════════════════════════════════════════════════════════════════════════════════

import Principal "mo:base/Principal";
import Text "mo:base/Text";
import Nat "mo:base/Nat";
import Nat64 "mo:base/Nat64";
import Buffer "mo:base/Buffer";
import Array "mo:base/Array";
import Order "mo:base/Order";

import Types "../types";

module {

  // ════════════════════════════════════════════════════════════════════════════
  // TYPE ALIASES
  // ════════════════════════════════════════════════════════════════════════════

  public type UserIdentifier = Types.UserIdentifier;
  public type AuthType = Types.AuthType;
  public type AccessMode = Types.AccessMode;
  public type SortBy = Types.SortBy;
  public type ScoreboardPeriod = Types.ScoreboardPeriod;
  public type ScoreboardConfig = Types.ScoreboardConfig;
  public type ScoreEntry = Types.ScoreEntry;
  public type PublicScoreEntry = Types.PublicScoreEntry;
  public type ArchivedScoreboard = Types.ArchivedScoreboard;
  public type ArchiveInfo = Types.ArchiveInfo;

  // ════════════════════════════════════════════════════════════════════════════
  // CONSTANTS
  // ════════════════════════════════════════════════════════════════════════════

  public let DAY_IN_NANOS : Nat64 = 86_400_000_000_000;
  public let WEEK_IN_NANOS : Nat64 = 604_800_000_000_000;
  public let MONTH_IN_NANOS : Nat64 = 2_592_000_000_000_000;  // ~30 days
  public let DEFAULT_MAX_ENTRIES : Nat = 100;
  public let MAX_ARCHIVES_PER_SCOREBOARD : Nat = 52;  // ~1 year of weekly

  // ════════════════════════════════════════════════════════════════════════════
  // KEY GENERATION
  // ════════════════════════════════════════════════════════════════════════════

  /// Create a key for a scoreboard (gameId:scoreboardId)
  public func makeKey(gameId : Text, scoreboardId : Text) : Text {
    gameId # ":" # scoreboardId
  };

  /// Create a key for an archived scoreboard
  public func makeArchiveKey(gameId : Text, scoreboardId : Text, timestamp : Nat64) : Text {
    gameId # ":" # scoreboardId # ":" # Nat64.toText(timestamp)
  };

  // ════════════════════════════════════════════════════════════════════════════
  // TYPE CONVERSIONS
  // ════════════════════════════════════════════════════════════════════════════

  /// Convert ScoreboardPeriod to text
  public func periodToText(period : ScoreboardPeriod) : Text {
    switch (period) {
      case (#allTime) { "allTime" };
      case (#daily) { "daily" };
      case (#weekly) { "weekly" };
      case (#monthly) { "monthly" };
      case (#custom) { "custom" };
    }
  };

  /// Convert text to ScoreboardPeriod
  public func textToPeriod(text : Text) : ?ScoreboardPeriod {
    switch (text) {
      case ("allTime") { ?#allTime };
      case ("daily") { ?#daily };
      case ("weekly") { ?#weekly };
      case ("monthly") { ?#monthly };
      case ("custom") { ?#custom };
      case (_) { null };
    }
  };

  /// Convert SortBy to text
  public func sortByToText(sortBy : SortBy) : Text {
    switch (sortBy) {
      case (#score) { "score" };
      case (#streak) { "streak" };
    }
  };

  /// Convert text to SortBy
  public func textToSortBy(text : Text) : ?SortBy {
    switch (text) {
      case ("score") { ?#score };
      case ("streak") { ?#streak };
      case (_) { null };
    }
  };

  /// Convert AuthType to text
  public func authTypeToText(auth : AuthType) : Text {
    switch (auth) {
      case (#internetIdentity) "internetIdentity";
      case (#google) "google";
      case (#apple) "apple";
      case (#external) "external";
    }
  };

  /// Convert AccessMode to text
  public func accessModeToText(mode : AccessMode) : Text {
    switch (mode) {
      case (#webOnly) "webOnly";
      case (#apiOnly) "apiOnly";
      case (#both) "both";
    }
  };

  // ════════════════════════════════════════════════════════════════════════════
  // TIME / PERIOD HELPERS
  // ════════════════════════════════════════════════════════════════════════════

  // ── Calendar boundary helpers (all UTC) ──────────────────────────────────
  // ICP time is nanoseconds since the Unix epoch, so day boundaries fall out
  // of integer division. Week/month need a little more work.

  /// Start of the current UTC day (00:00)
  public func dayStart(currentTime : Nat64) : Nat64 {
    (currentTime / DAY_IN_NANOS) * DAY_IN_NANOS
  };

  /// Start of the current ISO week (Monday 00:00 UTC)
  public func weekStart(currentTime : Nat64) : Nat64 {
    let d = currentTime / DAY_IN_NANOS;
    // 1 Jan 1970 was a Thursday, so days since the most recent Monday = (d + 3) % 7
    let daysSinceMonday = (d + 3) % 7;
    (d - daysSinceMonday) * DAY_IN_NANOS
  };

  /// Start of the current calendar month (1st, 00:00 UTC).
  /// Uses the civil-from-days algorithm (handles month lengths + leap years).
  public func monthStart(currentTime : Nat64) : Nat64 {
    let d = currentTime / DAY_IN_NANOS;
    let z = d + 719_468;
    let doe = z % 146_097;                                              // day of era [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // year of era [0, 399]
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);                  // day of (Mar-based) year
    let mp = (5 * doy + 2) / 153;                                       // month index [0, 11]
    let dayOfMonth0 = doy - (153 * mp + 2) / 5;                         // day of month, 0-based
    (d - dayOfMonth0) * DAY_IN_NANOS
  };

  /// Check if daily scoreboard should reset (midnight UTC boundary)
  public func shouldResetDaily(lastReset : Nat64, currentTime : Nat64) : Bool {
    lastReset < dayStart(currentTime)
  };

  /// Check if weekly scoreboard should reset (Monday 00:00 UTC boundary)
  public func shouldResetWeekly(lastReset : Nat64, currentTime : Nat64) : Bool {
    lastReset < weekStart(currentTime)
  };

  /// Check if monthly scoreboard should reset (1st of month 00:00 UTC boundary)
  public func shouldResetMonthly(lastReset : Nat64, currentTime : Nat64) : Bool {
    lastReset < monthStart(currentTime)
  };

  /// Where the CURRENT period began. Use this as the new lastReset when a
  /// board resets (sweep or lazy write-side reset) so periods stay anchored
  /// to calendar boundaries — and so archive periodStart values are exact.
  public func currentPeriodStart(config : ScoreboardConfig, currentTime : Nat64) : Nat64 {
    switch (config.period) {
      case (#daily) { dayStart(currentTime) };
      case (#weekly) { weekStart(currentTime) };
      case (#monthly) { monthStart(currentTime) };
      case (#custom) {
        switch (config.resetIntervalNanos) {
          case (?n) {
            if (n == 0) { currentTime } else {
              // Snap forward from lastReset by whole intervals (no drift)
              let elapsed = currentTime - config.lastReset;
              config.lastReset + (elapsed / n) * n
            }
          };
          case null { currentTime };
        }
      };
      case (#allTime) { currentTime };
    }
  };

  /// Check if a scoreboard needs reset based on its period and current time
  public func needsReset(config : ScoreboardConfig, currentTime : Nat64) : Bool {
    switch (config.period) {
      case (#allTime) { false };
      case (#custom) {
        // Configurable: never, unless a reset interval is set — then every N nanos.
        switch (config.resetIntervalNanos) {
          case (?n) { n > 0 and currentTime - config.lastReset >= n };
          case null { false };
        }
      };
      case (#daily) { shouldResetDaily(config.lastReset, currentTime) };
      case (#weekly) { shouldResetWeekly(config.lastReset, currentTime) };
      case (#monthly) { shouldResetMonthly(config.lastReset, currentTime) };
    }
  };

  // ════════════════════════════════════════════════════════════════════════════
  // IDENTIFIER HELPERS
  // ════════════════════════════════════════════════════════════════════════════

  /// Check if two UserIdentifiers are equal
  public func identifiersEqual(a : UserIdentifier, b : UserIdentifier) : Bool {
    switch (a, b) {
      case (#principal(p1), #principal(p2)) { Principal.equal(p1, p2) };
      case (#email(e1), #email(e2)) { e1 == e2 };
      case _ { false };
    }
  };

  // ════════════════════════════════════════════════════════════════════════════
  // ENTRY HELPERS
  // ════════════════════════════════════════════════════════════════════════════

  /// Get the comparison value from an entry based on sortBy
  public func getEntryValue(entry : ScoreEntry, sortBy : SortBy) : Nat64 {
    switch (sortBy) {
      case (#score) { entry.score };
      case (#streak) { entry.streak };
    }
  };

  /// Find an existing entry for a user in a buffer
  /// Returns (entry, index) if found
  public func findUserEntry(
    entries : Buffer.Buffer<ScoreEntry>,
    identifier : UserIdentifier
  ) : ?(ScoreEntry, Nat) {
    var idx : Nat = 0;
    for (entry in entries.vals()) {
      if (identifiersEqual(entry.odentifier, identifier)) {
        return ?(entry, idx);
      };
      idx += 1;
    };
    null
  };

  /// Find the index of the worst (lowest value) entry in a buffer
  public func findWorstEntryIndex(entries : Buffer.Buffer<ScoreEntry>, sortBy : SortBy) : Nat {
    var worstIdx : Nat = 0;
    var worstValue : Nat64 = getEntryValue(entries.get(0), sortBy);
    
    var i : Nat = 1;
    while (i < entries.size()) {
      let entryValue = getEntryValue(entries.get(i), sortBy);
      if (entryValue < worstValue) {
        worstValue := entryValue;
        worstIdx := i;
      };
      i += 1;
    };
    worstIdx
  };

  /// Remove entry at index from buffer, returning new buffer
  public func removeEntryAt(entries : Buffer.Buffer<ScoreEntry>, removeIdx : Nat, maxSize : Nat) : Buffer.Buffer<ScoreEntry> {
    let newBuffer = Buffer.Buffer<ScoreEntry>(maxSize);
    var i : Nat = 0;
    for (entry in entries.vals()) {
      if (i != removeIdx) {
        newBuffer.add(entry);
      };
      i += 1;
    };
    newBuffer
  };

  /// Create a new ScoreEntry
  public func createEntry(
    identifier : UserIdentifier,
    nickname : Text,
    score : Nat64,
    streak : Nat64,
    timestamp : Nat64,
    authType : AuthType
  ) : ScoreEntry {
    {
      odentifier = identifier;  // Note: typo preserved for backwards compat
      nickname = nickname;
      score = score;
      streak = streak;
      submittedAt = timestamp;
      authType = authType;
    }
  };

  /// Update just the nickname on an existing entry
  public func updateEntryNickname(entry : ScoreEntry, newNickname : Text) : ScoreEntry {
    {
      odentifier = entry.odentifier;
      nickname = newNickname;
      score = entry.score;
      streak = entry.streak;
      submittedAt = entry.submittedAt;
      authType = entry.authType;
    }
  };

  /// Convert internal ScoreEntry to public format with rank
  public func toPublicEntry(entry : ScoreEntry, rank : Nat) : PublicScoreEntry {
    {
      nickname = entry.nickname;
      displayName = null;
      score = entry.score;
      streak = entry.streak;
      submittedAt = entry.submittedAt;
      authType = authTypeToText(entry.authType);
      rank = rank;
    }
  };

  // ════════════════════════════════════════════════════════════════════════════
  // SORTING
  // ════════════════════════════════════════════════════════════════════════════

  /// Sort entries by score (descending)
  public func sortByScore(entries : [ScoreEntry]) : [ScoreEntry] {
    Array.sort<ScoreEntry>(
      entries,
      func(a, b) {
        if (a.score > b.score) { #less }
        else if (a.score < b.score) { #greater }
        else { #equal }
      }
    )
  };

  /// Sort entries by streak (descending)
  public func sortByStreak(entries : [ScoreEntry]) : [ScoreEntry] {
    Array.sort<ScoreEntry>(
      entries,
      func(a, b) {
        if (a.streak > b.streak) { #less }
        else if (a.streak < b.streak) { #greater }
        else { #equal }
      }
    )
  };

  /// Sort entries by the configured sortBy field
  public func sortEntries(entries : [ScoreEntry], sortBy : SortBy) : [ScoreEntry] {
    switch (sortBy) {
      case (#score) { sortByScore(entries) };
      case (#streak) { sortByStreak(entries) };
    }
  };

  // ════════════════════════════════════════════════════════════════════════════
  // CONFIG HELPERS
  // ════════════════════════════════════════════════════════════════════════════

  /// Create a new ScoreboardConfig
  public func createConfig(
    gameId : Text,
    scoreboardId : Text,
    name : Text,
    description : Text,
    period : ScoreboardPeriod,
    sortBy : SortBy,
    maxEntries : Nat,
    targeted : Bool,
    resetIntervalNanos : ?Nat64,
    timestamp : Nat64
  ) : ScoreboardConfig {
    {
      scoreboardId = scoreboardId;
      gameId = gameId;
      name = name;
      description = description;
      period = period;
      sortBy = sortBy;
      maxEntries = maxEntries;
      created = timestamp;
      lastReset = timestamp;
      isActive = true;
      targeted = ?targeted;
      resetIntervalNanos = resetIntervalNanos;
    }
  };

  /// Update config with new lastReset timestamp
  public func resetConfig(config : ScoreboardConfig, newTimestamp : Nat64) : ScoreboardConfig {
    {
      scoreboardId = config.scoreboardId;
      gameId = config.gameId;
      name = config.name;
      description = config.description;
      period = config.period;
      sortBy = config.sortBy;
      maxEntries = config.maxEntries;
      created = config.created;
      lastReset = newTimestamp;
      isActive = config.isActive;
      targeted = config.targeted;
      resetIntervalNanos = config.resetIntervalNanos;
    }
  };

  /// Create default "All Time" scoreboard config
  public func createAllTimeConfig(gameId : Text, timestamp : Nat64) : ScoreboardConfig {
    createConfig(
      gameId,
      "all-time",
      "All Time",
      "Best scores of all time",
      #allTime,
      #score,
      DEFAULT_MAX_ENTRIES,
      false,   // targeted: fan-out board
      null,    // resetIntervalNanos: n/a for #allTime
      timestamp
    )
  };

  /// Create default "Weekly" scoreboard config
  public func createWeeklyConfig(gameId : Text, timestamp : Nat64) : ScoreboardConfig {
    createConfig(
      gameId,
      "weekly",
      "Weekly",
      "Top scores this week",
      #weekly,
      #score,
      DEFAULT_MAX_ENTRIES,
      false,   // targeted: fan-out board
      null,    // resetIntervalNanos: n/a for #weekly
      timestamp
    )
  };

  // ════════════════════════════════════════════════════════════════════════════
  // ARCHIVE HELPERS
  // ════════════════════════════════════════════════════════════════════════════

  /// Create an ArchivedScoreboard from a config and entries
  public func createArchive(
    config : ScoreboardConfig,
    entries : [ScoreEntry],
    archiveTimestamp : Nat64
  ) : ArchivedScoreboard {
    {
      scoreboardId = config.scoreboardId;
      gameId = config.gameId;
      name = config.name;
      period = config.period;
      sortBy = config.sortBy;
      periodStart = config.lastReset;
      periodEnd = archiveTimestamp;
      entries = entries;
      totalEntries = entries.size();
    }
  };

  /// Create lightweight ArchiveInfo from an archived scoreboard
  public func toArchiveInfo(archiveKey : Text, archive : ArchivedScoreboard) : ArchiveInfo {
    let topEntry = if (archive.entries.size() > 0) {
      let sorted = sortEntries(archive.entries, archive.sortBy);
      ?sorted[0]
    } else {
      null
    };
    
    {
      archiveId = archiveKey;
      scoreboardId = archive.scoreboardId;
      periodStart = archive.periodStart;
      periodEnd = archive.periodEnd;
      entryCount = archive.totalEntries;
      topPlayer = switch (topEntry) {
        case (?e) { ?e.nickname };
        case null { null };
      };
      topScore = switch (topEntry) {
        case (?e) { 
          switch (archive.sortBy) {
            case (#score) { e.score };
            case (#streak) { e.streak };
          }
        };
        case null { 0 };
      };
    }
  };

}
