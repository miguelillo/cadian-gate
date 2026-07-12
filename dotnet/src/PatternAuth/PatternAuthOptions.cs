using MongoDB.Driver;

namespace PatternAuth;

/// <summary>
/// All knobs of the pattern-auth system. Every default reproduces the behavior
/// of the original homelab-map integration, so an existing deployment can adopt
/// the package by overriding only <see cref="MongoDatabaseFactory"/>.
/// </summary>
public sealed class PatternAuthOptions
{
    // ── Wire behavior ────────────────────────────────────────────────
    public string CookieName { get; set; } = "homelab_token";
    public TimeSpan TokenLifetime { get; set; } = TimeSpan.FromDays(30);
    public string BasePath { get; set; } = "/api/auth";
    public string UsersBasePath { get; set; } = "/api/users";

    /// <summary>Rate-limiting policy applied to POST {BasePath}/login. The host
    /// must define the policy (AddRateLimiter) and call UseRateLimiter. Set to
    /// null to attach no rate-limiting metadata.</summary>
    public string? LoginRateLimitPolicy { get; set; } = "login";

    // ── IConfiguration key names (values are read from IConfiguration) ──
    public string JwtSecretKey { get; set; } = "JWT_SECRET";
    public string PasswordHashKey { get; set; } = "HOMELAB_PASSWORD_HASH";
    public string TotpEnabledKey { get; set; } = "HOMELAB_TOTP_ENABLED";
    public string TotpSecretKey { get; set; } = "HOMELAB_TOTP_SECRET";
    public string BackupCodesKey { get; set; } = "HOMELAB_BACKUP_CODES";
    /// <summary>Key for the HMAC key deriving user identities. Falls back to
    /// the JWT secret when the configured key has no value.</summary>
    public string UserIdKeyKey { get; set; } = "HOMELAB_USER_ID_KEY";
    public string BreakglassEnabledKey { get; set; } = "HOMELAB_BREAKGLASS_ENABLED";

    // ── TOTP enrollment labels (otpauth:// URIs and the setup page) ──
    public string TotpIssuer { get; set; } = "homelab";
    public string TotpAccountName { get; set; } = "MINAVE.CASA";

    // ── Mongo persistence ────────────────────────────────────────────
    /// <summary>Supplies the IMongoDatabase used for the user store, the access
    /// audit log and consumed backup codes. Null (or a factory returning null)
    /// degrades gracefully: no persistence, pattern login never matches, and
    /// break-glass sign-in stays available — useful for CI and first boot.</summary>
    public Func<IServiceProvider, IMongoDatabase?>? MongoDatabaseFactory { get; set; }
    public string UsersCollection { get; set; } = "users";
    public string AccessEventsCollection { get; set; } = "access_events";
    public string ConsumedBackupCodesCollection { get; set; } = "consumed_backup_codes";

    // ── Pattern & lockout tuning ─────────────────────────────────────
    public int PatternGridSize { get; set; } = 6;
    public int MinPatternLength { get; set; } = 4;
    public int LockoutMaxFailures { get; set; } = 10;
    public TimeSpan LockoutDuration { get; set; } = TimeSpan.FromMinutes(15);
}

/// <summary>Resolved Mongo handle for the pattern-auth services. Database is
/// null when persistence isn't configured (degraded in-memory mode).</summary>
public sealed class PatternAuthMongo
{
    public IMongoDatabase? Database { get; }
    public PatternAuthMongo(IMongoDatabase? database) => Database = database;
}
