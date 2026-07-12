using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;
using MongoDB.Driver;
using PatternAuth.Models;

namespace PatternAuth;

// Pattern-auth user store (MongoDB, collection name from options).
//
// Identity model: a user is identified AND authenticated by the combination of
// an unlock pattern and a password. Their _id is a keyed HMAC-SHA256 of the
// normalized "pattern|password" — deterministic (so a login is an O(1) lookup)
// but not brute-forceable offline without the server key, even if the DB
// leaks. The raw pattern/password are never persisted.
//
// Null-tolerant: without Mongo configured the store is empty, so pattern login
// simply never matches and the env break-glass path still works.
public class UserService
{
    public const int DefaultGridSize = 6;
    public const int DefaultMinPatternLength = 4;
    private const char Sep = '␟';             // unambiguous pattern|password separator

    private readonly IMongoCollection<User>? _collection;
    private readonly byte[] _key;
    private readonly int _gridSize;
    private readonly int _minPatternLength;

    public UserService(IConfiguration config, PatternAuthOptions opts, PatternAuthMongo mongo)
    {
        _collection = mongo.Database?.GetCollection<User>(opts.UsersCollection);
        var keyMaterial = config[opts.UserIdKeyKey] ?? config[opts.JwtSecretKey] ?? "";
        _key = Encoding.UTF8.GetBytes(keyMaterial);
        _gridSize = opts.PatternGridSize;
        _minPatternLength = opts.MinPatternLength;
    }

    public bool Available => _collection is not null;
    public int GridSize => _gridSize;

    // Validates a pattern string ("0-5-12-35"): dots on the gridSize×gridSize
    // grid, distinct, at least minLength. Returns the canonical form (order
    // preserved) or null.
    public static string? NormalizePattern(string? pattern,
        int gridSize = DefaultGridSize, int minLength = DefaultMinPatternLength)
    {
        if (string.IsNullOrWhiteSpace(pattern)) return null;
        var parts = pattern.Split('-', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length < minLength) return null;
        var nodeCount = gridSize * gridSize;
        var seen = new HashSet<int>();
        foreach (var p in parts)
        {
            if (!int.TryParse(p, out var n) || n < 0 || n >= nodeCount || !seen.Add(n)) return null;
        }
        return string.Join('-', parts);
    }

    // Keyed HMAC of pattern|password → the user identity. Null if the pattern is invalid.
    public string? ComputeId(string? pattern, string? password)
    {
        var norm = NormalizePattern(pattern, _gridSize, _minPatternLength);
        if (norm is null || password is null) return null;
        using var h = new HMACSHA256(_key);
        var bytes = h.ComputeHash(Encoding.UTF8.GetBytes(norm + Sep + password));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    public User? Identify(string? pattern, string? password)
    {
        if (_collection is null) return null;
        var id = ComputeId(pattern, password);
        if (id is null) return null;
        try { return _collection.Find(u => u.Id == id).FirstOrDefault(); }
        catch { return null; }
    }

    public (bool ok, string? error, string? id) Create(string? label, string? pattern, string? password,
        string? totpSecret, bool totpEnabled, List<string>? backupCodeHashes)
    {
        if (_collection is null) return (false, "User store unavailable (Mongo not configured).", null);
        if (string.IsNullOrWhiteSpace(label)) return (false, "A label is required.", null);
        if (NormalizePattern(pattern, _gridSize, _minPatternLength) is null)
            return (false, $"Pattern must be {_minPatternLength}+ distinct dots on the {_gridSize}×{_gridSize} grid.", null);
        if (string.IsNullOrEmpty(password)) return (false, "A password is required.", null);

        var id = ComputeId(pattern, password)!;
        try
        {
            if (_collection.Find(u => u.Id == id).FirstOrDefault() is not null)
                return (false, "That pattern + password is already in use.", null);

            _collection.InsertOne(new User
            {
                Id = id,
                Label = label.Trim(),
                TotpSecret = string.IsNullOrWhiteSpace(totpSecret) ? null : totpSecret,
                TotpEnabled = totpEnabled && !string.IsNullOrWhiteSpace(totpSecret),
                BackupCodeHashes = backupCodeHashes ?? new(),
                CreatedAt = DateTime.UtcNow,
            });
            return (true, null, id);
        }
        catch { return (false, "Could not save the user.", null); }
    }

    // Users listed for admin — labels and metadata only, never secrets.
    public List<object> List()
    {
        if (_collection is null) return new();
        try
        {
            return _collection.Find(FilterDefinition<User>.Empty).ToList()
                .OrderBy(u => u.Label)
                .Select(u => (object)new
                {
                    id = u.Id,
                    label = u.Label,
                    totpEnabled = u.TotpEnabled,
                    backupCodesRemaining = u.BackupCodeHashes.Count,
                    createdAt = u.CreatedAt,
                    lastLoginAt = u.LastLoginAt,
                })
                .ToList();
        }
        catch { return new(); }
    }

    public long Count()
    {
        if (_collection is null) return 0;
        try { return _collection.CountDocuments(FilterDefinition<User>.Empty); }
        catch { return 0; }
    }

    public bool Delete(string id)
    {
        if (_collection is null) return false;
        try { return _collection.DeleteOne(u => u.Id == id).DeletedCount > 0; }
        catch { return false; }
    }

    public void RecordLogin(string id)
    {
        if (_collection is null) return;
        try { _collection.UpdateOne(u => u.Id == id, Builders<User>.Update.Set(u => u.LastLoginAt, DateTime.UtcNow)); }
        catch { /* best-effort */ }
    }

    // Verifies a backup code for a user and, on match, permanently consumes it.
    public bool ConsumeBackupCode(User user, string? code)
    {
        if (_collection is null || string.IsNullOrWhiteSpace(code)) return false;
        var candidate = code.Trim().ToUpperInvariant();
        foreach (var hash in user.BackupCodeHashes.ToList())
        {
            bool ok;
            try { ok = BCrypt.Net.BCrypt.Verify(candidate, hash); } catch { ok = false; }
            if (!ok) continue;
            try { _collection.UpdateOne(u => u.Id == user.Id, Builders<User>.Update.Pull(u => u.BackupCodeHashes, hash)); }
            catch { /* best-effort — the auth already succeeded */ }
            return true;
        }
        return false;
    }
}
