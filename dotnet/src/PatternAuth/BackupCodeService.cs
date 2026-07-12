using Microsoft.Extensions.Configuration;
using MongoDB.Bson;
using MongoDB.Driver;

namespace PatternAuth;

/// <summary>
/// Single-use TOTP recovery codes for the break-glass sign-in. The configured
/// key holds the base64 of a comma-separated list of bcrypt hashes. It is
/// base64-encoded because bcrypt hashes contain '$', which Docker Compose would
/// otherwise interpolate as a variable when the value flows through a compose
/// file. Consumed codes are tracked by hash in Mongo (one document per hash,
/// `_id` = hash) so a code stays spent across container recreates. When Mongo
/// isn't configured, consumed codes are tracked in memory only.
/// </summary>
public class BackupCodeService
{
    private readonly object _lock = new();
    private readonly List<string> _hashes;
    private readonly HashSet<string> _consumed;
    private readonly IMongoCollection<BsonDocument>? _collection;

    public BackupCodeService(IConfiguration config, PatternAuthOptions opts, PatternAuthMongo mongo)
    {
        _hashes = DecodeHashes(config[opts.BackupCodesKey]);
        _collection = mongo.Database?.GetCollection<BsonDocument>(opts.ConsumedBackupCodesCollection);

        _consumed = new HashSet<string>();
        if (_collection is not null)
        {
            try
            {
                foreach (var doc in _collection.Find(new BsonDocument()).ToList())
                    _consumed.Add(doc["_id"].AsString);
            }
            catch { /* offline — start with an empty consumed set */ }
        }
    }

    // Accepts either base64(comma-joined hashes) or, as a fallback, a raw
    // comma-separated list (useful for local runs that bypass Compose).
    private static List<string> DecodeHashes(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return new List<string>();
        var value = raw.Trim();
        if (!value.Contains('$'))
        {
            try { value = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(value)); }
            catch { /* not base64 — treat as already-plain below */ }
        }
        return value
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToList();
    }

    public int Remaining()
    {
        lock (_lock) return _hashes.Count(h => !_consumed.Contains(h));
    }

    /// <summary>Verifies a code and, on match, permanently consumes it.</summary>
    public bool TryConsume(string? code)
    {
        if (string.IsNullOrWhiteSpace(code)) return false;
        var candidate = code.Trim().ToUpperInvariant();

        lock (_lock)
        {
            foreach (var hash in _hashes)
            {
                if (_consumed.Contains(hash)) continue;
                bool ok;
                try { ok = BCrypt.Net.BCrypt.Verify(candidate, hash); }
                catch { ok = false; }
                if (!ok) continue;

                _consumed.Add(hash);
                PersistConsumed(hash);
                return true;
            }
        }
        return false;
    }

    private void PersistConsumed(string hash)
    {
        if (_collection is null) return;
        try { _collection.InsertOne(new BsonDocument("_id", hash)); }
        catch { /* duplicate or offline — in-memory set still blocks reuse this process */ }
    }
}
