using MongoDB.Bson;
using MongoDB.Driver;

namespace PatternAuth;

// Best-effort audit log of login attempts, persisted to Mongo (collection name
// from options). Fire-and-forget inserts so login latency is unaffected; a
// no-op when Mongo isn't configured.
public class AccessLogService
{
    private readonly IMongoCollection<BsonDocument>? _collection;

    public AccessLogService(PatternAuthOptions opts, PatternAuthMongo mongo)
    {
        _collection = mongo.Database?.GetCollection<BsonDocument>(opts.AccessEventsCollection);
    }

    // outcome: "success" | "invalid" | "locked"
    public void Record(string ip, string outcome, bool usedTotp = false, bool usedBackupCode = false,
        int? attemptsRemaining = null, LoginFingerprint? fp = null)
    {
        if (_collection is null) return;

        var doc = new BsonDocument
        {
            { "time", DateTime.UtcNow },
            { "ip", ip },
            { "outcome", outcome },
            { "usedTotp", usedTotp },
            { "usedBackupCode", usedBackupCode },
        };
        if (attemptsRemaining is not null) doc.Add("attemptsRemaining", attemptsRemaining.Value);

        if (fp is not null)
        {
            void AddStr(string key, string? v, int max)
            {
                if (!string.IsNullOrEmpty(v)) doc[key] = v.Length > max ? v[..max] : v;
            }
            AddStr("clientIp", fp.Ip, 64);
            AddStr("isp", fp.Isp, 64);
            AddStr("city", fp.City, 64);
            AddStr("country", fp.Country, 64);
            if (fp.LatencyMs is int lat) doc["latencyMs"] = lat;
            AddStr("os", fp.Os, 48);
            AddStr("browser", fp.Browser, 48);
            AddStr("resolution", fp.Resolution, 32);
            AddStr("tz", fp.Tz, 64);
            AddStr("lang", fp.Lang, 16);
            AddStr("cores", fp.Cores, 8);
            if (fp.Mem is int mem) doc["mem"] = mem;
            AddStr("touch", fp.Touch, 8);
            AddStr("cookies", fp.Cookies, 16);
            AddStr("userAgent", fp.UserAgent, 512);
        }

        _ = InsertSafe(doc);
    }

    private async Task InsertSafe(BsonDocument doc)
    {
        try { await _collection!.InsertOneAsync(doc); }
        catch { /* best-effort audit — never break login on a logging failure */ }
    }
}
