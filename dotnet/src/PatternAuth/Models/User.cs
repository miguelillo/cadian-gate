using MongoDB.Bson.Serialization.Attributes;

namespace PatternAuth.Models;

// A pattern-auth user. The identity (_id) is a keyed HMAC of the normalized
// pattern + password — the raw pattern and password are NEVER stored. TOTP is
// the optional (recommended) second factor; backup codes are single-use bcrypt
// hashes. See UserService.
public class User
{
    [BsonId] public string Id { get; set; } = "";   // HMAC-SHA256(pattern|password), hex
    public string Label { get; set; } = "";          // human-facing name, not a credential
    public string? TotpSecret { get; set; }
    public bool TotpEnabled { get; set; }
    public List<string> BackupCodeHashes { get; set; } = new();
    public DateTime CreatedAt { get; set; }
    public DateTime? LastLoginAt { get; set; }
}
