using MongoDB.Bson.Serialization.Attributes;

namespace PatternAuth.Models;

// An auth user. Two kinds coexist in the same collection:
//
//  • Pattern users — the identity (_id) is a keyed HMAC of the normalized
//    pattern + password; the raw pattern and password are NEVER stored.
//    Username and PasswordHash are null.
//  • Password users — a traditional username + password account. The _id is
//    random, Username holds the normalized (lowercased) login name and
//    PasswordHash a bcrypt hash of the password.
//
// TOTP is the optional (recommended) second factor for both kinds; backup
// codes are single-use bcrypt hashes. See UserService.
public class User
{
    [BsonId] public string Id { get; set; } = "";   // pattern: HMAC-SHA256(pattern|password) hex; password: random hex
    public string Label { get; set; } = "";          // human-facing name, not a credential
    [BsonIgnoreIfNull] public string? Username { get; set; }      // password users only, normalized lowercase
    [BsonIgnoreIfNull] public string? PasswordHash { get; set; }  // password users only, bcrypt
    public string? TotpSecret { get; set; }
    public bool TotpEnabled { get; set; }
    public List<string> BackupCodeHashes { get; set; } = new();
    public DateTime CreatedAt { get; set; }
    public DateTime? LastLoginAt { get; set; }

    public bool IsPasswordUser => Username is not null;
}
