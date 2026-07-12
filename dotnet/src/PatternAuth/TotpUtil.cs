using System.Security.Cryptography;
using OtpNet;

namespace PatternAuth;

// Shared TOTP helpers used by both the env break-glass login and per-user 2FA.
public static class TotpUtil
{
    public static bool Validate(string? secret, string? code)
    {
        if (string.IsNullOrWhiteSpace(secret) || string.IsNullOrWhiteSpace(code) || code.Length != 6) return false;
        try
        {
            var key = Base32Encoding.ToBytes(secret);
            var totp = new Totp(key);
            return totp.VerifyTotp(code, out _, new VerificationWindow(previous: 1, future: 1));
        }
        catch { return false; }
    }

    // Fresh 160-bit base32 secret for authenticator enrollment.
    public static string GenerateSecret()
    {
        var bytes = new byte[20];
        RandomNumberGenerator.Fill(bytes);
        return Base32Encoding.ToString(bytes);
    }
}
