using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace PatternAuth;

public record LoginRequest(string Password, string? TotpCode, string? Pattern = null, LoginFingerprint? Fingerprint = null);

// Client fingerprint sent with a login attempt, stored on the access-events
// document. All optional and untrusted — lengths are capped when persisted
// (see AccessLogService).
public record LoginFingerprint(
    string? Ip, string? Isp, string? City, string? Country, int? LatencyMs,
    string? Os, string? Browser, string? Resolution, string? Tz, string? Lang,
    string? Cores, int? Mem, string? Touch, string? Cookies, string? UserAgent);

public static class PatternAuthEndpoints
{
    public static IEndpointRouteBuilder MapPatternAuthEndpoints(this IEndpointRouteBuilder app)
    {
        var opts = app.ServiceProvider.GetRequiredService<PatternAuthOptions>();
        var auth = app.MapGroup(opts.BasePath);

        auth.MapGet("/me", (BackupCodeService backupCodes) =>
            Results.Ok(new { ok = true, backupCodesRemaining = backupCodes.Remaining() }))
            .RequireAuthorization();

        auth.MapGet("/config", (IConfiguration config, UserService users) =>
        {
            var totpRequired = config[opts.TotpEnabledKey] == "true" &&
                               !string.IsNullOrWhiteSpace(config[opts.TotpSecretKey]);
            var breakglassAvailable = config[opts.BreakglassEnabledKey] == "true" || users.Count() == 0;
            return Results.Ok(new { totpRequired, breakglassAvailable });
        });

        auth.MapGet("/setup-totp", (IConfiguration config) =>
        {
            var secret = config[opts.TotpSecretKey];
            if (string.IsNullOrWhiteSpace(secret))
                return Results.Content($"<h1>{opts.TotpSecretKey} not configured</h1>", "text/html");

            var account = Uri.EscapeDataString(opts.TotpAccountName);
            var issuer = Uri.EscapeDataString(opts.TotpIssuer);
            var uri = $"otpauth://totp/{account}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30";
            var html = $$"""
                <!DOCTYPE html>
                <html>
                <head>
                  <meta charset="utf-8">
                  <meta name="viewport" content="width=device-width,initial-scale=1">
                  <title>TOTP Setup</title>
                  <style>
                    body { font-family: monospace; background: #111; color: #eee; display: flex; flex-direction: column; align-items: center; padding: 2rem; gap: 1.5rem; }
                    h2 { margin: 0; }
                    #qr { background: white; padding: 12px; border-radius: 8px; }
                    .secret { background: #222; padding: .75rem 1rem; border-radius: 6px; letter-spacing: .1em; font-size: 1.1rem; word-break: break-all; }
                    p { margin: 0; color: #aaa; text-align: center; max-width: 320px; }
                  </style>
                </head>
                <body>
                  <h2>Scan with Google Authenticator</h2>
                  <div id="qr"></div>
                  <p>Or enter the key manually:</p>
                  <div class="secret">{{secret}}</div>
                  <p style="font-size:.85rem">Open Google Authenticator &rarr; + &rarr; Scan QR code, then point at the code above.</p>
                  <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
                  <script>new QRCode(document.getElementById("qr"), { text: "{{uri}}", width: 256, height: 256 });</script>
                </body>
                </html>
                """;
            return Results.Content(html, "text/html");
        }).RequireAuthorization();

        var login = auth.MapPost("/login", (HttpContext ctx, LoginRequest body, IConfiguration config,
            IpLockoutService lockout, BackupCodeService backupCodes, AccessLogService access, UserService users) =>
        {
            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var (locked, until, _) = lockout.Check(ip);

            if (locked)
            {
                access.Record(ip, "locked", fp: body.Fingerprint);
                var secsLeft = (int)(until!.Value - DateTimeOffset.UtcNow).TotalSeconds;
                return Results.Json(new
                {
                    error = $"Too many attempts. Try again in {secsLeft / 60}:{secsLeft % 60:D2}.",
                    lockedUntilUtc = until!.Value,
                    secsLeft,
                }, statusCode: 423);
            }

            bool ok, usedTotp = false, usedBackupCode = false;
            string subject = "owner";
            string invalidMsg = "Invalid credentials";

            if (!string.IsNullOrWhiteSpace(body.Pattern))
            {
                // Pattern-auth flow: pattern + password identify the user in one
                // keyed-HMAC lookup; TOTP (if enrolled) is the second factor.
                var user = users.Identify(body.Pattern, body.Password);
                if (user is null)
                {
                    ok = false;
                    invalidMsg = "Pattern or password not recognized.";
                }
                else if (user.TotpEnabled)
                {
                    if (TotpUtil.Validate(user.TotpSecret, body.TotpCode)) { ok = true; usedTotp = true; }
                    else if (users.ConsumeBackupCode(user, body.TotpCode)) { ok = true; usedBackupCode = true; }
                    else { ok = false; invalidMsg = "Authenticator code incorrect."; }
                }
                else ok = true;

                if (ok) { subject = "user:" + user!.Label; users.RecordLogin(user.Id); }
            }
            else
            {
                // Env break-glass flow — single-operator credentials. Disabled
                // once at least one pattern user exists (unless forced on), but
                // always allowed while there are no users so the first one can
                // be bootstrapped.
                var breakglassAllowed = config[opts.BreakglassEnabledKey] == "true" || users.Count() == 0;
                if (!breakglassAllowed)
                {
                    access.Record(ip, "invalid", fp: body.Fingerprint);
                    return Results.Json(new { error = "Password sign-in is disabled — use your unlock pattern." }, statusCode: 401);
                }

                var hash = config[opts.PasswordHashKey];
                var passwordOk = !string.IsNullOrWhiteSpace(hash) && BCrypt.Net.BCrypt.Verify(body.Password, hash);

                var totpEnabled = config[opts.TotpEnabledKey] == "true" &&
                                  !string.IsNullOrWhiteSpace(config[opts.TotpSecretKey]);

                bool totpOk;
                if (!totpEnabled) totpOk = true;
                else if (TotpUtil.Validate(config[opts.TotpSecretKey], body.TotpCode)) { totpOk = true; usedTotp = true; }
                else if (passwordOk && backupCodes.TryConsume(body.TotpCode)) { totpOk = true; usedBackupCode = true; }
                else totpOk = false;

                ok = passwordOk && totpOk;
            }

            if (!ok)
            {
                var (nowLocked, lockUntil) = lockout.RecordFailure(ip);
                if (nowLocked)
                {
                    access.Record(ip, "locked", fp: body.Fingerprint);
                    var secsLeft = (int)(lockUntil!.Value - DateTimeOffset.UtcNow).TotalSeconds;
                    return Results.Json(new
                    {
                        error = $"Too many failed attempts. Locked for {(int)opts.LockoutDuration.TotalMinutes} minutes.",
                        lockedUntilUtc = lockUntil!.Value,
                        secsLeft,
                    }, statusCode: 423);
                }
                var (_, _, remaining) = lockout.Check(ip);
                access.Record(ip, "invalid", attemptsRemaining: remaining, fp: body.Fingerprint);
                return Results.Json(new { error = invalidMsg, attemptsRemaining = remaining }, statusCode: 401);
            }

            lockout.RecordSuccess(ip);
            access.Record(ip, "success", usedTotp, usedBackupCode, fp: body.Fingerprint);

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config[opts.JwtSecretKey]!));
            var token = new JwtSecurityToken(
                expires: DateTime.UtcNow.Add(opts.TokenLifetime),
                signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256),
                claims: [new Claim("sub", subject)]
            );

            ctx.Response.Cookies.Append(opts.CookieName, new JwtSecurityTokenHandler().WriteToken(token), new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = DateTimeOffset.UtcNow.Add(opts.TokenLifetime),
                Path = "/",
            });

            return Results.Ok(new { ok = true, backupCodesRemaining = backupCodes.Remaining() });
        });
        if (opts.LoginRateLimitPolicy is not null)
            login.RequireRateLimiting(opts.LoginRateLimitPolicy);

        auth.MapPost("/logout", (HttpContext ctx) =>
        {
            ctx.Response.Cookies.Delete(opts.CookieName, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Path = "/",
            });
            return Results.Ok(new { ok = true });
        }).RequireAuthorization();

        return app;
    }
}
