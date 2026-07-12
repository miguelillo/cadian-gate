using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace PatternAuth;

public record UserCreateRequest(
    string Label,
    string Pattern,
    string Password,
    string? TotpSecret,
    string? TotpCode,
    List<string>? BackupCodes);

// Authenticated management of pattern-auth users. All endpoints require a valid
// session (via pattern or break-glass). Secrets are never read back.
public static class PatternAuthUsersEndpoints
{
    public static IEndpointRouteBuilder MapPatternAuthUsersEndpoints(this IEndpointRouteBuilder app)
    {
        var opts = app.ServiceProvider.GetRequiredService<PatternAuthOptions>();
        var users = app.MapGroup(opts.UsersBasePath).RequireAuthorization();

        users.MapGet("", (UserService svc) => Results.Ok(svc.List()));

        // Fresh TOTP secret + otpauth URI for authenticator enrollment when
        // creating a user. The UI renders the URI as a QR and posts back a code.
        users.MapGet("/new-totp-secret", (string? label) =>
        {
            var secret = TotpUtil.GenerateSecret();
            var account = Uri.EscapeDataString(string.IsNullOrWhiteSpace(label) ? opts.TotpAccountName : label!);
            var issuer = Uri.EscapeDataString(opts.TotpIssuer);
            var uri = $"otpauth://totp/{account}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30";
            return Results.Ok(new { secret, otpauthUri = uri });
        });

        users.MapPost("", (UserCreateRequest body, UserService svc) =>
        {
            // If a TOTP secret is supplied, require a matching code so we only
            // enable 2FA once the authenticator is proven to be set up.
            var totpEnabled = false;
            if (!string.IsNullOrWhiteSpace(body.TotpSecret))
            {
                if (!TotpUtil.Validate(body.TotpSecret, body.TotpCode))
                    return Results.Json(new { ok = false, error = "The TOTP code did not verify — re-scan and try again." }, statusCode: 400);
                totpEnabled = true;
            }

            var backupHashes = body.BackupCodes?
                .Where(c => !string.IsNullOrWhiteSpace(c))
                .Select(c => BCrypt.Net.BCrypt.HashPassword(c.Trim().ToUpperInvariant(), workFactor: 12))
                .ToList();

            var (ok, error, id) = svc.Create(body.Label, body.Pattern, body.Password, body.TotpSecret, totpEnabled, backupHashes);
            return ok
                ? Results.Ok(new { ok = true, id, label = body.Label.Trim() })
                : Results.Json(new { ok = false, error }, statusCode: 400);
        });

        users.MapDelete("/{id}", (string id, UserService svc) =>
            svc.Delete(id)
                ? Results.Ok(new { ok = true })
                : Results.Json(new { ok = false, error = "User not found." }, statusCode: 404));

        return app;
    }
}
