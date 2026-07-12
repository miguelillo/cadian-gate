using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace PatternAuth;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the pattern-auth services (user store, lockout, backup codes,
    /// access log) plus JWT bearer authentication that reads the token from the
    /// configured cookie. Call <c>MapPatternAuthEndpoints()</c> /
    /// <c>MapPatternAuthUsersEndpoints()</c> on the app to expose the endpoints.
    /// </summary>
    public static IServiceCollection AddPatternAuth(this IServiceCollection services,
        IConfiguration config, Action<PatternAuthOptions>? configure = null)
    {
        var opts = new PatternAuthOptions();
        configure?.Invoke(opts);
        services.AddSingleton(opts);

        var jwtSecret = config[opts.JwtSecretKey]
            ?? throw new InvalidOperationException($"{opts.JwtSecretKey} configuration value is required");
        var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret));

        services.AddSingleton(sp => new PatternAuthMongo(opts.MongoDatabaseFactory?.Invoke(sp)));
        services.AddSingleton<IpLockoutService>();
        services.AddSingleton<BackupCodeService>();
        services.AddSingleton<AccessLogService>();
        services.AddSingleton<UserService>();

        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(o =>
            {
                o.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = signingKey,
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ClockSkew = TimeSpan.Zero,
                };
                o.Events = new JwtBearerEvents
                {
                    OnMessageReceived = ctx =>
                    {
                        ctx.Token = ctx.Request.Cookies[opts.CookieName];
                        return Task.CompletedTask;
                    }
                };
            });

        services.AddAuthorization();
        return services;
    }
}
