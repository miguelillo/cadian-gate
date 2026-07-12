using Microsoft.Extensions.Configuration;
using PatternAuth;
using Xunit;

namespace PatternAuth.Tests;

public class UserServiceTests
{
    private static UserService Make(string key = "unit-test-key")
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["HOMELAB_USER_ID_KEY"] = key })
            .Build();
        return new UserService(config, new PatternAuthOptions(), new PatternAuthMongo(null));
    }

    [Theory]
    [InlineData("0-5-12-35", "0-5-12-35")]     // valid 6×6, order preserved
    [InlineData(" 1 - 2 - 3 - 4 ", "1-2-3-4")]  // trims
    public void NormalizePattern_accepts_valid(string input, string expected)
    {
        Assert.Equal(expected, UserService.NormalizePattern(input));
    }

    [Theory]
    [InlineData("0-1-2")]        // too short (min 4)
    [InlineData("0-1-0-2")]      // repeated node
    [InlineData("0-1-2-36")]     // 36 is off the 6×6 grid (valid 0..35)
    [InlineData("0-1-2--3")]     // empty segment removed → collapses to a valid pattern
    [InlineData("a-b-c-d")]      // non-numeric
    [InlineData("")]             // empty
    public void NormalizePattern_rejects_invalid(string input)
    {
        // Note: "0-1-2--3" collapses to 0,1,2,3 which IS valid — assert that instead.
        if (input == "0-1-2--3") { Assert.Equal("0-1-2-3", UserService.NormalizePattern(input)); return; }
        Assert.Null(UserService.NormalizePattern(input));
    }

    [Fact]
    public void NormalizePattern_respects_custom_grid_size()
    {
        Assert.Null(UserService.NormalizePattern("0-1-2-9", gridSize: 3));   // 9 off a 3×3 grid
        Assert.Equal("0-1-2-8", UserService.NormalizePattern("0-1-2-8", gridSize: 3));
    }

    [Fact]
    public void ComputeId_is_deterministic_and_credential_sensitive()
    {
        var svc = Make();
        var a = svc.ComputeId("0-5-12-35", "hunter2");
        var again = svc.ComputeId("0-5-12-35", "hunter2");
        var diffPass = svc.ComputeId("0-5-12-35", "hunter3");
        var diffPattern = svc.ComputeId("0-5-12-34", "hunter2");

        Assert.NotNull(a);
        Assert.Equal(a, again);                 // same inputs → same id
        Assert.NotEqual(a, diffPass);           // password matters
        Assert.NotEqual(a, diffPattern);        // pattern matters
        Assert.Equal(64, a!.Length);            // SHA-256 hex
    }

    [Fact]
    public void ComputeId_depends_on_the_server_key()
    {
        var id1 = Make("key-one").ComputeId("0-1-2-3", "pw");
        var id2 = Make("key-two").ComputeId("0-1-2-3", "pw");
        Assert.NotEqual(id1, id2);              // keyed HMAC, not a plain hash
    }

    [Fact]
    public void ComputeId_returns_null_for_invalid_pattern()
    {
        Assert.Null(Make().ComputeId("0-1", "pw"));
    }

    [Fact]
    public void Count_and_availability_are_zero_without_mongo()
    {
        var svc = Make();
        Assert.Equal(0, svc.Count());
        Assert.False(svc.Available);       // no collection ⇒ store unavailable
    }
}
