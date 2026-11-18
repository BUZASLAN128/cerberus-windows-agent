using System.Security.AccessControl;
using Cerberus.Agent.Security;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentAccessTokenCacheTests : IDisposable
{
    private const string Backend = "https://backend.example";
    private const string KeyFingerprint = "fixture-key-fingerprint";
    private const string Token = "fixture-access-token";
    private static readonly DateTimeOffset Now = new(2026, 11, 18, 12, 0, 0, TimeSpan.Zero);
    private static readonly AgentIdentity Identity = new("agent", "tenant");
    private readonly string _root = Path.Combine(Path.GetTempPath(), "cerberus-cache-" + Guid.NewGuid().ToString("N"));
    private string CacheDirectory => Path.Combine(_root, "token-cache");
    private string CachePath => Path.Combine(CacheDirectory, "access-token.v1.dpapi");

    public void Dispose()
    {
        if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true);
    }

    [Fact]
    public async Task RoundTrip_SameBinding_Hit()
    {
        var cache = new AgentAccessTokenCache(CacheDirectory, production: false);
        await WriteAsync(cache);

        var reopened = new AgentAccessTokenCache(CacheDirectory, production: false);
        var cached = await reopened.ReadAsync(Identity, "https://BACKEND.example:443/", KeyFingerprint, 4, Now, default);

        Assert.NotNull(cached);
        Assert.Equal(Token, cached.Token);
        Assert.Equal(Now.AddMinutes(15), cached.ExpiresAtUtc);
    }

    [Theory]
    [InlineData("agent")]
    [InlineData("tenant")]
    [InlineData("product")]
    [InlineData("backend")]
    [InlineData("key")]
    [InlineData("generation")]
    public async Task MismatchAgentTenantProductBackendKeyGeneration_AbsentAndDeleted(string changed)
    {
        var cache = new AgentAccessTokenCache(CacheDirectory, production: false);
        await WriteAsync(cache);
        var identity = changed switch
        {
            "agent" => Identity with { AgentId = "other-agent" },
            "tenant" => Identity with { TenantId = "other-tenant" },
            "product" => Identity with { Product = AgentProducts.Secondary },
            _ => Identity,
        };
        var path = CachePath;
        if (changed == "product")
        {
            path = Path.Combine(CacheDirectory, "secondary-access-token.v1.dpapi");
            File.Move(CachePath, path);
        }

        Assert.Null(await cache.ReadAsync(identity, changed == "backend" ? "https://other.example" : Backend,
            changed == "key" ? "other-key" : KeyFingerprint, changed == "generation" ? 5 : 4, Now, default));
        Assert.False(File.Exists(path));
    }

    [Theory]
    [InlineData(0, 86401)]
    [InlineData(121, 900)]
    [InlineData(0, 90)]
    public async Task TtlCeiling_ClockBack_NearExpiry_Absent(int writtenSeconds, int expirySeconds)
    {
        var cache = new AgentAccessTokenCache(CacheDirectory, production: false);
        await cache.WriteAsync(Identity, Backend, KeyFingerprint, 4, Token, Now.AddSeconds(expirySeconds),
            Now.AddSeconds(writtenSeconds), default);

        Assert.Null(await cache.ReadAsync(Identity, Backend, KeyFingerprint, 4, Now, default));
        Assert.False(File.Exists(CachePath));
    }

    [Theory]
    [InlineData(4)]
    [InlineData(16385)]
    public async Task Oversize_Corrupt_Absent(int bytes)
    {
        var cache = new AgentAccessTokenCache(CacheDirectory, production: false);
        Directory.CreateDirectory(CacheDirectory);
        await File.WriteAllBytesAsync(CachePath, new byte[bytes]);

        Assert.Null(await cache.ReadAsync(Identity, Backend, KeyFingerprint, 4, Now, default));
        Assert.False(File.Exists(CachePath));
    }

    [Theory]
    [InlineData("O:SYD:P(A;;FA;;;SY)", true)]
    [InlineData("O:BAD:P(A;;FA;;;SY)", false)]
    [InlineData("O:SYD:P(A;;FA;;;SY)(A;;GR;;;BU)", false)]
    [InlineData("O:SYD:(A;;FA;;;SY)", false)]
    [InlineData("O:SYD:P(A;OICI;FA;;;SY)", false)]
    public void DescriptorRequiresSystemOwnerAndOnlyOneExplicitSystemAce(string descriptor, bool accepted)
    {
        var security = new DirectorySecurity();
        security.SetSecurityDescriptorSddlForm(descriptor);
        Assert.Equal(accepted, AgentAccessTokenCache.HasSystemOnlyAcl(security));
    }

    [LocalSystemFact]
    public async Task Directory_HasNoUsersAce_AndFileIsDpapiProtected()
    {
        Directory.CreateDirectory(_root);
        var cache = new AgentAccessTokenCache(CacheDirectory, production: true);
        await WriteAsync(cache);

        Assert.True(AgentAccessTokenCache.HasSystemOnlyAcl(new DirectoryInfo(CacheDirectory).GetAccessControl()));
        Assert.True(AgentAccessTokenCache.HasSystemOnlyAcl(new FileInfo(CachePath).GetAccessControl()));
        var stored = await File.ReadAllBytesAsync(CachePath);
        Assert.DoesNotContain(Token, System.Text.Encoding.UTF8.GetString(stored));
        Assert.Equal(Token, (await cache.ReadAsync(Identity, Backend, KeyFingerprint, 4, Now, default))?.Token);
    }

    [LocalSystemFact]
    public async Task ForeignAce_Absent()
    {
        Directory.CreateDirectory(_root);
        var cache = new AgentAccessTokenCache(CacheDirectory, production: true);
        await WriteAsync(cache);
        var security = new FileSecurity();
        security.SetSecurityDescriptorSddlForm("O:SYD:P(A;;FA;;;SY)(A;;GR;;;BU)");
        new FileInfo(CachePath).SetAccessControl(security);

        Assert.Null(await cache.ReadAsync(Identity, Backend, KeyFingerprint, 4, Now, default));
        Assert.False(File.Exists(CachePath));
    }

    [LocalSystemFact]
    public async Task SquattedDirectoryOrReparsePoint_CacheDisabled_NoWrite()
    {
        var cache = new AgentAccessTokenCache(CacheDirectory, production: true);
        Directory.CreateDirectory(CacheDirectory);
        var security = new DirectorySecurity();
        security.SetSecurityDescriptorSddlForm("O:SYD:P(A;;FA;;;SY)(A;;GR;;;BU)");
        new DirectoryInfo(CacheDirectory).SetAccessControl(security);

        await WriteAsync(cache);
        Assert.Empty(Directory.EnumerateFileSystemEntries(CacheDirectory));
        Directory.Delete(CacheDirectory);
        await WriteAsync(cache);
        Assert.False(Directory.Exists(CacheDirectory));

        var target = Directory.CreateDirectory(Path.Combine(_root, "other-directory"));
        var link = Directory.CreateSymbolicLink(CacheDirectory, target.FullName);
        try
        {
            var fresh = new AgentAccessTokenCache(CacheDirectory, production: true);
            await WriteAsync(fresh);
            Assert.Empty(target.EnumerateFileSystemInfos());
            Assert.True(link.Attributes.HasFlag(FileAttributes.ReparsePoint));
        }
        finally
        {
            Directory.Delete(CacheDirectory);
        }
    }

    private static Task WriteAsync(AgentAccessTokenCache cache)
        => cache.WriteAsync(Identity, Backend, KeyFingerprint, 4, Token, Now.AddMinutes(15), Now, default);

    private sealed class LocalSystemFactAttribute : FactAttribute
    {
        public LocalSystemFactAttribute()
        {
            if (!AgentUpdateSecurity.IsLocalSystem()) Skip = "Requires a LocalSystem test process to access the SYSTEM-only cache.";
        }
    }
}
