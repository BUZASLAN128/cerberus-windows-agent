using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
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
    [InlineData("O:SYD:P(A;;FA;;;SY)(A;;RC;;;BA)", false)]
    public void FileDescriptorRequiresSystemOwnerAndOnlyOneExplicitSystemAce(string descriptor, bool accepted)
    {
        var security = new FileSecurity();
        security.SetSecurityDescriptorSddlForm(descriptor);
        var cache = new AgentAccessTokenCache(CacheDirectory, production: true);
        Assert.Equal(accepted, cache.HasExpectedAcl(security));
    }

    [Theory]
    [InlineData("O:SYD:P(A;;FA;;;SY)(A;;RC;;;BA)", true)]
    [InlineData("O:SYD:P(A;;FA;;;SY)", false)]
    [InlineData("O:BAD:P(A;;FA;;;SY)(A;;RC;;;BA)", false)]
    [InlineData("O:SYD:P(A;;FA;;;SY)(A;;GR;;;BA)", false)]
    [InlineData("O:SYD:P(A;OICI;FA;;;SY)(A;;RC;;;BA)", false)]
    [InlineData("O:SYD:P(A;;FA;;;SY)(A;OICI;RC;;;BA)", false)]
    [InlineData("O:SYD:P(A;;FA;;;SY)(A;;RC;;;BA)(A;;RC;;;BU)", false)]
    public void DirectoryDescriptorAllowsAdministratorsReadControlOnly(string descriptor, bool accepted)
    {
        var security = new DirectorySecurity();
        security.SetSecurityDescriptorSddlForm(descriptor);
        var cache = new AgentAccessTokenCache(CacheDirectory, production: true);
        Assert.Equal(accepted, cache.HasExpectedAcl(security));
    }

    [Fact]
    public Task IsolatedAuthority_UsesNativeAclsAndMachineDpapi()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return AssertProtectedRoundTripAsync(new AgentAccessTokenCache(CacheDirectory, identity.User!));
    }

    [LocalSystemFact]
    public Task LocalSystem_UsesProductionDirectoryAndFileAcls()
        => AssertProtectedRoundTripAsync(new AgentAccessTokenCache(CacheDirectory, production: true));

    [Fact]
    public async Task ForeignAce_Absent()
    {
        Directory.CreateDirectory(_root);
        using var identity = WindowsIdentity.GetCurrent();
        var owner = identity.User!;
        var cache = new AgentAccessTokenCache(CacheDirectory, owner);
        await WriteAsync(cache);
        var security = new FileSecurity();
        security.SetSecurityDescriptorSddlForm($"D:P(A;;FA;;;{owner.Value})(A;;RC;;;BA)", AccessControlSections.Access);
        new FileInfo(CachePath).SetAccessControl(security);

        Assert.Null(await cache.ReadAsync(Identity, Backend, KeyFingerprint, 4, Now, default));
        Assert.False(File.Exists(CachePath));
    }

    [Fact]
    public async Task SquattedDirectoryOrReparsePoint_CacheDisabled_NoWrite()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var owner = identity.User!;
        var cache = new AgentAccessTokenCache(CacheDirectory, owner);
        Directory.CreateDirectory(CacheDirectory);
        var security = new DirectorySecurity();
        security.SetSecurityDescriptorSddlForm($"D:P(A;;FA;;;{owner.Value})(A;;GR;;;BA)", AccessControlSections.Access);
        new DirectoryInfo(CacheDirectory).SetAccessControl(security);

        await WriteAsync(cache);
        Assert.Empty(Directory.EnumerateFileSystemEntries(CacheDirectory));
        Directory.Delete(CacheDirectory);
        await WriteAsync(cache);
        Assert.False(Directory.Exists(CacheDirectory));

        var target = Directory.CreateDirectory(Path.Combine(_root, "other-directory"));
        // A directory junction needs no elevated Windows token or developer-mode setting.
        using var mklink = Process.Start(new ProcessStartInfo("cmd.exe")
        {
            ArgumentList = { "/c", "mklink", "/J", CacheDirectory, target.FullName },
            UseShellExecute = false,
            CreateNoWindow = true,
        })!;
        await mklink.WaitForExitAsync();
        Assert.Equal(0, mklink.ExitCode);
        try
        {
            Assert.True(File.GetAttributes(CacheDirectory).HasFlag(FileAttributes.ReparsePoint));
            var fresh = new AgentAccessTokenCache(CacheDirectory, owner);
            await WriteAsync(fresh);
            Assert.Empty(target.EnumerateFileSystemInfos());
            Assert.True(File.GetAttributes(CacheDirectory).HasFlag(FileAttributes.ReparsePoint));
        }
        finally
        {
            Directory.Delete(CacheDirectory);
        }
    }

    private async Task AssertProtectedRoundTripAsync(AgentAccessTokenCache cache)
    {
        Directory.CreateDirectory(_root);
        await WriteAsync(cache);

        Assert.True(cache.HasExpectedAcl(new DirectoryInfo(CacheDirectory).GetAccessControl()));
        Assert.True(cache.HasExpectedAcl(new FileInfo(CachePath).GetAccessControl()));
        var stored = await File.ReadAllBytesAsync(CachePath);
        Assert.DoesNotContain(Token, System.Text.Encoding.UTF8.GetString(stored));
        Assert.Equal(Token, (await cache.ReadAsync(Identity, Backend, KeyFingerprint, 4, Now, default))?.Token);
    }

    [Fact]
    public async Task StopCleanupDeletesOnlyTheExactDisposableCacheFiles()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var cache = new AgentAccessTokenCache(CacheDirectory, identity.User!);
        Directory.CreateDirectory(_root);
        await WriteAsync(cache);
        await cache.WriteAsync(Identity with { Product = AgentProducts.Secondary }, Backend, KeyFingerprint, 4,
            Token, Now.AddMinutes(15), Now, default);
        var secondary = Path.Combine(CacheDirectory, "secondary-access-token.v1.dpapi");
        Assert.True(File.Exists(CachePath));
        Assert.True(File.Exists(secondary));

        var unrelated = new[] { Path.Combine(CacheDirectory, "access-token.v1.dpapi.backup"),
            Path.Combine(CacheDirectory, "enrollment.json"), Path.Combine(_root, "secrets.json") };
        foreach (var path in unrelated) File.WriteAllText(path, "fixture sentinel");
        var before = new DirectoryInfo(CacheDirectory).GetAccessControl().GetSecurityDescriptorBinaryForm();

        cache.RemoveExactCacheFiles();
        cache.RemoveExactCacheFiles();
        Assert.False(File.Exists(CachePath));
        Assert.False(File.Exists(secondary));
        Assert.All(unrelated, path => Assert.Equal("fixture sentinel", File.ReadAllText(path)));
        Assert.Equal(before, new DirectoryInfo(CacheDirectory).GetAccessControl().GetSecurityDescriptorBinaryForm());
    }

    [Theory]
    [InlineData("foreign-directory")]
    [InlineData("entry-directory")]
    [InlineData("entry-reparse")]
    [InlineData("entry-hardlink")]
    public async Task StopCleanupRefusesUntrustedDirectoryAndAmbiguousEntries(string kind)
    {
        using var identity = WindowsIdentity.GetCurrent();
        var cache = new AgentAccessTokenCache(CacheDirectory, identity.User!);
        Directory.CreateDirectory(_root);
        if (kind == "foreign-directory")
        {
            Directory.CreateDirectory(CacheDirectory);
            File.WriteAllText(CachePath, "foreign entry");
            Assert.Throws<UnauthorizedAccessException>(cache.RemoveExactCacheFiles);
            Assert.Equal("foreign entry", File.ReadAllText(CachePath));
            Assert.Throws<UnauthorizedAccessException>(
                new AgentAccessTokenCache(CacheDirectory, production: false).RemoveExactCacheFiles);
            return;
        }

        await WriteAsync(cache);
        File.Delete(CachePath);
        var target = Path.Combine(_root, "target");
        if (kind == "entry-directory")
        {
            Directory.CreateDirectory(CachePath);
            target = CachePath;
        }
        else
        {
            var junction = kind == "entry-reparse";
            if (junction) Directory.CreateDirectory(target);
            else File.WriteAllText(target, "target");
            using var mklink = Process.Start(new ProcessStartInfo("cmd.exe")
            {
                ArgumentList = { "/d", "/c", "mklink", junction ? "/j" : "/h", CachePath, target },
                UseShellExecute = false, CreateNoWindow = true,
            })!;
            await mklink.WaitForExitAsync();
            Assert.Equal(0, mklink.ExitCode);
        }
        Assert.Throws<InvalidOperationException>(cache.RemoveExactCacheFiles);
        if (kind == "entry-hardlink") Assert.Equal("target", File.ReadAllText(target));
        else Assert.True(Directory.Exists(target));
        Assert.True(File.Exists(CachePath) || Directory.Exists(CachePath));
        if (kind == "entry-reparse") Directory.Delete(CachePath);
    }

    private static Task WriteAsync(AgentAccessTokenCache cache)
        => cache.WriteAsync(Identity, Backend, KeyFingerprint, 4, Token, Now.AddMinutes(15), Now, default);

    private sealed class LocalSystemFactAttribute : FactAttribute
    {
        public LocalSystemFactAttribute()
        {
            if (!AgentUpdateSecurity.IsLocalSystem()) Skip = "Requires LocalSystem to verify the production ownership and cache I/O path.";
        }
    }
}
