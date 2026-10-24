// Backend address migration tests. Run in both builds:
//   dotnet test ... -c Release                              -> default build: never migrates
//   dotnet test ... -c Release -p:AgentBuildProfile=server  -> server profile: compiled https address wins
// ServiceMode wiring (the BlockedConfig fallback) is not unit-reachable; these cover the decision
// and the persisted result that ServiceMode consumes.
using Cerberus.Agent.App.Control;
using Cerberus.Agent.Core;
using Cerberus.Agent.Security;

namespace Cerberus.Agent.Core.Tests;

public sealed class ServerBackendMigrationTests
{
    private const string Stored = "https://old-collector.example.test:8443";
    private const string Compiled = "https://new-collector.example.test:8443";

    private static readonly AgentIdentity Identity = new("agent-id-1", "tenant-id-1");

    private static string NewDir()
        => Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"));

    private static async Task<DpapiSecretStore> SeedAsync(string dir)
    {
        var store = new DpapiSecretStore(SecretStoreScope.User, dir);
        await store.SaveAsync(Identity, "refresh-1", "key-pem-1", Stored, "https://tailnet.example.test", "ts-key-1", CancellationToken.None);
        return store;
    }

#if CERBERUS_SERVER_PROFILE
    [Fact]
    public async Task ServerProfile_MigratesCompiledAddressAndKeepsCredentials()
    {
        var store = await SeedAsync(NewDir());
        var current = await store.LoadAsync(CancellationToken.None);

        Assert.True(ServerBackendMigration.ShouldMigrate(current.BackendUrl, Compiled, null));
        var migrated = await ServerBackendMigration.MigrateAsync(store, current, Compiled, CancellationToken.None);

        Assert.Equal(Compiled, migrated);
        var after = await store.LoadAsync(CancellationToken.None);
        Assert.Equal(Compiled, after.BackendUrl);
        Assert.Equal(Identity, after.Identity);
        Assert.Equal("refresh-1", after.RefreshToken);
        Assert.Equal("key-pem-1", after.PrivateKeyPem);
        Assert.Equal("https://tailnet.example.test", after.TailscaleLoginServer);
        Assert.Equal("ts-key-1", after.TailscaleAuthkey);
        Assert.False(ServerBackendMigration.ShouldMigrate(after.BackendUrl, Compiled, null));
    }

    [Fact]
    public void ServerProfile_AcceptsTrailingSlashAndSameEndpointIsNoMigration()
    {
        Assert.False(ServerBackendMigration.ShouldMigrate(Stored, Stored + "/", null));
        Assert.True(ServerBackendMigration.ShouldMigrate("http://old.example.test", Compiled + "/", null));
    }

    [Theory]
    [InlineData("")]
    [InlineData("https://new-collector.example.test:8443")]
    [InlineData("https://other.example.test")]
    public void ServerProfile_EnvironmentOverrideNeverMigrates(string env)
        // Any non-null environment value (matching the compiled address or not) disables migration.
        => Assert.False(ServerBackendMigration.ShouldMigrate(Stored, Compiled, env));

    [Theory]
    [InlineData("http://new-collector.example.test:8080")]
    [InlineData("https://user:pw@new-collector.example.test")]
    [InlineData("https://new-collector.example.test/?x=1")]
    [InlineData("https://new-collector.example.test/#f")]
    [InlineData("ftp://new-collector.example.test")]
    [InlineData("not a url")]
    [InlineData("")]
    public void ServerProfile_RejectsNonHttpsOrDecoratedTargets(string target)
        => Assert.False(ServerBackendMigration.ShouldMigrate(Stored, target, null));

    [Fact]
    public async Task ServerProfile_InterruptedWriteLeavesPreviousRegistrationReadable()
    {
        var dir = NewDir();
        var store = await SeedAsync(dir);
        var current = await store.LoadAsync(CancellationToken.None);

        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => ServerBackendMigration.MigrateAsync(store, current, Compiled, cts.Token));

        var after = await store.LoadAsync(CancellationToken.None);
        Assert.Equal(Stored, after.BackendUrl);
        Assert.Equal(Identity, after.Identity);
        Assert.Equal("refresh-1", after.RefreshToken);
        Assert.Equal("key-pem-1", after.PrivateKeyPem);

        // A temp file left by a crash mid-write does not disturb the next open or a retry.
        await File.WriteAllBytesAsync(Path.Combine(dir, "secrets.json." + Guid.NewGuid().ToString("N") + ".tmp"), new byte[] { 1, 2, 3 });
        var reopened = await new DpapiSecretStore(SecretStoreScope.User, dir).LoadAsync(CancellationToken.None);
        Assert.Equal(Stored, reopened.BackendUrl);
        await ServerBackendMigration.MigrateAsync(store, reopened, Compiled, CancellationToken.None);
        Assert.Equal(Compiled, (await store.LoadAsync(CancellationToken.None)).BackendUrl);
    }
#else
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void DefaultBuild_NeverMigrates_SoMismatchStaysBlockedConfig(string? env)
    {
        // ShouldMigrate=false leaves ServiceMode on its existing backend_environment_mismatch path.
        Assert.False(ServerBackendMigration.ShouldMigrate(Stored, Compiled, env));
        Assert.False(ServerBackendMigration.ShouldMigrate("http://old.example.test", Compiled, null));
    }
#endif
}
