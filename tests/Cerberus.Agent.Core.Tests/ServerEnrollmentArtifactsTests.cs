#if CERBERUS_SERVER_PROFILE
using Cerberus.Agent.App;

namespace Cerberus.Agent.Core.Tests;

// Temp folder through the Seams parameter; the real %ProgramData% data folder and DPAPI stores are never touched.
public sealed class ServerEnrollmentArtifactsTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "cerberus-artifacts-" + Guid.NewGuid().ToString("N"));

    public ServerEnrollmentArtifactsTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    internal string Pending => Path.Combine(_root, "secrets.json");
    internal string Marker => Path.Combine(_root, "adopt.marker");
    internal string Fingerprint => Path.Combine(_root, "enrollment-fingerprint.txt");
    internal List<string> Calls { get; } = [];

    internal void StageAll()
    {
        File.WriteAllText(Pending, "x");
        File.WriteAllText(Marker, "x");
        File.WriteAllText(Fingerprint, "x");
    }

    internal ServerEnrollmentArtifacts.Seams Seams(
        Action? requireNoUnresolved = null, Func<Task>? clearPending = null, Func<Task>? clearMachine = null) => new(
        Pending, Marker, Fingerprint,
        _ =>
        {
            Calls.Add("fence");
            return Task.FromResult<IDisposable>(new Release(() => Calls.Add("unfence")));
        },
        async _ =>
        {
            Calls.Add("clear_pending");
            if (clearPending is not null) await clearPending();
            File.Delete(Pending);
        },
        async _ =>
        {
            Calls.Add("clear_machine");
            if (clearMachine is not null) await clearMachine();
        },
        () =>
        {
            Calls.Add("check_journal");
            requireNoUnresolved?.Invoke();
        },
        path => Calls.Add("validate_marker:" + Path.GetFileName(path)));

    [Fact]
    public async Task Stale_discard_with_nothing_staged_does_not_take_the_fence_or_check_anything()
    {
        Assert.False(await ServerEnrollmentArtifacts.DiscardStalePendingAsync(default, Seams()));

        Assert.Empty(Calls);
    }

    [Theory]
    [InlineData("pending")]
    [InlineData("marker")]
    public async Task Stale_discard_removes_staged_data_under_the_fence_once_no_publication_is_unresolved(string staged)
    {
        File.WriteAllText(staged == "pending" ? Pending : Marker, "x");

        Assert.True(await ServerEnrollmentArtifacts.DiscardStalePendingAsync(default, Seams()));

        Assert.False(File.Exists(Pending));
        Assert.False(File.Exists(Marker));
        Assert.Equal(["check_journal", "fence", "clear_pending", "validate_marker:adopt.marker", "unfence"], Calls);
    }

    [Fact]
    public async Task Stale_discard_leaves_everything_when_an_adoption_publication_is_unresolved()
    {
        StageAll();

        var removed = await ServerEnrollmentArtifacts.DiscardStalePendingAsync(default,
            Seams(requireNoUnresolved: () => throw new InvalidOperationException("journal")));

        Assert.False(removed);
        Assert.True(File.Exists(Pending));
        Assert.True(File.Exists(Marker));
        Assert.Equal(["check_journal"], Calls);
    }

    [Fact]
    public async Task Discard_still_removes_the_marker_when_clearing_the_pending_store_fails()
    {
        StageAll();

        await Assert.ThrowsAsync<IOException>(() => ServerEnrollmentArtifacts.DiscardPendingAsync(default,
            Seams(clearPending: () => throw new IOException("locked"))));

        Assert.False(File.Exists(Marker));
        Assert.Contains("unfence", Calls);
    }

    internal sealed class Release(Action released) : IDisposable
    {
        public void Dispose() => released();
    }
}
#endif
