#if CERBERUS_SERVER_PROFILE
using System.IO;
using Cerberus.Agent.App.Control;
using Cerberus.Agent.Core;
using Cerberus.Agent.Security;

namespace Cerberus.Agent.App;

/// <summary>Server profile: the credential artifacts an install-time enroll leaves under the data folder.</summary>
internal static class ServerEnrollmentArtifacts
{
    /// <summary>
    /// Where the artifacts live and how they are cleared. Production uses <see cref="Real"/>; tests point it at a
    /// temporary folder and replace the operations that reach the real machine.
    /// </summary>
    internal sealed record Seams(
        string PendingSecretsPath,
        string MarkerPath,
        string FingerprintPath,
        Func<CancellationToken, Task<IDisposable>> AcquireFence,
        Func<CancellationToken, Task> ClearPending,
        Func<CancellationToken, Task> ClearMachine,
        Action RequireNoUnresolvedPublication,
        Action<string> ValidateMarker);

    internal static Seams Real { get; } = new(
        Path.Combine(AgentCredentialPublication.PendingDirectory, "secrets.json"),
        AgentCredentialPublication.MarkerPath,
        Path.Combine(ServerDataRoot.DefaultPath, EnrollHeadlessMode.FingerprintFileName),
        async ct => await AgentUpdateLaunchFence.AcquireForEnrollmentPromotionAsync(ct).ConfigureAwait(false),
        ct => AgentEnrollmentPromotion.OpenPendingStore().ClearAsync(ct),
        ct => new DpapiSecretStore(SecretStoreScope.Machine).ClearAsync(ct),
        AgentCredentialPublication.RequireNoUnresolvedPublication,
        path => AgentCredentialPublication.ValidateProtectedItem(path, allowMissing: true));

    private static bool PendingStaged(Seams s) => File.Exists(s.PendingSecretsPath) || File.Exists(s.MarkerPath);

    /// <summary>Removes the staged pending credentials and the adopt marker.</summary>
    internal static async Task DiscardPendingAsync(CancellationToken ct, Seams? seams = null)
    {
        var s = seams ?? Real;
        using var fence = await s.AcquireFence(ct).ConfigureAwait(false);
        try
        {
            await s.ClearPending(ct).ConfigureAwait(false);
        }
        finally
        {
            s.ValidateMarker(s.MarkerPath);
            File.Delete(s.MarkerPath);
        }
    }

    /// <summary>
    /// Removes pending credentials and the adopt marker that a killed enroll run left behind. Staged data is stale
    /// when no credential publication is unresolved, because an adoption in progress holds a publication journal and a
    /// finished one has already consumed the pending store. Callers hold the enroll lock (the enroll run, before it sends
    /// the proof). Returns true when something was removed.
    /// </summary>
    internal static async Task<bool> DiscardStalePendingAsync(CancellationToken ct, Seams? seams = null)
    {
        var s = seams ?? Real;
        if (!PendingStaged(s))
            return false;
        try
        {
            s.RequireNoUnresolvedPublication();
        }
        catch (InvalidOperationException)
        {
            return false;
        }
        await DiscardPendingAsync(ct, s).ConfigureAwait(false);
        return true;
    }

    /// <summary>
    /// Undoes an install-time enroll: committed credentials, pending store, adopt marker and fingerprint file.
    /// Never touches the network. Each step is independent; returns one log line without secrets.
    /// </summary>
    internal static async Task<string> RollbackAsync(CancellationToken ct, Seams? seams = null)
    {
        var s = seams ?? Real;
        var pending = await StepAsync(async () => { if (PendingStaged(s)) await DiscardPendingAsync(ct, s).ConfigureAwait(false); }).ConfigureAwait(false);
        var committed = await StepAsync(() => s.ClearMachine(ct)).ConfigureAwait(false);
        var fingerprint = await StepAsync(() =>
        {
            File.Delete(s.FingerprintPath);
            return Task.CompletedTask;
        }).ConfigureAwait(false);
        return $"Enrollment rollback pending={pending} committed={committed} fingerprint={fingerprint}";
    }

    private static async Task<string> StepAsync(Func<Task> step)
    {
        try
        {
            await step().ConfigureAwait(false);
            return "ok";
        }
        catch (Exception ex)
        {
            return ex.GetType().Name;
        }
    }
}
#endif
