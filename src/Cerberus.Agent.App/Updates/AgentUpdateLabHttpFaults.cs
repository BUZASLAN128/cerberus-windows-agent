using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.App.Updates;

internal static class AgentUpdateLabHttpFaults
{
    internal const string RefreshEvidenceSchema = "agent.update.lab.token_refresh.v1";
    internal const int MaxBackendSends = 16;
    internal static readonly TimeSpan MaxObservation = TimeSpan.FromMinutes(20);

    internal static HttpMessageHandler Wrap(HttpMessageHandler inner) => string.IsNullOrEmpty(AgentUpdateDefaults.LabPolicyB64)
        ? inner
        : new TokenRouteHandler(inner, TryArmToken429, QueueRefreshEvidence);

    internal sealed record RefreshAttempt(AgentUpdateLabRuntime.Scope Scope, string Version, string AttemptId);
    internal sealed record RefreshSample(DateTimeOffset Utc, int? Status, int? RetryAfterSeconds);
    internal sealed record RefreshEvidence(string Schema, string CampaignId, string Version, string AttemptId,
        string Status, DateTimeOffset SinceUtc, DateTimeOffset ThroughUtc, DateTimeOffset? FaultUtc,
        RefreshSample SyntheticResponse, RefreshSample[] BackendSends);

    private static RefreshAttempt? TryArmToken429()
    {
        var scope = AgentUpdateLabRuntime.Resolve();
        var version = AgentUpdateCampaignTransition.Release(WindowsDeviceInfo.GetAgentVersion());
        if (scope is null || AgentUpdateLabFaults.FaultFor(scope.Policy, version) != AgentUpdateLabFaults.TokenRoute429 ||
            !AgentUpdateLocalService.AllowsLabFault(scope.Context.Generation)) return null;

        var journal = new AgentUpdateJournalStore(AgentUpdateStager.DefaultStagingRoot).Read();
        return IsPostCommit(journal, scope.Policy.CampaignId, scope.Context.Generation, version) &&
            !IsInstallerBusy(AgentUpdateLabFaults.InstallerMutexName) &&
            AgentUpdateLabFaults.RecordOnce(scope, version, AgentUpdateLabFaults.TokenRoute429,
                journal.InstallRequest!.VerifiedRelease!.ArtifactSha256, journal.AttemptId)
            ? new(scope, version, journal.AttemptId!) : null;
    }

    private static void QueueRefreshEvidence(RefreshAttempt attempt, RefreshEvidence evidence)
    {
        // The observation must never delay the refresh to perform disk I/O.
        _ = Task.Run(() =>
        {
            try { PublishRefreshEvidence(attempt, evidence); }
            catch (Exception) { } // An unavailable record leaves evidence missing.
        });
    }

    private static void PublishRefreshEvidence(RefreshAttempt attempt, RefreshEvidence evidence)
    {
        var scope = AgentUpdateLabRuntime.Resolve();
        if (scope is null || !AgentUpdateSecurity.IsLocalSystem() || scope.Context != attempt.Scope.Context ||
            scope.Policy.CampaignId != attempt.Scope.Policy.CampaignId ||
            AgentUpdateLabFaults.FaultFor(scope.Policy, attempt.Version) != AgentUpdateLabFaults.TokenRoute429 ||
            AgentUpdateCampaignTransition.Release(WindowsDeviceInfo.GetAgentVersion()) != attempt.Version ||
            !AgentUpdateLocalService.AllowsLabFault(scope.Context.Generation))
            return;
        var journal = new AgentUpdateJournalStore(AgentUpdateStager.DefaultStagingRoot).Read();
        if (!IsPostCommit(journal, scope.Policy.CampaignId, scope.Context.Generation, attempt.Version) ||
            journal.AttemptId != attempt.AttemptId) return;

        var root = AgentUpdateLabRuntimeAdmission.CampaignRoot(scope.Policy);
        using var held = AgentUpdateLabFaults.LockFaultRecords(root);
        var fault = AgentUpdateDurableFile.Read<AgentUpdateLabFaults.Receipt>(Path.Combine(root, attempt.Version + ".json"), root);
        if (fault is null || !MatchesFaultReceipt(attempt, evidence, fault, Environment.ProcessId) ||
            fault.ArtifactSha256 != journal.InstallRequest!.VerifiedRelease!.ArtifactSha256) return;
        var path = Path.Combine(root, "token-refresh-" + attempt.Version + ".json");
        AgentUpdateSecurity.ValidateProtectedPath(path, root, allowMissing: true);
        if (AgentUpdateDurableFile.Read<RefreshEvidence>(path, root) is null)
            AgentUpdateDurableFile.Write(path, root, evidence with { FaultUtc = fault.Utc });
    }

    internal static bool MatchesFaultReceipt(RefreshAttempt attempt, RefreshEvidence evidence, AgentUpdateLabFaults.Receipt fault,
        int processId) => evidence.Schema == RefreshEvidenceSchema && evidence.CampaignId == attempt.Scope.Policy.CampaignId &&
        evidence.Version == attempt.Version && evidence.AttemptId == attempt.AttemptId &&
        evidence.SyntheticResponse is { Status: 429, RetryAfterSeconds: > 0 } &&
        fault.CampaignId == attempt.Scope.Policy.CampaignId && fault.AgentId == attempt.Scope.Context.AgentId &&
        fault.TenantId == attempt.Scope.Context.TenantId && fault.KeyFingerprint == attempt.Scope.Context.KeyFingerprint &&
        fault.Version == attempt.Version && fault.AttemptId == attempt.AttemptId && fault.Fault == AgentUpdateLabFaults.TokenRoute429 &&
        fault.ProcessId == processId && fault.Utc >= evidence.SinceUtc && fault.Utc <= evidence.SyntheticResponse.Utc;

    internal static bool IsPostCommit(AgentUpdateJournal journal, string campaignId, long generation, string version)
        => journal.Phase is ("committed_watch" or AgentUpdateStates.Installed) &&
            AgentUpdateSecurity.IsSafeAttemptId(journal.AttemptId) && journal.LifecycleGeneration == generation &&
            journal.InstallRequest is { ExpectedPlan: { } expected, VerifiedRelease: { } release } request &&
            request.LocalPolicyId == campaignId && request.LifecycleGeneration == generation &&
            request.BoundAttemptId == journal.AttemptId && release.Version == version && expected.Matches(release);

    internal static bool IsInstallerBusy(string name)
    {
        if (!Mutex.TryOpenExisting(name, out var mutex)) return false;
        using (mutex)
        {
            if (!AgentUpdateLabFaults.TryAcquireMutex(mutex)) return true;
            mutex.ReleaseMutex();
            return false;
        }
    }

    private static int? ObservedRetryAfter(HttpResponseMessage response) => response.StatusCode == HttpStatusCode.TooManyRequests &&
        AgentHttpFailure.ReadRetryAfter(response, TimeSpan.FromHours(1)) is { } delay
        ? (int)Math.Ceiling(delay.TotalSeconds) : null;

    internal sealed class TokenRouteHandler(HttpMessageHandler inner, Func<RefreshAttempt?> tryArm,
        Action<RefreshAttempt, RefreshEvidence>? publish = null, TimeProvider? time = null) : DelegatingHandler(inner)
    {
        private readonly TimeProvider _time = time ?? TimeProvider.System;
        private readonly object _gate = new();
        private Observation? _observation;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (request.Method != HttpMethod.Post || request.RequestUri is not { IsAbsoluteUri: true } uri ||
                uri.AbsolutePath != "/api/v1/agents/token") return base.SendAsync(request, cancellationToken);

            Observation? observation;
            int index = -1;
            lock (_gate)
            {
                var since = _time.GetUtcNow();
                RefreshAttempt? armed;
                try { armed = tryArm(); }
                catch (Exception) { armed = null; } // Fault arming must not interrupt the real token request.
                if (armed is not null)
                {
                    var response = new HttpResponseMessage(HttpStatusCode.TooManyRequests)
                    {
                        RequestMessage = request,
                        Content = new StringContent("{}", Encoding.UTF8, "application/json"),
                    };
                    response.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromSeconds(120));
                    var now = _time.GetUtcNow();
                    if (publish is not null && now >= since && ObservedRetryAfter(response) is { } delay)
                        _observation = new(armed, since, new(now, (int)response.StatusCode, delay), _time.GetTimestamp());
                    return Task.FromResult(response);
                }
                observation = _observation;
                if (observation is not null)
                {
                    var utc = _time.GetUtcNow();
                    var elapsed = _time.GetElapsedTime(observation.StartTimestamp);
                    if (!observation.CanObserve(utc, elapsed) || observation.Sends.Count == MaxBackendSends)
                        _observation = observation = null;
                    else
                    {
                        index = observation.Sends.Count;
                        observation.Sends.Add(new(utc, null, null));
                        observation.Premature |= elapsed < TimeSpan.FromSeconds(observation.Synthetic.RetryAfterSeconds!.Value);
                    }
                }
            }
            return observation is null ? base.SendAsync(request, cancellationToken) :
                ObserveBackendAsync(observation, index, request, cancellationToken);
        }

        private async Task<HttpResponseMessage> ObserveBackendAsync(Observation observation, int index,
            HttpRequestMessage request, CancellationToken ct)
        {
            HttpResponseMessage response;
            try { response = await base.SendAsync(request, ct).ConfigureAwait(false); }
            catch
            {
                lock (_gate) { if (ReferenceEquals(_observation, observation)) _observation = null; }
                throw;
            }
            RefreshEvidence? evidence = null;
            lock (_gate)
            {
                if (!ReferenceEquals(_observation, observation)) return response;
                var through = _time.GetUtcNow();
                var elapsed = _time.GetElapsedTime(observation.StartTimestamp);
                if (!observation.CanObserve(through, elapsed))
                    _observation = null;
                else
                {
                    observation.Sends[index] = observation.Sends[index] with
                    {
                        Status = (int)response.StatusCode,
                        RetryAfterSeconds = ObservedRetryAfter(response),
                    };
                    if (observation.Sends.All(sample => sample.Status is not null))
                    {
                        _observation = null;
                        evidence = new(RefreshEvidenceSchema, observation.Attempt.Scope.Policy.CampaignId,
                            observation.Attempt.Version, observation.Attempt.AttemptId,
                            observation.Premature ? "Unqualified" : "READ", observation.SinceUtc, through, null,
                            observation.Synthetic, observation.Sends.ToArray());
                    }
                }
            }
            if (evidence is not null)
            {
                try { publish!(observation.Attempt, evidence); }
                catch (Exception) { } // Publishing evidence cannot change the HTTP result.
            }
            return response;
        }
    }

    private sealed class Observation(RefreshAttempt attempt, DateTimeOffset sinceUtc, RefreshSample synthetic, long startTimestamp)
    {
        public RefreshAttempt Attempt { get; } = attempt;
        public DateTimeOffset SinceUtc { get; } = sinceUtc;
        public RefreshSample Synthetic { get; } = synthetic;
        public long StartTimestamp { get; } = startTimestamp;
        public List<RefreshSample> Sends { get; } = [];
        public bool Premature { get; set; }

        public bool CanObserve(DateTimeOffset utc, TimeSpan elapsed) =>
            (Sends.Count == 0 ? utc >= Synthetic.Utc : utc >= Sends[^1].Utc) && utc < Attempt.Scope.Policy.ExpiresAtUtc &&
            elapsed >= TimeSpan.Zero && elapsed <= MaxObservation && utc - Synthetic.Utc <= MaxObservation &&
            ((utc - Synthetic.Utc) - elapsed).Duration() <= TimeSpan.FromSeconds(1);
    }
}
