using System.Text.Json;
using System.Security.Cryptography;

namespace Cerberus.Agent.Core;

/// <summary>Protected local registration binding, never a caller-supplied authority or wire field.</summary>
public sealed record AgentStateDeliveryContext(string AgentId, string TenantId, long Generation,
    string? EnrollmentNonce, string Product, string KeyFingerprint)
{
    internal bool IsValid(string agentId) => AgentId == agentId && !string.IsNullOrWhiteSpace(TenantId) &&
        TenantId.Length <= 256 && Generation >= 0 && (EnrollmentNonce is null || Guid.TryParseExact(EnrollmentNonce, "N", out _)) &&
        Product is AgentProducts.Cerberus or AgentProducts.Secondary && KeyFingerprint is not null &&
        KeyFingerprint.StartsWith(AgentKeyFingerprint.Prefix, StringComparison.Ordinal) &&
        KeyFingerprint.Length == AgentKeyFingerprint.Prefix.Length + 64 && KeyFingerprint[AgentKeyFingerprint.Prefix.Length..].All(Uri.IsHexDigit);
}

/// <summary>One state delivery's local ACK barrier. The cached result remains in the existing replay record.</summary>
public sealed record AgentPreparedStateControl(AgentStateDeliveryContext? Context, long StateSequence,
    string[] Applied, bool AckAccepted = false, bool TransportRefused = false)
{
    internal static bool IsPending(CommandReplayRecord record) => record.Type == EnvelopeTypes.AgentState &&
        !record.ResultSubmitted && record.State != EnvelopeRecordStates.RejectedAfterReserve;

    internal bool IsValid(string agentId) => StateSequence > 0 && Applied is { Length: <= 3 } &&
        Applied.Distinct(StringComparer.Ordinal).Count() == Applied.Length &&
        Applied.All(value => value is "quarantine" or "registration_state" or "revoke") &&
        (Context?.IsValid(agentId) == true || Context is null && !AckAccepted && Applied.Length == 0);
}

public sealed partial class EnvelopeExecutionQueue
{
    private readonly object _controlAdmissionGate = new();
    private readonly AgentStateDeliveryContext? _controlContext;
    private readonly Func<CancellationToken, Task<AgentStateDeliveryContext>>? _currentControlContext;

    internal ReplayReserveOutcome Reserve(CommandReplayRecord record)
    { lock (_controlAdmissionGate) return Store.TryReserve(record); }

    private async Task WaitForPendingControlsAsync(CancellationToken ct)
    {
        while (ControlRecovery().Pending)
        {
            await DrainOutboxAsync(ct).ConfigureAwait(false);
            if (ControlRecovery().Pending) await _signal.WaitAsync(ct).ConfigureAwait(false);
        }
    }

    private Task? BeginResultSubmission(CommandReplayRecord record, CancellationToken ct)
    {
        lock (_controlAdmissionGate)
        {
            if (record.Type != EnvelopeTypes.AgentState && RequiresStateRecovery) return null;
            return _api.SubmitEnvelopeResultAsync(record.AgentId, record.Id, Convert.FromBase64String(record.ResultB64!), ct);
        }
    }

    private (bool Pending, long Floor) ControlRecovery()
    {
        if (_controlContext is null) return (false, 0);
        if (!Store.IsAvailable) return (true, 0);
        var records = Store.Records(_controlContext.AgentId).Where(IsPendingControl).ToArray();
        return (records.Length > 0, records.Select(record => record.StateControl?.StateSequence ?? 0).DefaultIfEmpty().Max());
    }

    private bool IsPendingControl(CommandReplayRecord record) => AgentPreparedStateControl.IsPending(record) &&
        (record.StateControl?.Context is null || record.StateControl.Context == _controlContext);

    private async Task<bool> HasCurrentControlContextAsync(CommandReplayRecord record, CancellationToken ct)
    {
        if (record.StateControl?.Context is not { } context || context != _controlContext || _currentControlContext is null)
            return false;
        try { return await _currentControlContext(ct).ConfigureAwait(false) == context &&
            await _currentAgentId(ct).ConfigureAwait(false) == record.AgentId; }
        catch (Exception ex) when (ex is not OperationCanceledException) { return false; }
    }

    internal async Task<AgentPreparedStateControl?> CreateStateControlAsync(SignedEnvelope envelope, CancellationToken ct)
    {
        if (_controlContext is null || !_controlContext.IsValid(envelope.AgentId) || _currentControlContext is null)
            return null;
        if (await _currentControlContext(ct).ConfigureAwait(false) != _controlContext) return null;
        var applied = new[] { "quarantine", "registration_state", "revoke" }
            .Where(name => envelope.Payload.TryGetProperty(name, out _)).ToArray();
        return new(_controlContext, envelope.Payload.GetProperty("state_seq").GetInt64(), applied);
    }

    internal void HoldUnboundState(CommandReplayRecord record, SignedEnvelope envelope)
    {
        if (record.StateControl is null)
            Store.TryUpdate(record with { StateControl = new(null, envelope.Payload.GetProperty("state_seq").GetInt64(), []) }, record.State);
    }

    internal async Task<bool> PrepareStateBeforeAckAsync(CommandReplayRecord record, SignedEnvelope envelope, CancellationToken ct)
    {
        if (!await HasCurrentControlContextAsync(record, ct).ConfigureAwait(false)) return false;
        if (record.State == EnvelopeRecordStates.Done) return true;
        if (record.State == EnvelopeRecordStates.Started)
            return RecoverAppliedState(record);
        if (SignedState is not null && envelope.Payload.GetProperty("state_seq").GetInt64() <= SignedState.Load(record.AgentId).StateSeq)
        {
            RejectStaleState(record);
            return false;
        }
        var started = record with { State = EnvelopeRecordStates.Started };
        if (Store.TryUpdate(started, EnvelopeRecordStates.Reserved) != ReplayUpdateOutcome.Updated) return false;
        var body = await ExecuteAsync(envelope, ct).ConfigureAwait(false);
        using var result = JsonDocument.Parse(body);
        if (result.RootElement.GetProperty("status").GetString() == "FAILED" &&
            result.RootElement.TryGetProperty("stderr", out var error) && error.GetString() == AgentStateCommandHandler.StaleStateSeq)
        {
            RejectStaleState(started);
            return false;
        }
        if (result.RootElement.GetProperty("status").GetString() != "DONE" || !IsStateApplied(started)) return false;
        var (done, durable) = StoreResult(started, body);
        if (durable) SupersedeOlderControls(done);
        return durable;
    }

    private void RejectStaleState(CommandReplayRecord record)
    {
        var body = Failed(AgentStateCommandHandler.StaleStateSeq, record.EnvelopeSha256);
        var rejected = record with { State = EnvelopeRecordStates.RejectedAfterReserve, RejectReason = null,
            ResultB64 = Convert.ToBase64String(body), ResultSha256 = CommandEnvelope.Sha256Hex(body) };
        var outcome = Store.TryUpdate(rejected, record.State);
        if (outcome == ReplayUpdateOutcome.Failed) outcome = Store.TryUpdate(rejected, record.State);
        if (outcome != ReplayUpdateOutcome.Updated)
            _log.Warn($"Stale state id={record.Id} remains unacknowledged: rejection could not be persisted.");
    }

    private bool IsStateApplied(CommandReplayRecord record)
    {
        if (SignedState is null) return true; // Isolated support queues have no machine state owner.
        return record.StateControl is { } control &&
            SignedState.HasPersistedState(record.AgentId, control.StateSequence, exactSequence: true);
    }

    private bool RecoverAppliedState(CommandReplayRecord record)
    {
        if (record.StateControl is not { Context: not null } control || SignedState is null || !IsStateApplied(record))
            return false;
        var body = CommandEnvelope.BuildResultBody("DONE", 0, null, new
        {
            schema_version = AgentStateCommandHandler.ResultSchema,
            state_seq = control.StateSequence,
            applied = control.Applied,
        }, record.EnvelopeSha256);
        var (done, durable) = StoreResult(record, body);
        if (durable) SupersedeOlderControls(done);
        return durable;
    }

    private void SupersedeOlderControls(CommandReplayRecord prepared)
    {
        var seq = prepared.StateControl!.StateSequence;
        var revoke = SignedState?.Load(prepared.AgentId).PendingRevoke;
        foreach (var old in Store.Records(prepared.AgentId).Where(record => IsPendingControl(record) &&
                     record.Id != prepared.Id && record.Id != revoke?.CommandId &&
                     (record.StateControl?.StateSequence ?? 0) < seq))
            Store.TryUpdate(old with { State = EnvelopeRecordStates.RejectedAfterReserve, RejectReason = null }, old.State);
    }

    private async Task RecoverStateControlsAsync(string agentId, CancellationToken ct)
    {
        foreach (var record in Store.Records(agentId).Where(record => IsPendingControl(record) &&
                     record.State == EnvelopeRecordStates.Started && !IsInFlight(record.AgentId, record.Id)))
        {
            if (!await HasCurrentControlContextAsync(record, ct).ConfigureAwait(false)) continue;
            RecoverAppliedState(record);
        }
    }

    private static bool IsPreparedResult(CommandReplayRecord record)
    {
        try
        {
            var bytes = Convert.FromBase64String(record.ResultB64!);
            if (bytes.Length > 4096 || !string.Equals(Convert.ToHexString(SHA256.HashData(bytes)),
                    record.ResultSha256, StringComparison.OrdinalIgnoreCase)) return false;
            using var body = JsonDocument.Parse(bytes);
            return body.RootElement.GetProperty("status").GetString() == "DONE" &&
                body.RootElement.GetProperty("envelope_sha256").GetString() == record.EnvelopeSha256;
        }
        catch (Exception ex) when (ex is FormatException or JsonException or KeyNotFoundException or InvalidOperationException or ArgumentNullException)
        { return false; }
    }

    internal async Task<bool> AcceptPreparedStateAsync(CommandReplayRecord record, CancellationToken ct)
    {
        if (record.State != EnvelopeRecordStates.Done || record.ResultB64 is null ||
            record.StateControl is not { } control || control.TransportRefused || !IsPreparedResult(record) ||
            SignedState is not null && !SignedState.HasPersistedState(record.AgentId, control.StateSequence, exactSequence: false) ||
            !await HasCurrentControlContextAsync(record, ct).ConfigureAwait(false)) return false;
        if (control.AckAccepted) return true;
        if (!_resultRetry.CanTry) return false;
        using var timeout = new CancellationTokenSource(EnvelopeCommandProcessor.AckTimeout, Time);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, timeout.Token);
        try
        {
            await _api.SubmitEnvelopeAckAsync(record.AgentId, record.Id,
                CommandEnvelope.BuildAckBody(record.EnvelopeSha256, true, null), linked.Token)
                .WaitAsync(linked.Token).ConfigureAwait(false);
        }
        catch (HttpRequestException ex) when (ex.StatusCode is { } status && IsFinalRefusal(status))
        {
            Store.TryUpdate(record with { StateControl = control with { TransportRefused = true } }, record.State);
            return false;
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            _resultRetry.Failed(ex);
            return false;
        }
        _resultRetry.Succeeded();
        return Store.TryUpdate(record with { StateControl = control with { AckAccepted = true } }, record.State) == ReplayUpdateOutcome.Updated;
    }
}

public sealed partial class CommandReplayStore
{
    /// <summary>Read the durable update barrier before automatic service workers start.</summary>
    public bool HasPendingStateDelivery(long generation, string? enrollmentNonce)
    {
        lock (_gate)
        {
            return !EnsureLoaded() || _records.Any(record => AgentPreparedStateControl.IsPending(record) &&
                (record.StateControl?.Context is null || record.StateControl.Context.Generation == generation &&
                    record.StateControl.Context.EnrollmentNonce == enrollmentNonce));
        }
    }
}
