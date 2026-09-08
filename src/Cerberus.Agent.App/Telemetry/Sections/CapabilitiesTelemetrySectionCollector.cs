using System.IO;
using Cerberus.Agent.Core;
using Cerberus.Agent.Integrations.Ad;

namespace Cerberus.Agent.App.Telemetry.Sections;

internal sealed class CapabilitiesTelemetrySectionCollector : IWindowsTelemetrySectionCollector, IAgentTelemetrySnapshotTrigger
{
    private readonly Func<LocalUserCommandPolicy> _localUserPolicyResolver;
    private readonly Action<LocalUserCommandPolicy, DateTimeOffset>? _serviceObservationWriter;
    private readonly object _policyGate = new();
    private LocalUserCommandPolicy _lastSubmittedPolicy = LocalUserCommandPolicy.UnknownPolicy;
    private LocalUserCommandPolicy? _lastCollectedPolicy;

    public CapabilitiesTelemetrySectionCollector()
        : this(LocalUserCommandPolicy.Resolve, serviceObservationWriter: null)
    {
    }

    internal CapabilitiesTelemetrySectionCollector(LocalUserCommandPolicy localUserPolicy)
        : this(() => localUserPolicy, serviceObservationWriter: null)
    {
    }

    internal CapabilitiesTelemetrySectionCollector(Func<LocalUserCommandPolicy> localUserPolicyResolver)
        : this(localUserPolicyResolver, serviceObservationWriter: null)
    {
    }

    internal CapabilitiesTelemetrySectionCollector(
        Func<LocalUserCommandPolicy> localUserPolicyResolver,
        Action<LocalUserCommandPolicy, DateTimeOffset>? serviceObservationWriter)
    {
        _localUserPolicyResolver = localUserPolicyResolver
            ?? throw new ArgumentNullException(nameof(localUserPolicyResolver));
        _serviceObservationWriter = serviceObservationWriter;
        _lastSubmittedPolicy = ResolvePolicy();
    }

    public string SectionName => "capabilities";

    public bool IsSnapshotRefreshRequired()
    {
        var current = ResolvePolicy();
        lock (_policyGate)
        {
            return current.State != _lastSubmittedPolicy.State;
        }
    }

    public void MarkSnapshotSubmitted()
    {
        lock (_policyGate)
        {
            if (_lastCollectedPolicy is not null)
                _lastSubmittedPolicy = _lastCollectedPolicy;
        }
    }

    public ValueTask<object> CollectAsync(WindowsTelemetryContext context, CancellationToken ct)
    {
        var localUserPolicy = ResolvePolicy();
        lock (_policyGate)
        {
            _lastCollectedPolicy = localUserPolicy;
        }

        var observedAtUtc = DateTimeOffset.UtcNow;
        try
        {
            _serviceObservationWriter?.Invoke(localUserPolicy, observedAtUtc);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or
            System.Security.SecurityException or InvalidOperationException or PlatformNotSupportedException or
            System.ComponentModel.Win32Exception or ArgumentException)
        {
            // A receipt is best-effort observability. It must never make the
            // capability snapshot disappear or affect command authorization.
        }

        var mutation = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["windows.local_user.disable"] = "managed_local_user",
            ["windows.local_user.delete"] = "managed_local_user",
            ["local_users"] = "managed_cerberus_users",
            ["local_groups"] = "remote_desktop_users_managed",
            ["windows_services"] = "governed_boundary_disabled",
            ["firewall"] = "governed_boundary_disabled",
            ["rdp"] = "managed_local_user_credential_ready",
            ["ad"] = "planned_governed_module",
        };
        if (localUserPolicy.CreateEnabled)
        {
            mutation["windows.local_user.create"] = "managed_local_user";
        }

        return ValueTask.FromResult<object>(new
        {
            status = "ok",
            read = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["identity"] = "supported",
                ["os"] = "supported",
                ["resources"] = "supported",
                ["network"] = "supported",
                ["tailscale"] = "supported_when_installed",
                ["rdp"] = "supported",
                ["firewall"] = "supported",
                ["security"] = "best_effort",
                ["clock"] = "supported",
                ["runtime"] = "supported",
            },
            mutation,
            local_user_create_policy = new
            {
                state = localUserPolicy.StateValue,
                observed_at = observedAtUtc.ToString("O"),
            },
            arbitrary_command_execution = "unsupported",
        });
    }

    private LocalUserCommandPolicy ResolvePolicy()
    {
        try
        {
            return _localUserPolicyResolver();
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or
            System.Security.SecurityException or PlatformNotSupportedException)
        {
            return LocalUserCommandPolicy.UnknownPolicy;
        }
    }
}
