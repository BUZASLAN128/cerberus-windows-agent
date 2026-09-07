using System.Diagnostics;
using System.Globalization;
using Microsoft.Win32;

namespace Cerberus.Agent.Integrations.Ad;

public enum LocalUserCreatePolicyState
{
    Enabled,
    Disabled,
    Unknown,
}

public enum LocalUserCommandPolicySource
{
    Registry,
    EnvironmentRestriction,
    DefaultDisabled,
    Unknown,
    TestOverride,
}

/// <summary>
/// Non-authoritative observation written by the service telemetry collector.
/// The receipt is useful to the interactive UI, but is never consulted for
/// command authorization.
/// </summary>
public sealed record LocalUserPolicyObservation(
    LocalUserCreatePolicyState State,
    DateTimeOffset ObservedAtUtc,
    int ProcessId,
    DateTimeOffset ProcessStartedAtUtc)
{
    public string StateValue => State switch
    {
        LocalUserCreatePolicyState.Enabled => "enabled",
        LocalUserCreatePolicyState.Disabled => "disabled",
        _ => "unknown",
    };

    public bool IsFresh(DateTimeOffset nowUtc, TimeSpan maxAge)
    {
        var age = nowUtc.ToUniversalTime() - ObservedAtUtc.ToUniversalTime();
        return maxAge > TimeSpan.Zero && age >= TimeSpan.Zero && age <= maxAge;
    }

    public bool IsCurrentServiceProcess()
    {
        if (ProcessId <= 0)
            return false;

        try
        {
            using var process = Process.GetProcessById(ProcessId);
            if (process.HasExited)
                return false;

            var startedAtUtc = new DateTimeOffset(process.StartTime.ToUniversalTime());
            return startedAtUtc == ProcessStartedAtUtc.ToUniversalTime();
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or
            System.ComponentModel.Win32Exception or UnauthorizedAccessException or NotSupportedException)
        {
            return false;
        }
    }

    /// <summary>
    /// Returns true only for a fresh observation from the currently running
    /// service whose state agrees with the registry-configured state. Unknown
    /// states never count as confirmation.
    /// </summary>
    public bool ConfirmsConfiguredState(
        LocalUserCommandPolicy configuredPolicy,
        DateTimeOffset nowUtc,
        TimeSpan maxAge)
        => configuredPolicy is not null &&
           (State is LocalUserCreatePolicyState.Enabled or LocalUserCreatePolicyState.Disabled) &&
           (configuredPolicy.Source is LocalUserCommandPolicySource.Registry or LocalUserCommandPolicySource.DefaultDisabled) &&
           configuredPolicy.State == State &&
           IsFresh(nowUtc, maxAge) &&
           IsCurrentServiceProcess();
}

/// <summary>
/// Resolves the local approval half of the managed-account double lock.
/// The production resolver reads the current environment and machine registry
/// every time it is called; it intentionally does not retain a startup value.
/// </summary>
public sealed record LocalUserCommandPolicy
{
    private const string CreateEnabledEnvVar = "CERBERUS_AGENT_LOCAL_USER_CREATE_ENABLED";
    private const string RegistryPath = @"SOFTWARE\Cerberus\WindowsAgent";
    private const string RegistryValueName = "localUserCreateEnabled";
    private const string ObservationRegistryPath = RegistryPath + @"\LocalUserCreatePolicyObservation";
    private const string ObservationStateValueName = "state";
    private const string ObservationAtValueName = "observedAtUtc";
    private const string ObservationProcessIdValueName = "processId";
    private const string ObservationProcessStartedAtValueName = "processStartedAtUtc";

    private enum RegistryPolicyState
    {
        Missing,
        Enabled,
        Disabled,
        Unknown,
    }

    private readonly record struct RegistryPolicyValue(RegistryPolicyState State);

    public LocalUserCommandPolicy(bool createEnabled)
        : this(
            createEnabled ? LocalUserCreatePolicyState.Enabled : LocalUserCreatePolicyState.Disabled,
            createEnabled,
            LocalUserCommandPolicySource.TestOverride)
    {
    }

    private LocalUserCommandPolicy(
        LocalUserCreatePolicyState state,
        bool createEnabled,
        LocalUserCommandPolicySource source)
    {
        State = state;
        CreateEnabled = createEnabled;
        Source = source;
    }

    public LocalUserCreatePolicyState State { get; }

    /// <summary>Effective local create authority. Unknown and disabled states are always false.</summary>
    public bool CreateEnabled { get; }

    /// <summary>Indicates whether registry or environment/default state determined the result.</summary>
    public LocalUserCommandPolicySource Source { get; }

    /// <summary>Stable lowercase state used by the capabilities telemetry contract.</summary>
    public string StateValue => State switch
    {
        LocalUserCreatePolicyState.Enabled => "enabled",
        LocalUserCreatePolicyState.Disabled => "disabled",
        _ => "unknown",
    };

    // These deterministic policies are test injection values only. Production
    // service and telemetry wiring use Resolve() below rather than either value.
    public static LocalUserCommandPolicy CreateDisabled { get; } = new(false);
    public static LocalUserCommandPolicy CreateEnabledPolicy { get; } = new(true);
    public static LocalUserCommandPolicy UnknownPolicy { get; } = new(
        LocalUserCreatePolicyState.Unknown,
        false,
        LocalUserCommandPolicySource.Unknown);

    public static LocalUserCommandPolicy Resolve()
        => ResolveCore(
            Environment.GetEnvironmentVariable(CreateEnabledEnvVar),
            ReadRegistryPolicy());

    /// <summary>
    /// Reads only the machine registry setting. This is the configured UI
    /// value; it intentionally does not infer the service's environment-based
    /// restriction.
    /// </summary>
    public static LocalUserCommandPolicy ReadConfiguredPolicy()
        => ResolveCore(environmentValue: null, ReadRegistryPolicy());

    /// <summary>
    /// Reads the last service-owned telemetry observation, if its protected
    /// registry receipt is present and well formed. A receipt is informational
    /// only and cannot grant local-user create authority.
    /// </summary>
    public static LocalUserPolicyObservation? ReadServiceObservation()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(ObservationRegistryPath, writable: false);
            if (key is null)
                return null;

            var state = ParseStateValue(Convert.ToString(key.GetValue(ObservationStateValueName, null)));
            var observedAt = ParseObservationTime(key.GetValue(ObservationAtValueName, null));
            var processId = ParseProcessId(key.GetValue(ObservationProcessIdValueName, null));
            var processStartedAt = ParseObservationTime(key.GetValue(ObservationProcessStartedAtValueName, null));
            return state is null || observedAt is null || processId is null || processStartedAt is null
                ? null
                : new LocalUserPolicyObservation(state.Value, observedAt.Value, processId.Value, processStartedAt.Value);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or
            System.Security.SecurityException or PlatformNotSupportedException or InvalidCastException or
            FormatException or OverflowException)
        {
            return null;
        }
    }

    /// <summary>
    /// Persists a non-authoritative observation for the running service. The
    /// service capabilities collector is the only production caller.
    /// </summary>
    public static void WriteServiceObservation(LocalUserCommandPolicy policy, DateTimeOffset observedAtUtc)
    {
        ArgumentNullException.ThrowIfNull(policy);
        using var process = Process.GetCurrentProcess();
        var processStartedAtUtc = new DateTimeOffset(process.StartTime.ToUniversalTime());
        using var key = Registry.LocalMachine.CreateSubKey(ObservationRegistryPath, writable: true)
            ?? throw new InvalidOperationException("Cerberus Windows Agent policy observation path could not be opened.");

        key.SetValue(ObservationStateValueName, policy.StateValue, RegistryValueKind.String);
        key.SetValue(ObservationAtValueName, observedAtUtc.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture), RegistryValueKind.String);
        key.SetValue(ObservationProcessIdValueName, Environment.ProcessId, RegistryValueKind.DWord);
        key.SetValue(ObservationProcessStartedAtValueName, processStartedAtUtc.ToString("O", CultureInfo.InvariantCulture), RegistryValueKind.String);
    }

    // Kept as the compatibility name used by the UI/CLI while Resolve is the
    // canonical live-read API.
    public static LocalUserCommandPolicy FromEnvironmentAndRegistry() => Resolve();

    public static void WriteRegistryCreateEnabled(bool enabled)
    {
        using var key = Registry.LocalMachine.CreateSubKey(RegistryPath, writable: true)
            ?? throw new InvalidOperationException("Cerberus Windows Agent registry policy path could not be opened.");
        key.SetValue(RegistryValueName, enabled ? 1 : 0, RegistryValueKind.DWord);
    }

    internal static LocalUserCommandPolicy ResolveForTesting(
        string? environmentValue,
        string? registryValue,
        bool registryReadFailed = false)
        => ResolveCore(
            environmentValue,
            registryReadFailed
                ? new RegistryPolicyValue(RegistryPolicyState.Unknown)
                : ParseRegistryValue(registryValue));

    private static LocalUserCommandPolicy ResolveCore(
        string? environmentValue,
        RegistryPolicyValue registry)
    {
        var environment = ParseBool(environmentValue, out var environmentMalformed);
        if (environmentMalformed || registry.State == RegistryPolicyState.Unknown)
            return new(LocalUserCreatePolicyState.Unknown, false, LocalUserCommandPolicySource.Unknown);

        return registry.State switch
        {
            // A missing registry value is an explicit fail-closed default. An
            // environment true value cannot create authority that is absent.
            RegistryPolicyState.Missing => new(
                LocalUserCreatePolicyState.Disabled,
                false,
                LocalUserCommandPolicySource.DefaultDisabled),
            RegistryPolicyState.Disabled => new(
                LocalUserCreatePolicyState.Disabled,
                false,
                LocalUserCommandPolicySource.Registry),
            RegistryPolicyState.Enabled when environment == false => new(
                LocalUserCreatePolicyState.Disabled,
                false,
                LocalUserCommandPolicySource.EnvironmentRestriction),
            RegistryPolicyState.Enabled => new(
                LocalUserCreatePolicyState.Enabled,
                true,
                LocalUserCommandPolicySource.Registry),
            _ => new(LocalUserCreatePolicyState.Unknown, false, LocalUserCommandPolicySource.Unknown),
        };
    }

    private static RegistryPolicyValue ReadRegistryPolicy()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(RegistryPath, writable: false);
            if (key is null)
                return new(RegistryPolicyState.Missing);

            var value = key.GetValue(RegistryValueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
            return value is null
                ? new(RegistryPolicyState.Missing)
                : ParseRegistryValue(Convert.ToString(value));
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or System.Security.SecurityException
            or PlatformNotSupportedException)
        {
            return new(RegistryPolicyState.Unknown);
        }
    }

    private static RegistryPolicyValue ParseRegistryValue(string? raw)
    {
        if (raw is null)
            return new(RegistryPolicyState.Missing);

        var parsed = ParseBool(raw, out var malformed);
        return malformed || parsed is null
            ? new(RegistryPolicyState.Unknown)
            : new(parsed.Value ? RegistryPolicyState.Enabled : RegistryPolicyState.Disabled);
    }

    private static LocalUserCreatePolicyState? ParseStateValue(string? raw)
        => raw?.Trim().ToLowerInvariant() switch
        {
            "enabled" => LocalUserCreatePolicyState.Enabled,
            "disabled" => LocalUserCreatePolicyState.Disabled,
            "unknown" => LocalUserCreatePolicyState.Unknown,
            _ => null,
        };

    private static DateTimeOffset? ParseObservationTime(object? raw)
    {
        var value = Convert.ToString(raw)?.Trim();
        return DateTimeOffset.TryParse(
            value,
            CultureInfo.InvariantCulture,
            DateTimeStyles.RoundtripKind,
            out var parsed)
            ? parsed.ToUniversalTime()
            : null;
    }

    private static int? ParseProcessId(object? raw)
    {
        try
        {
            var processId = Convert.ToInt32(raw, CultureInfo.InvariantCulture);
            return processId > 0 ? processId : null;
        }
        catch (Exception ex) when (ex is InvalidCastException or FormatException or OverflowException)
        {
            return null;
        }
    }

    private static bool? ParseBool(string? raw, out bool malformed)
    {
        malformed = false;
        var value = (raw ?? string.Empty).Trim();
        if (value.Length == 0)
            return null;
        if (string.Equals(value, "1", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(value, "true", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(value, "yes", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(value, "on", StringComparison.OrdinalIgnoreCase))
            return true;
        if (string.Equals(value, "0", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(value, "false", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(value, "no", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(value, "off", StringComparison.OrdinalIgnoreCase))
            return false;

        malformed = true;
        return null;
    }
}
