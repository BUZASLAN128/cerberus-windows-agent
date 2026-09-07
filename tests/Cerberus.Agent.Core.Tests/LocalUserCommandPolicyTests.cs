using Cerberus.Agent.Integrations.Ad;

namespace Cerberus.Agent.Core.Tests;

public sealed class LocalUserCommandPolicyTests
{
    [Theory]
    [InlineData(null, "1", "enabled", true, "Registry")]
    [InlineData("true", "1", "enabled", true, "Registry")]
    [InlineData("false", "1", "disabled", false, "EnvironmentRestriction")]
    [InlineData("true", "0", "disabled", false, "Registry")]
    [InlineData(null, "0", "disabled", false, "Registry")]
    [InlineData("true", null, "disabled", false, "DefaultDisabled")]
    public void ResolveForTesting_CombinesEnvironmentAndRegistryFailClosed(
        string? environmentValue,
        string? registryValue,
        string expectedState,
        bool expectedCreateEnabled,
        string expectedSource)
    {
        var policy = LocalUserCommandPolicy.ResolveForTesting(environmentValue, registryValue);

        Assert.Equal(expectedState, policy.StateValue);
        Assert.Equal(expectedCreateEnabled, policy.CreateEnabled);
        Assert.Equal(expectedSource, policy.Source.ToString());
    }

    [Theory]
    [InlineData("malformed", false)]
    [InlineData(null, true)]
    public void ResolveForTesting_UnknownRegistryStateDeniesCreate(string? registryValue, bool readFailed)
    {
        var policy = LocalUserCommandPolicy.ResolveForTesting("true", registryValue, readFailed);

        Assert.Equal(LocalUserCreatePolicyState.Unknown, policy.State);
        Assert.False(policy.CreateEnabled);
        Assert.Equal("unknown", policy.StateValue);
    }

    [Fact]
    public void ResolveForTesting_MalformedEnvironmentIsUnknownEvenWhenRegistryAllows()
    {
        var policy = LocalUserCommandPolicy.ResolveForTesting("maybe", "1");

        Assert.Equal(LocalUserCreatePolicyState.Unknown, policy.State);
        Assert.False(policy.CreateEnabled);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void ResolveForTesting_PresentBlankRegistryValueIsUnknown(string registryValue)
    {
        var policy = LocalUserCommandPolicy.ResolveForTesting(null, registryValue);

        Assert.Equal(LocalUserCreatePolicyState.Unknown, policy.State);
        Assert.False(policy.CreateEnabled);
        Assert.Equal(LocalUserCommandPolicySource.Unknown, policy.Source);
    }

    [Fact]
    public void Observation_ConfirmsFreshCurrentConfiguredState()
    {
        using var process = System.Diagnostics.Process.GetCurrentProcess();
        var startedAtUtc = new DateTimeOffset(process.StartTime.ToUniversalTime());
        var now = DateTimeOffset.UtcNow;
        var observation = new LocalUserPolicyObservation(
            LocalUserCreatePolicyState.Disabled,
            now,
            Environment.ProcessId,
            startedAtUtc);

        Assert.True(observation.IsFresh(now.AddSeconds(1), TimeSpan.FromMinutes(1)));
        Assert.True(observation.ConfirmsConfiguredState(
            LocalUserCommandPolicy.ResolveForTesting(null, "0"),
            now.AddSeconds(1),
            TimeSpan.FromMinutes(1)));
        Assert.False(observation.ConfirmsConfiguredState(
            LocalUserCommandPolicy.CreateEnabledPolicy,
            now.AddSeconds(1),
            TimeSpan.FromMinutes(1)));
    }

    [Fact]
    public void Observation_UnknownStateNeverConfirms()
    {
        var observation = new LocalUserPolicyObservation(
            LocalUserCreatePolicyState.Unknown,
            DateTimeOffset.UtcNow,
            Environment.ProcessId,
            DateTimeOffset.UtcNow);

        Assert.False(observation.ConfirmsConfiguredState(
            LocalUserCommandPolicy.UnknownPolicy,
            DateTimeOffset.UtcNow,
            TimeSpan.FromMinutes(1)));
    }
}
