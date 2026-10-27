// Pure status/pin decision of the update Authenticode gate (the same functions Verify calls).
namespace Cerberus.Agent.Core.Tests;

public sealed class AgentUpdateAuthenticodeDecisionTests
{
    private const string Pin = "sha256:ABCDEF0123456789";
    private const int UntrustedRoot = unchecked((int)0x800B0109);

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void AcceptsSigner_CleanStatus_RequiresPinnedKey(bool allowUntrustedRoot)
    {
        Assert.True(AgentUpdateAuthenticode.AcceptsSigner(0, "abcdef0123456789", $"sha256:00,{Pin}", allowUntrustedRoot));
        Assert.False(AgentUpdateAuthenticode.AcceptsSigner(0, "abcdef0123456789", "sha256:00", allowUntrustedRoot));
    }

    [Fact]
    public void AcceptsSigner_UntrustedRoot_OnlyWhenAllowedAndPinned()
    {
        Assert.True(AgentUpdateAuthenticode.AcceptsSigner(UntrustedRoot, "abcdef0123456789", Pin, allowUntrustedRoot: true));
        Assert.False(AgentUpdateAuthenticode.AcceptsSigner(UntrustedRoot, "abcdef0123456789", "sha256:00", allowUntrustedRoot: true));
        Assert.False(AgentUpdateAuthenticode.AcceptsSigner(UntrustedRoot, "abcdef0123456789", Pin, allowUntrustedRoot: false));
        Assert.False(AgentUpdateAuthenticode.AcceptsStatus(UntrustedRoot, allowUntrustedRoot: false));
    }

    [Theory]
    [InlineData(unchecked((int)0x800B0100))] // TRUST_E_NOSIGNATURE
    [InlineData(unchecked((int)0x80096010))] // TRUST_E_BAD_DIGEST
    [InlineData(unchecked((int)0x800B010A))] // CERT_E_CHAINING
    [InlineData(unchecked((int)0x800B0101))] // CERT_E_EXPIRED
    [InlineData(unchecked((int)0x800B010C))] // CERT_E_REVOKED
    [InlineData(unchecked((int)0x800B0111))] // TRUST_E_EXPLICIT_DISTRUST
    public void AcceptsSigner_AnyOtherFailure_IsRejectedEvenWithPinnedKey(int status)
    {
        Assert.False(AgentUpdateAuthenticode.AcceptsSigner(status, "ABCDEF0123456789", Pin, allowUntrustedRoot: true));
        Assert.False(AgentUpdateAuthenticode.AcceptsStatus(status, allowUntrustedRoot: true));
    }
}
