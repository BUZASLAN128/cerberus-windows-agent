using Cerberus.Agent.App;

namespace Cerberus.Agent.Core.Tests;

public sealed class TailscaleInstallerSafetyTests
{
    [Theory]
    [InlineData("https://pkgs.tailscale.com/stable/tailscale-setup-latest-amd64.msi")]
    [InlineData("https://pkgs.tailscale.com/stable/tailscale-setup-latest-x86.msi")]
    [InlineData("https://pkgs.tailscale.com/stable/tailscale-setup-latest-arm64.msi")]
    public void OfficialStableMsiUris_AreAllowedByDefault(string url)
    {
        var uri = new Uri(url);

        Assert.True(TailscaleInstaller.IsOfficialStableMsiUri(uri));
        Assert.True(TailscaleInstaller.IsAllowedDownloadUri(uri, allowCustomMirror: false));
    }

    [Theory]
    [InlineData("http://pkgs.tailscale.com/stable/tailscale-setup-latest-amd64.msi")]
    [InlineData("https://pkgs.tailscale.com/unstable/tailscale-setup-latest-amd64.msi")]
    [InlineData("https://pkgs.tailscale.com/stable/tailscale-setup-latest-amd64.exe")]
    [InlineData("https://example.com/tailscale-setup-latest-amd64.msi")]
    public void NonOfficialOrNonMsiUris_AreRejectedByDefault(string url)
    {
        Assert.False(TailscaleInstaller.IsAllowedDownloadUri(new Uri(url), allowCustomMirror: false));
    }

    [Fact]
    public void ManagedMirror_RequiresExplicitOptInAndMsi()
    {
        var mirror = new Uri("https://mirror.example.internal/tailscale-setup-latest-amd64.msi");
        var exeMirror = new Uri("https://mirror.example.internal/tailscale-setup-latest-amd64.exe");

        Assert.False(TailscaleInstaller.IsAllowedDownloadUri(mirror, allowCustomMirror: false));
        Assert.True(TailscaleInstaller.IsAllowedDownloadUri(mirror, allowCustomMirror: true));
        Assert.False(TailscaleInstaller.IsAllowedDownloadUri(exeMirror, allowCustomMirror: true));
    }

    [Theory]
    [InlineData("CN=Tailscale Inc., O=Tailscale Inc., L=Toronto, S=Ontario, C=CA")]
    [InlineData("O=Tailscale, CN=Tailscale")]
    public void TrustedSignerSubject_MustBeTailscale(string subject)
    {
        Assert.True(TailscaleInstaller.IsTrustedSignerSubject(subject));
    }

    [Theory]
    [InlineData("")]
    [InlineData("CN=Microsoft Corporation")]
    [InlineData("CN=Example Mirror Operator")]
    public void NonTailscaleSignerSubject_IsRejected(string subject)
    {
        Assert.False(TailscaleInstaller.IsTrustedSignerSubject(subject));
    }
}
