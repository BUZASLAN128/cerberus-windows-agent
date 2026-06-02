using System.Globalization;
using Cerberus.Agent.App.Localization;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentLocalizationTests
{
    [Theory]
    [InlineData("tr", AgentLocalizer.TurkishCultureName)]
    [InlineData("tr-TR", AgentLocalizer.TurkishCultureName)]
    [InlineData("en", AgentLocalizer.DefaultCultureName)]
    [InlineData("en-US", AgentLocalizer.DefaultCultureName)]
    [InlineData("de-DE", null)]
    [InlineData("auto", null)]
    public void NormalizeCulture_AllowsOnlySupportedLocales(string input, string? expected)
    {
        Assert.Equal(expected, AgentLocalizer.NormalizeCulture(input));
    }

    [Fact]
    public void Get_ReturnsEnglishFallbackAndTurkishOverride()
    {
        Assert.Equal("Ready to connect", AgentLocalizer.Get("ReadyToConnect", CultureInfo.GetCultureInfo("en-US")));
        Assert.Equal("Bağlanmaya hazır", AgentLocalizer.Get("ReadyToConnect", CultureInfo.GetCultureInfo("tr-TR")));
    }

    [Fact]
    public void UpdateCheckMessages_AreCustomerFacingAndLocalized()
    {
        var english = AgentLocalizer.Get("UpdateNotConfiguredDetail", CultureInfo.GetCultureInfo("en-US"));
        var turkish = AgentLocalizer.Get("UpdateNotConfiguredDetail", CultureInfo.GetCultureInfo("tr-TR"));

        Assert.Contains("Updates are not configured", english);
        Assert.Contains("güncellemeler yapılandırılmamış", turkish);
        Assert.Contains("No update was found", AgentLocalizer.Get("UpdateNotFoundDetail", CultureInfo.GetCultureInfo("en-US")));
        Assert.Contains("Güncelleme bulunamadı", AgentLocalizer.Get("UpdateNotFoundDetail", CultureInfo.GetCultureInfo("tr-TR")));
        Assert.Contains("Do you want to install it now", AgentLocalizer.Get("UpdateFoundPrompt", CultureInfo.GetCultureInfo("en-US")));
        Assert.Contains("Şimdi kurulsun mu", AgentLocalizer.Get("UpdateFoundPrompt", CultureInfo.GetCultureInfo("tr-TR")));
        Assert.DoesNotContain("Agent registration", english);
        Assert.DoesNotContain("Agent registration", turkish);
        Assert.DoesNotContain("{0}", AgentLocalizer.Get("UpdateCheckFailedDetail", CultureInfo.GetCultureInfo("en-US")));
        Assert.DoesNotContain("{0}", AgentLocalizer.Get("UpdateCheckFailedDetail", CultureInfo.GetCultureInfo("tr-TR")));
    }

    [Fact]
    public void ConnectorRepairLabels_DoNotExposeVendorNameToCustomers()
    {
        var englishCulture = CultureInfo.GetCultureInfo("en-US");
        var turkishCulture = CultureInfo.GetCultureInfo("tr-TR");

        Assert.Equal("Secure network", AgentLocalizer.Get("Tailscale", englishCulture));
        Assert.Equal("Güvenli ağ", AgentLocalizer.Get("Tailscale", turkishCulture));
        Assert.DoesNotContain("Tailscale", AgentLocalizer.Get("ExportTailscale", englishCulture));
        Assert.DoesNotContain("Tailscale", AgentLocalizer.Get("InstallTailscale", englishCulture));
        Assert.DoesNotContain("Tailscale", AgentLocalizer.Get("TailscaleUnavailableNote", englishCulture));
        Assert.DoesNotContain("Tailscale", AgentLocalizer.Get("ExportTailscale", turkishCulture));
        Assert.DoesNotContain("Tailscale", AgentLocalizer.Get("InstallTailscale", turkishCulture));
        Assert.DoesNotContain("Tailscale", AgentLocalizer.Get("TailscaleUnavailableNote", turkishCulture));
    }
}
