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
}
