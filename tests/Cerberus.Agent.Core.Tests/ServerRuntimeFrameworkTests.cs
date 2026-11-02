using System.Diagnostics;
using System.Text.Json;

namespace Cerberus.Agent.Core.Tests;

public sealed class ServerRuntimeFrameworkTests
{
    [Theory]
    [InlineData("server", true)]
    [InlineData("desktop", false)]
    public void HelperCompressionKeepsExtractionDisabledForServer(string profile, bool compressed)
    {
        var project = Path.Combine(ServerPackageStaticTests.FindRepoRoot(), "src", "Cerberus.Agent.Installer", "Helper", "Cerberus.Agent.Installer.Helper.csproj");
        var run = ServerPackageStaticTests.RunPwsh($"dotnet msbuild '{project}' -nologo -p:AgentBuildProfile={profile} " +
            "-getProperty:EnableCompressionInSingleFile,IncludeNativeLibrariesForSelfExtract,IncludeAllContentForSelfExtract");
        Assert.True(run.ExitCode == 0, run.Output);
        using var json = JsonDocument.Parse(run.Output);
        var values = json.RootElement.GetProperty("Properties");
        Assert.Equal(compressed, values.GetProperty("EnableCompressionInSingleFile").GetString() == "true");
        Assert.Equal(!compressed, values.GetProperty("IncludeNativeLibrariesForSelfExtract").GetString() == "true");
        Assert.NotEqual("true", values.GetProperty("IncludeAllContentForSelfExtract").GetString());
    }

    [Theory]
    [InlineData("Service", "server", false)]
    [InlineData("Updater", "server", false)]
    [InlineData("Service", "desktop", true)]
    [InlineData("Updater", "desktop", true)]
    public async Task EvaluatedHostFrameworksMatchProfile(string host, string profile, bool needsDesktop)
    {
        var project = Path.Combine(ServerPackageStaticTests.FindRepoRoot(), "src", $"Cerberus.Agent.{host}", $"Cerberus.Agent.{host}.csproj");
        var start = new ProcessStartInfo("dotnet")
        {
            RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true,
        };
        foreach (var arg in new[] { "msbuild", project, "-nologo", $"-p:AgentBuildProfile={profile}", "-getItem:FrameworkReference" })
            start.ArgumentList.Add(arg);
        using var process = Process.Start(start)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        try { await process.WaitForExitAsync(timeout.Token); }
        catch (OperationCanceledException) { process.Kill(entireProcessTree: true); throw; }
        var output = await stdout;
        Assert.True(process.ExitCode == 0, output + await stderr);
        using var json = JsonDocument.Parse(output);
        var frameworks = json.RootElement.GetProperty("Items").GetProperty("FrameworkReference").EnumerateArray()
            .Select(x => x.GetProperty("Identity").GetString()!).ToArray();
        Assert.Contains("Microsoft.NETCore.App", frameworks);
        Assert.Equal(needsDesktop, frameworks.Any(x => x.StartsWith("Microsoft.WindowsDesktop.App", StringComparison.Ordinal)));
    }
}
