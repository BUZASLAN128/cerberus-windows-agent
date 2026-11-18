using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Updater;

internal static class LkgProbe
{
    internal const string Schema = "agent.update.probe.v1";
    internal const string PassedLogMarker = "lkg_probe_passed";
    private const int MaxOutputChars = 4096;
    private static readonly string[] RequiredModes = ["attempt", "watch", "scm-failure", "probe"];
    private static readonly JsonSerializerOptions ResponseJson = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        RespectRequiredConstructorParameters = true,
        AllowDuplicateProperties = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        NumberHandling = JsonNumberHandling.Strict,
    };

    private sealed record Response(string Schema, string Nonce, string Version, string[] Modes, int Contract);

    internal static int WriteResponse(string nonce, TextWriter output)
        => WriteResponse(nonce, AgentProductVersion.Get(typeof(LkgProbe).Assembly), AgentUpdaterContract.VersionNumber, output);

    internal static int WriteResponse(string nonce, string version, int contract, TextWriter output)
    {
        if (!AgentUpdateSecurity.IsSafeAttemptId(nonce) || !AgentUpdateManifestValidator.IsReleaseVersion(version) ||
            contract <= 0)
            return 2;

        output.WriteLine(JsonSerializer.Serialize(new Response(Schema, nonce, version, RequiredModes, contract), ResponseJson));
        return 0;
    }

    internal static bool Accepts(string output, int exitCode, string nonce, string expectedVersion, int minimumContract)
    {
        if (exitCode != 0 || output.Length > MaxOutputChars || minimumContract <= 0)
            return false;

        var line = output.EndsWith('\n') ? output.AsSpan(0, output.Length - 1) : output.AsSpan();
        if (output.EndsWith('\n') && line.EndsWith("\r", StringComparison.Ordinal)) line = line[..^1];
        if (line.IndexOfAny('\r', '\n') >= 0) return false;

        try
        {
            var response = JsonSerializer.Deserialize<Response>(line, ResponseJson);
            return response is { Modes: not null } && response.Schema == Schema && response.Nonce == nonce &&
                   response.Version == expectedVersion && response.Contract >= minimumContract &&
                   RequiredModes.All(mode => response.Modes.Contains(mode, StringComparer.Ordinal));
        }
        catch (JsonException) { return false; }
    }

    /// <summary>The caller keeps the verified staged executable open for reading without delete/write sharing.</summary>
    internal static bool Run(string stagedUpdater, string expectedVersion)
    {
        var minimumContract = AgentUpdaterContract.VersionNumber;
        if (minimumContract <= 0) return false;

        var nonce = Guid.NewGuid().ToString("N");
        var start = new ProcessStartInfo(stagedUpdater)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            StandardOutputEncoding = Encoding.UTF8,
            WorkingDirectory = Path.GetDirectoryName(stagedUpdater)!,
        };
        start.ArgumentList.Add("--probe");
        start.ArgumentList.Add(nonce);

        return Run(start, nonce, expectedVersion, minimumContract, TimeSpan.FromSeconds(60));
    }

    internal static bool Run(ProcessStartInfo start, string nonce, string expectedVersion, int minimumContract, TimeSpan probeTimeout)
    {
        using var process = Process.Start(start);
        if (process is null) return false;
        using var timeout = new CancellationTokenSource(probeTimeout);
        var expired = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var terminate = timeout.Token.Register(() =>
        {
            TerminateChild(process);
            expired.TrySetResult(false);
        });
        var response = ReadResponseAsync(process, nonce, expectedVersion, minimumContract);
        if (Task.WhenAny(response, expired.Task).GetAwaiter().GetResult() == expired.Task)
            return false;
        try { return !timeout.IsCancellationRequested && response.GetAwaiter().GetResult(); }
        finally
        {
            TerminateChild(process);
        }
    }

    private static void TerminateChild(Process process)
    {
        try
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or AggregateException)
        {
            // The probe can exit concurrently with termination. The timed read still fails closed.
        }
    }

    private static async Task<bool> ReadResponseAsync(Process process, string nonce, string version, int minimumContract)
    {
        var buffer = new char[MaxOutputChars + 1];
        var count = await process.StandardOutput.ReadBlockAsync(buffer.AsMemory()).ConfigureAwait(false);
        if (count > MaxOutputChars) return false;
        await process.WaitForExitAsync().ConfigureAwait(false);
        return Accepts(new string(buffer, 0, count), process.ExitCode, nonce, version, minimumContract);
    }

}
