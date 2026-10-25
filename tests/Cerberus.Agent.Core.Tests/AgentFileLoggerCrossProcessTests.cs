using System.Diagnostics;
using System.Runtime.Versioning;
using Cerberus.Agent.Observability;

namespace Cerberus.Agent.Core.Tests;

// A second process holds the log mutex name; the logger must wait for it and write once it is released.
[SupportedOSPlatform("windows")]
public sealed class AgentFileLoggerCrossProcessTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_dir))
                Directory.Delete(_dir, recursive: true);
        }
        catch (IOException)
        {
            // Best-effort cleanup of the per-test temp directory.
        }
    }

    private static string ReadShared(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    [Fact]
    public void LoggerWaitsForMutexHeldByAnotherProcess_ThenWritesAfterRelease()
    {
        var path = Path.Combine(_dir, "agent.log");
        Directory.CreateDirectory(_dir);
        var name = AgentLogMutex.NameFor(path);

        var script = $"$m=[System.Threading.Mutex]::new($false,'{name}');$m.WaitOne()|Out-Null;[Console]::Out.WriteLine('held');[Console]::Out.Flush();[Console]::In.ReadLine()|Out-Null;$m.ReleaseMutex()";
        var startInfo = new ProcessStartInfo
        {
            FileName = "pwsh",
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            CreateNoWindow = true,
        };
        foreach (var argument in new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script })
            startInfo.ArgumentList.Add(argument);

        using var child = Process.Start(startInfo) ?? throw new InvalidOperationException("Could not start pwsh.");
        try
        {
            var held = child.StandardOutput.ReadLineAsync();
            Assert.True(held.Wait(TimeSpan.FromSeconds(30)), "child did not take the mutex");
            Assert.Equal("held", held.Result);

            using var logger = new AgentFileLogger(path, alsoConsole: false);
            var write = Task.Run(() => logger.Info("written-after-release"));

            // The logger waits up to 2 s for the mutex; it must not have written yet.
            Assert.False(write.Wait(TimeSpan.FromMilliseconds(500)), "write did not wait for the foreign holder");
            Assert.DoesNotContain("written-after-release", ReadShared(path), StringComparison.Ordinal);

            child.StandardInput.WriteLine();
            child.StandardInput.Flush();

            Assert.True(write.Wait(TimeSpan.FromSeconds(10)), "write did not finish after release");
            Assert.Contains("written-after-release", ReadShared(path), StringComparison.Ordinal);
            Assert.True(child.WaitForExit(30_000));
            Assert.Equal(0, child.ExitCode);
        }
        finally
        {
            if (!child.HasExited)
                child.Kill(entireProcessTree: true);
        }
    }
}
