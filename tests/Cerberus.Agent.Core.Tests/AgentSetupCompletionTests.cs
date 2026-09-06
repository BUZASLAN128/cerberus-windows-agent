using System.Diagnostics;
using Cerberus.Agent.App;
using Cerberus.Agent.App.Actions;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentSetupCompletionTests
{
    [Theory]
    [InlineData(0, true)]
    [InlineData(2, false)]
    [InlineData(null, false)]
    public async Task SetupServiceActionWaitsForProvisioningResultInsteadOfTreatingLaunchAsSuccess(int? exitCode, bool succeeded)
    {
        var completed = new TaskCompletionSource<int?>(TaskCreationOptions.RunContinuationsAsynchronously);
        var action = ServiceControlAction.RunElevatedAndWaitAsync(ServiceControlCommand.Install, (arguments, _) =>
        {
            Assert.Equal("--install-service", arguments);
            return completed.Task;
        }, default);
        Assert.False(action.IsCompleted);
        completed.SetResult(exitCode);
        var result = await action.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(succeeded, result.Succeeded);
        Assert.DoesNotContain("UAC prompt opened", result.Message);
        if (exitCode == 2)
            Assert.Contains("exit code 2", result.Message);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task TrackedProcessWaitObservesExitAndCancellationDoesNotKillProvisioning(bool cancelWait)
    {
        // Real disposable subprocess, no UAC, SCM, credentials or production paths.
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var stopped = CancellationTokenSource.CreateLinkedTokenSource(timeout.Token);
        using var child = Process.Start(new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe"),
            Arguments = "/d /q /c \"echo ready & set /p setup_test_input= & exit /b 2\"",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        })!;
        try
        {
            Assert.Equal("ready", (await child.StandardOutput.ReadLineAsync(timeout.Token))?.Trim());
            var waiting = Elevation.WaitForCompletionAsync(child, stopped.Token);
            Assert.False(waiting.IsCompleted);
            if (cancelWait)
            {
                stopped.Cancel();
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiting);
                Assert.False(child.HasExited);
            }
            await child.StandardInput.WriteLineAsync("complete");
            await child.StandardInput.FlushAsync(timeout.Token);
            await child.WaitForExitAsync(timeout.Token);
            Assert.Equal(2, child.ExitCode);
            if (!cancelWait)
                Assert.Equal(2, await waiting);
        }
        finally
        {
            // Only this test's disposable child may be terminated during failed-fixture cleanup.
            if (!child.HasExited)
            {
                child.Kill();
                await child.WaitForExitAsync();
            }
        }
    }
}
