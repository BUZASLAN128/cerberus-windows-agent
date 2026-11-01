using Cerberus.Agent.App.Actions;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentServiceLocalStateTests
{
    [Fact]
    public void LocalRemovalClearsBothTelemetryBuffersAndProductSpecificProtectedState()
    {
        var parent = Path.GetFullPath(Path.GetTempPath());
        var root = Path.Combine(parent, "cerberus-local-removal-" + Guid.NewGuid().ToString("N"));
        var privileged = Path.Combine(root, "Privileged");
        var updates = Path.Combine(root, "updates");
        Directory.CreateDirectory(privileged);
        Directory.CreateDirectory(updates);
        try
        {
            foreach (var name in new[] { "idempotency.json", "telemetry-offline.json", "secondary-telemetry-offline.json" })
                File.WriteAllText(Path.Combine(root, name), "owned fixture");
            foreach (var name in new[] { "secondary-command-envelopes.v1.json", "secondary-agent-state.v1.json",
                         "secondary-agent-state.v1.json.seq", "secondary-agent-state.v1.json.enrollment-cleanup" })
                File.WriteAllText(Path.Combine(privileged, name), "owned fixture");
            File.WriteAllText(Path.Combine(updates, "owned.json"), "owned fixture");
            var unrelated = Path.Combine(root, "unrelated.txt");
            File.WriteAllText(unrelated, "keep");

            AgentServiceLocalState.ClearLocalData(root, privileged);

            Assert.False(File.Exists(Path.Combine(root, "secondary-telemetry-offline.json")));
            Assert.False(File.Exists(Path.Combine(root, "telemetry-offline.json")));
            Assert.False(File.Exists(Path.Combine(root, "idempotency.json")));
            Assert.False(Directory.Exists(privileged));
            Assert.False(Directory.Exists(updates));
            Assert.Equal("keep", File.ReadAllText(unrelated));
            AgentServiceLocalState.ClearLocalData(root, privileged); // Repeated removal remains harmless.
            Assert.Equal("keep", File.ReadAllText(unrelated));
        }
        finally
        {
            var resolved = Path.GetFullPath(root);
            Assert.Equal(parent.TrimEnd(Path.DirectorySeparatorChar), Path.GetDirectoryName(resolved), ignoreCase: true);
            if (Directory.Exists(resolved)) Directory.Delete(resolved, recursive: true);
        }
    }
}
