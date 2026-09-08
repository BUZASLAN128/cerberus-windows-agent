using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentUiContextStoreTests
{
    [Fact]
    public async Task RegistrationContextDoesNotCreateMachineNamespaceAndWritesAfterProvisioning()
    {
        var root = Path.Combine(Path.GetTempPath(), "cerberus-ui-context-" + Guid.NewGuid().ToString("N"));
        var userPath = Path.Combine(root, "user", "ui-context.json");
        var machinePath = Path.Combine(root, "machine", "ui-context.json");
        var identity = new AgentIdentity("test-agent", "test-tenant");
        try
        {
            await AgentUiContextStore.WriteBestEffortAsync(identity, "Workspace", "Account", CancellationToken.None, userPath, machinePath);
            Assert.False(Directory.Exists(Path.GetDirectoryName(machinePath)));
            using var user = JsonDocument.Parse(await File.ReadAllTextAsync(userPath));
            Assert.Equal(identity.AgentId, user.RootElement.GetProperty("agentId").GetString());
            Assert.Equal("Workspace", user.RootElement.GetProperty("tenantName").GetString());

            // The installer owns provisioning. This temporary fixture proves only writer behavior, not trusted ACLs.
            Directory.CreateDirectory(Path.GetDirectoryName(machinePath)!);
            await AgentUiContextStore.WriteBestEffortAsync(identity, "Workspace", "Account", CancellationToken.None, userPath, machinePath);
            Assert.Equal(await File.ReadAllTextAsync(userPath), await File.ReadAllTextAsync(machinePath));
        }
        finally
        {
            if (File.Exists(userPath)) File.Delete(userPath);
            if (File.Exists(machinePath)) File.Delete(machinePath);
            if (Directory.Exists(Path.GetDirectoryName(userPath))) Directory.Delete(Path.GetDirectoryName(userPath)!);
            if (Directory.Exists(Path.GetDirectoryName(machinePath))) Directory.Delete(Path.GetDirectoryName(machinePath)!);
            if (Directory.Exists(root)) Directory.Delete(root);
        }
    }
}
