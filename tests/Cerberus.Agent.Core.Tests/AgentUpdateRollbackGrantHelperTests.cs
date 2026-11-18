using System.Text.Json;
using Cerberus.Agent.Core;
using InstallerHelper = Cerberus.Agent.Installer.Helper.Program;

namespace Cerberus.Agent.Core.Tests
{
    public sealed class AgentUpdateRollbackGrantHelperTests
    {
        [Theory]
        [InlineData("bad_argument_count", 1603, "denied", "grant_parse")]
        [InlineData("write_failure", 1603, null, null)]
        [InlineData("non_system", 1603, null, null)]
        [InlineData("admitted", 0, "admitted", "grant_accepted")]
        public void RequireRollbackGrantMapsExitCodeAndReceipt(string scenario, int expectedCode, string? expectedResult, string? expectedReason)
        {
            Assert.True(OperatingSystem.IsWindows());
            Assert.False(AgentUpdateSecurity.IsUnderDirectory(Path.GetTempPath(),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)));
            var root = Directory.CreateTempSubdirectory("rollback-grant-mapping-");
            try
            {
                var product = Guid.NewGuid();
                var args = new[] { "require-rollback-grant", product.ToString("B"), "unused", "1.1.0", "", "", "", "test-attempt", "unused.msi" };
                if (scenario == "bad_argument_count") Array.Resize(ref args, 8);
                var admissions = 0;
                var writes = 0;
                var code = InstallerHelper.InvokeRequireRollbackGrant(args, root.FullName, scenario != "non_system",
                    () => { admissions++; return AgentUpdateRollbackGrantResult.Accepted; },
                    (resultProduct, result, now) =>
                    {
                        writes++;
                        Assert.Equal(product, resultProduct);
                        if (scenario == "write_failure") throw new IOException("Test receipt write failure.");
                        AgentUpdateRollbackGrant.WriteResultRecord(root.FullName, root.FullName, resultProduct, result, now);
                    });

                Assert.Equal(expectedCode, code);
                Assert.Equal(scenario is "admitted" or "write_failure" ? 1 : 0, admissions);
                Assert.Equal(scenario == "non_system" ? 0 : 1, writes);
                var path = Path.Combine(root.FullName, $"{product:N}.rollback-grant.json");
                Assert.Equal(expectedResult is not null, File.Exists(path));
                if (expectedResult is null) return;
                using var receipt = JsonDocument.Parse(File.ReadAllText(path));
                Assert.Equal(expectedResult, receipt.RootElement.GetProperty("result").GetString());
                Assert.Equal(expectedReason, receipt.RootElement.GetProperty("reason_code").GetString());
            }
            finally { root.Delete(recursive: true); }
        }
    }
}

namespace Cerberus.Agent.Installer.Helper
{
    // Program.Lkg.cs is linked into this test assembly. These nested doubles bind only in that assembly.
    internal static partial class Program
    {
        private sealed record GrantMapping(string Root, bool IsSystem, Func<AgentUpdateRollbackGrantResult> Consume,
            Action<Guid, AgentUpdateRollbackGrantResult, DateTimeOffset> WriteResult);

        [ThreadStatic] private static GrantMapping? _grantMapping;

        internal static int InvokeRequireRollbackGrant(string[] args, string root, bool isSystem,
            Func<AgentUpdateRollbackGrantResult> consume, Action<Guid, AgentUpdateRollbackGrantResult, DateTimeOffset> writeResult)
        {
            _grantMapping = new GrantMapping(root, isSystem, consume, writeResult);
            try { return RequireRollbackGrant(args); }
            finally { _grantMapping = null; }
        }

        private static class AgentUpdateSecurity
        {
            public static bool IsLocalSystem() => _grantMapping!.IsSystem;
            public static string DefaultPrivilegedRoot => _grantMapping!.Root;
        }

        private static class AgentUpdateRollbackGrant
        {
            public static AgentUpdateRollbackGrantResult Consume(string root, bool serverProfile, Guid product, string version,
                string detectedNewerProducts, string attemptId, string originalDatabase) => _grantMapping!.Consume();

            public static void WriteResult(string root, Guid product, AgentUpdateRollbackGrantResult result, DateTimeOffset now)
                => _grantMapping!.WriteResult(product, result, now);
        }
    }
}
