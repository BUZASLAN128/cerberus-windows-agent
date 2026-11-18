using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentUpdateRollbackGrantTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-11-18T15:30:00Z");
    private static readonly Guid InstalledProduct = Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
    private static readonly Guid TargetProduct = Guid.Parse("cccccccc-cccc-cccc-cccc-cccccccccccc");
    private const string Boot = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private static readonly string Hash = new('a', 64);

    private static AgentUpdateRollbackGrantRecord ValidGrant => new(AgentUpdateRollbackGrant.Schema, Guid.NewGuid(),
        "rollback-attempt", "watched-attempt", InstalledProduct, TargetProduct, "1.1.0", Hash,
        Now.AddMinutes(-10), Now.AddMinutes(10), Boot);

    [Fact]
    public void DesktopProfileCannotEnterTheGrantReader()
    {
        Assert.True(OperatingSystem.IsWindows());
        var result = AgentUpdateRollbackGrant.Consume("", false, TargetProduct, "1.1.0", "", "", "");
        Assert.False(result.Allowed);
        Assert.Equal("grant_profile", result.ReasonCode);
    }

    [Fact]
    public void GrantWireFormatRejectsDuplicateAndUnknownFields()
    {
        var json = JsonSerializer.Serialize(ValidGrant, AgentUpdateLkgStore.RecordJson);
        Assert.Contains("\"target_msi_sha256\"", json);
        Assert.Equal(AgentUpdateRollbackGrant.Schema,
            JsonSerializer.Deserialize<AgentUpdateRollbackGrantRecord>(json, AgentUpdateLkgStore.RecordJson)!.Schema);
        var duplicate = json.Insert(1, "\"schema\":\"wrong\",");
        var unknown = json.Insert(1, "\"unexpected\":0,");
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<AgentUpdateRollbackGrantRecord>(duplicate, AgentUpdateLkgStore.RecordJson));
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<AgentUpdateRollbackGrantRecord>(unknown, AgentUpdateLkgStore.RecordJson));
    }

    [Fact]
    public void ValidGrantRequiresSuccessfulConsumptionAndCannotBeUsedTwice()
    {
        using var fixture = new GrantIoFixture();
        fixture.Prepare();
        Assert.True(File.Exists(fixture.GrantPath));

        Assert.Equal(AgentUpdateRollbackGrantResult.Accepted, fixture.Consume(fixture.Store.MsiPath));
        Assert.False(File.Exists(fixture.GrantPath));
        Assert.Equal(AgentUpdateRollbackGrantResult.Denied("grant_path"), fixture.Consume(fixture.Store.MsiPath));
    }

    [Theory]
    [InlineData("missing_file", "grant_path")]
    [InlineData("wrong_dacl", "grant_path")]
    [InlineData("malformed_json", "grant_parse")]
    [InlineData("desktop_profile", "grant_profile")]
    [InlineData("other_path", "grant_msi_hash")]
    [InlineData("different_case", "grant_msi_hash")]
    [InlineData("short_spelling", "grant_msi_hash")]
    public void GrantFileDenialsRetainTheGrantAndRecordTheReason(string failure, string expected)
    {
        using var fixture = new GrantIoFixture();
        fixture.Prepare(failure);
        var originalDatabase = failure switch
        {
            "other_path" => Path.Combine(fixture.Store.Root, "other.msi"),
            "different_case" => Path.Combine(fixture.Store.Root, "AGENT.MSI"),
            // Use the spelling independently of the volume's 8.3 name creation policy.
            "short_spelling" => Path.Combine(Path.GetDirectoryName(fixture.Store.UpdatesRoot)!, "CANONI~1", "lkg", "agent.msi"),
            _ => fixture.Store.MsiPath,
        };
        if (failure == "other_path")
            File.Copy(fixture.Store.MsiPath, originalDatabase);

        var result = fixture.Consume(originalDatabase, serverProfile: failure != "desktop_profile");

        Assert.Equal(AgentUpdateRollbackGrantResult.Denied(expected), result);
        Assert.Equal(failure != "missing_file", File.Exists(fixture.GrantPath));
        AssertDeniedReceipt(fixture.Store.UpdatesRoot, result, expected);
    }

    [Theory]
    [InlineData("missing", "grant_schema")]
    [InlineData("schema", "grant_schema")]
    [InlineData("empty_id", "grant_schema")]
    [InlineData("expired", "grant_expired")]
    [InlineData("future_issued", "grant_expired")]
    [InlineData("long_window", "grant_expired")]
    [InlineData("boot", "grant_boot_id")]
    [InlineData("version", "grant_version")]
    [InlineData("target_product", "grant_product_code")]
    [InlineData("replaced_product", "grant_product_code")]
    [InlineData("attempt", "grant_attempt_id")]
    [InlineData("hash", "grant_msi_hash")]
    [InlineData("floor", "grant_floor")]
    [InlineData("missing_floor", "grant_floor")]
    [InlineData("corrupt_floor", "grant_floor")]
    [InlineData("delete", "grant_consume")]
    public void BadGrantCannotAdmitAndTheReceiptContainsOnlyItsResultAndReason(string failure, string expected)
    {
        var grant = ValidGrant;
        AgentUpdateRollbackGrantRecord? candidate = failure switch
        {
            "missing" => null,
            "schema" => grant with { Schema = "wrong" },
            "empty_id" => grant with { GrantId = Guid.Empty },
            "expired" => grant with { ExpiresUtc = Now },
            "future_issued" => grant with { IssuedUtc = Now.AddMinutes(1) },
            "long_window" => grant with { ExpiresUtc = Now.AddHours(1) },
            _ => grant,
        };
        var consumes = 0;
        var result = AgentUpdateRollbackGrant.ValidateAndConsume(candidate,
            failure == "target_product" ? Guid.Empty : TargetProduct, failure == "version" ? "2.0.0" : "1.1.0",
            failure == "replaced_product" ? TargetProduct.ToString("B") : InstalledProduct.ToString("B"),
            failure == "attempt" ? "some-other-attempt" : "rollback-attempt", Now,
            () => failure == "boot" ? Guid.NewGuid().ToString("N") : Boot,
            () => failure == "hash" ? new string('b', 64) : Hash,
            () => failure == "corrupt_floor" ? throw new JsonException() : failure == "missing_floor" ? null :
                Floor(failure == "floor" ? "1.2.0" : "1.1.0"),
            () => { consumes++; return failure != "delete"; });
        Assert.False(result.Allowed);
        Assert.Equal(expected, result.ReasonCode);
        Assert.Equal(failure == "delete" ? 1 : 0, consumes);

        var root = Directory.CreateTempSubdirectory("rollback-grant-test-");
        try { AssertDeniedReceipt(root.FullName, result, expected); }
        finally { root.Delete(recursive: true); }
    }

    [Theory]
    [InlineData("O:SYG:SYD:P(A;;FA;;;SY)", true)]
    [InlineData("O:BAG:SYD:P(A;;FA;;;SY)", false)]
    [InlineData("O:SYG:SYD:(A;;FA;;;SY)", false)]
    [InlineData("O:SYG:SYD:P(A;ID;FA;;;SY)", false)]
    [InlineData("O:SYG:SYD:P(A;;FA;;;SY)(A;;FR;;;BA)", false)]
    [InlineData("O:SYG:SYD:P(A;;FR;;;SY)", false)]
    public void ChecksTheExactSystemOnlyOwnerAndDacl(string sddl, bool accepted)
    {
        Assert.True(OperatingSystem.IsWindows());
        Assert.Equal("O:SYG:SYD:P(A;;FA;;;SY)", AgentUpdateRollbackGrant.Descriptor);
        Assert.Equal(accepted, AgentUpdateRollbackGrant.HasRequiredDescriptor(new RawSecurityDescriptor(sddl)));
    }

    private static void AssertDeniedReceipt(string root, AgentUpdateRollbackGrantResult result, string expected)
    {
        AgentUpdateRollbackGrant.WriteResultRecord(root, root, TargetProduct, result, Now);
        using var receipt = JsonDocument.Parse(File.ReadAllText(Path.Combine(root, $"{TargetProduct:N}.rollback-grant.json")));
        Assert.Equal(new[] { "result", "reason_code", "utc" }, receipt.RootElement.EnumerateObject().Select(p => p.Name));
        Assert.Equal("denied", receipt.RootElement.GetProperty("result").GetString());
        Assert.Equal(expected, receipt.RootElement.GetProperty("reason_code").GetString());
        Assert.Equal(Now, receipt.RootElement.GetProperty("utc").GetDateTimeOffset());
    }

    private static AgentUpdateRollbackFloorRecord Floor(string version)
        => new(AgentUpdateRollbackFloor.Schema, version, "watch_pass", 12, Hash, Now);

    private sealed class GrantIoFixture : IDisposable
    {
        private readonly DirectoryInfo _root;
        private readonly SecurityIdentifier _user;

        internal GrantIoFixture()
        {
            Assert.True(OperatingSystem.IsWindows());
            using var identity = WindowsIdentity.GetCurrent();
            Assert.False(identity.IsSystem);
            _user = identity.User!;
            Assert.False(AgentUpdateSecurity.IsUnderDirectory(Path.GetTempPath(),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)));
            _root = Directory.CreateTempSubdirectory("rollback-grant-io-");
            Store = new AgentUpdateLkgStore(Path.Combine(_root.FullName, "Canonical Updates"));
        }

        internal AgentUpdateLkgStore Store { get; }
        internal string GrantPath => Path.Combine(Store.Root, AgentUpdateRollbackGrant.FileName);

        internal void Prepare(string? failure = null)
        {
            Directory.CreateDirectory(Store.Root);
            var payload = "temporary payload, never run as an installer"u8.ToArray();
            File.WriteAllBytes(Store.MsiPath, payload);
            Assert.True(AgentUpdateRollbackFloor.Raise(Store.UpdatesRoot, "1.1.0", "watch_pass", 12, Hash, Now));
            if (failure == "missing_file") return;

            var now = DateTimeOffset.UtcNow;
            var grant = ValidGrant with
            {
                TargetMsiSha256 = Convert.ToHexStringLower(SHA256.HashData(payload)),
                IssuedUtc = now.AddMinutes(-10),
                ExpiresUtc = now.AddMinutes(10),
                IssuedBootId = AgentUpdateBootIdentity.Read(),
            };
            File.WriteAllText(GrantPath, failure == "malformed_json" ? "{" : JsonSerializer.Serialize(grant, AgentUpdateLkgStore.RecordJson));
            var security = new FileSecurity();
            security.SetOwner(_user);
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            security.AddAccessRule(new FileSystemAccessRule(_user, FileSystemRights.FullControl, AccessControlType.Allow));
            if (failure == "wrong_dacl")
                security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                    FileSystemRights.Read, AccessControlType.Allow));
            new FileInfo(GrantPath).SetAccessControl(security);
        }

        internal AgentUpdateRollbackGrantResult Consume(string originalDatabase, bool serverProfile = true)
            => AgentUpdateRollbackGrant.ConsumeCore(Store.UpdatesRoot, serverProfile, TargetProduct, "1.1.0",
                $"{{{Guid.NewGuid():D}}};{InstalledProduct:B}", "rollback-attempt", originalDatabase, () => true,
                AgentUpdateSecurity.ValidateTrustedPath, _user.Value);

        public void Dispose() => _root.Delete(recursive: true);
    }
}
