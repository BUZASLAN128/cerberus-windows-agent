using System.Security.AccessControl;
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

    // Ordinary support tests feed the admission policy in memory. They do not mint a grant file.
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
        AgentUpdateRollbackGrantRecord? grant = ValidGrant;
        var calls = 0;
        AgentUpdateRollbackGrantResult Evaluate() => AgentUpdateRollbackGrant.ValidateAndConsume(grant, TargetProduct,
            "1.1.0", $"{{{Guid.NewGuid():D}}};{InstalledProduct:B}", "rollback-attempt", Now, () => Boot, () => Hash,
            () => Floor("1.1.0"), () => { calls++; grant = null; return true; });

        Assert.True(Evaluate().Allowed);
        Assert.False(Evaluate().Allowed);
        Assert.Equal(1, calls);
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
    [InlineData("path", "grant_msi_hash")]
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
            () => failure == "path" ? null : failure == "hash" ? new string('b', 64) : Hash,
            () => failure == "corrupt_floor" ? throw new JsonException() : failure == "missing_floor" ? null :
                Floor(failure == "floor" ? "1.2.0" : "1.1.0"),
            () => { consumes++; return failure != "delete"; });
        Assert.False(result.Allowed);
        Assert.Equal(expected, result.ReasonCode);
        Assert.Equal(failure == "delete" ? 1 : 0, consumes);

        var root = Directory.CreateTempSubdirectory("rollback-grant-test-");
        try
        {
            AgentUpdateRollbackGrant.WriteResultRecord(root.FullName, root.FullName, TargetProduct, result, Now);
            using var receipt = JsonDocument.Parse(File.ReadAllText(Path.Combine(root.FullName, $"{TargetProduct:N}.rollback-grant.json")));
            Assert.Equal(new[] { "result", "reason_code", "utc" }, receipt.RootElement.EnumerateObject().Select(p => p.Name));
            Assert.Equal("denied", receipt.RootElement.GetProperty("result").GetString());
            Assert.Equal(expected, receipt.RootElement.GetProperty("reason_code").GetString());
            Assert.Equal(Now, receipt.RootElement.GetProperty("utc").GetDateTimeOffset());
        }
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

    private static AgentUpdateRollbackFloorRecord Floor(string version)
        => new(AgentUpdateRollbackFloor.Schema, version, "watch_pass", 12, Hash, Now);
}
