using System.DirectoryServices.Protocols;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Cerberus.Agent.Integrations.Ad;

namespace Cerberus.Agent.Core.Tests;

// Native request construction and policy support only. The fake transport never opens a network connection.
public sealed class WindowsAdDirectoryBoundaryTests
{
    private const string DomainSid = "S-1-5-21-11-22-33";
    private static readonly AdScope Scope = new(Guid.NewGuid().ToString("D"), "dc.example.test", Guid.NewGuid(), Guid.NewGuid(),
        "example.test", DomainSid + "-1100", true, true);
    private static readonly AdMachineEvidence Machine = new(true, 3, 0x01000000, Scope.DomainGuid, "example.test", "MEMBER");

    [Fact]
    public void NativeRequests_CreateDisabled_HonorPasswordPolicy_AndDeleteOnlyGuidLeaf()
    {
        var transport = new Transport();
        using var session = new AdLdapDirectorySession(Scope, transport, () => Machine);
        var created = session.CreateDisabled("cerb_test");
        Assert.True(created.Disabled);
        Assert.Equal(Scope.OuGuid, created.ParentGuid);
        var add = Assert.IsType<AddRequest>(Assert.Single(transport.Mutations));
        Assert.Equal("CN=cerb_test,OU=Selected,DC=example,DC=test", add.DistinguishedName);
        Assert.Equal(new[] { "objectClass", "sAMAccountName", "userAccountControl", "description" },
            add.Attributes.Cast<DirectoryAttribute>().Select(a => a.Name).ToArray());
        Assert.Equal("514", add.Attributes[2][0]);
        session.InitializePassword(created.Identity, "cerb_test", "Offline-Generated-Password-Only-29!");
        Assert.True(transport.PasswordEncodedAsQuotedUtf16);
        Assert.True(session.Read(created.Identity.ObjectGuid)!.Disabled);
        session.SetDisabled(created.Identity, "cerb_test", false);
        Assert.False(session.Read(created.Identity.ObjectGuid)!.Disabled);
        Assert.Equal("ad_disable_before_delete", Assert.Throws<AdOperationDeniedException>(() => session.DeleteLeaf(created.Identity, "cerb_test")).Code);
        session.SetDisabled(created.Identity, "cerb_test", true);
        session.DeleteLeaf(created.Identity, "cerb_test");
        Assert.Null(transport.User);
        Assert.All(transport.Mutations.Skip(1), request =>
        {
            var dn = request switch { ModifyRequest modify => modify.DistinguishedName, DeleteRequest delete => delete.DistinguishedName, _ => "invalid" };
            Assert.Equal(AdLdapDirectorySession.GuidDn(created.Identity.ObjectGuid), dn);
            Assert.Empty(request.Controls.Cast<DirectoryControl>());
        });
        Assert.Single(transport.Mutations.OfType<DeleteRequest>());
    }

    [Theory]
    [InlineData("moved")]
    [InlineData("sid")]
    [InlineData("admin")]
    [InlineData("children")]
    [InlineData("groups_unavailable")]
    [InlineData("rename")]
    public void NativeDelete_RefusesChangedOwnershipScopeOrProtection(string change)
    {
        var transport = new Transport();
        using var session = new AdLdapDirectorySession(Scope, transport, () => Machine);
        var created = session.CreateDisabled("cerb_test");
        transport.Mutations.Clear();
        switch (change)
        {
            case "moved": transport.InSelectedOu = false; break;
            case "sid": transport.UserSid = DomainSid + "-1201"; break;
            case "admin": transport.UserPrivileged = true; break;
            case "children": transport.HasChildren = true; break;
            case "groups_unavailable": transport.GroupsUnavailable = true; break;
            case "rename": transport.Username = "other"; break;
        }
        Assert.Throws<AdOperationDeniedException>(() => session.DeleteLeaf(created.Identity, "cerb_test"));
        Assert.Empty(transport.Mutations);
        Assert.NotNull(transport.User);
    }

    [Theory]
    [InlineData(0, "ad_not_domain_member")]
    [InlineData(2, "ad_not_domain_member")]
    [InlineData(4, "ad_domain_controller_denied")]
    [InlineData(5, "ad_domain_controller_denied")]
    public void MachineRole_DeniesStandaloneAndBothControllerRoles(int role, string code)
        => Assert.Equal(code, Assert.Throws<AdOperationDeniedException>(() => WindowsAdRuntime.Validate(Machine with { Role = role }, Scope)).Code);

    [Fact]
    public void MachineAndControllerIdentityMismatch_DeniesBeforeMutation()
    {
        Assert.Equal("ad_system_identity_required", Assert.Throws<AdOperationDeniedException>(() =>
            WindowsAdRuntime.Validate(Machine with { IsSystem = false }, Scope)).Code);
        Assert.Equal("ad_domain_mismatch", Assert.Throws<AdOperationDeniedException>(() =>
            WindowsAdRuntime.Validate(Machine with { DomainDnsName = "other.test" }, Scope)).Code);
        var transport = new Transport { ControllerMismatch = true };
        using var session = new AdLdapDirectorySession(Scope, transport, () => Machine);
        Assert.Equal("ad_controller_mismatch", Assert.Throws<AdOperationDeniedException>(() => session.CreateDisabled("cerb_test")).Code);
        Assert.Empty(transport.Mutations);
    }

    [Fact]
    public void ScopePolicy_BindsEnrollmentAndRequiresBothDelegationAttestations()
    {
        var identity = new AgentIdentity("agent", "tenant");
        var policy = new AdScopePolicyDocument(ProtectedAdScopePolicy.SchemaVersion, true, "tenant", "agent", [Scope]);
        Assert.Equal(Scope, Assert.Single(ProtectedAdScopePolicy.Decode(JsonSerializer.SerializeToUtf8Bytes(policy), identity)));
        Assert.Empty(ProtectedAdScopePolicy.Decode(JsonSerializer.SerializeToUtf8Bytes(policy with { Enabled = false }), identity));
        Assert.Throws<AdOperationDeniedException>(() => ProtectedAdScopePolicy.Decode(JsonSerializer.SerializeToUtf8Bytes(policy), identity with { TenantId = "other" }));
        Assert.Throws<AdOperationDeniedException>(() => ProtectedAdScopePolicy.Decode(JsonSerializer.SerializeToUtf8Bytes(policy with
            { Scopes = [Scope with { ExactOuDelegationAcknowledged = false }] }), identity));
        Assert.Throws<AdOperationDeniedException>(() => ProtectedAdScopePolicy.Decode(JsonSerializer.SerializeToUtf8Bytes(policy with
            { Scopes = [Scope with { NoBroadDirectoryPrivilegesAcknowledged = false }] }), identity));
    }

    [Fact]
    public void NativeCreate_DoesNotAdoptAReplacementAtTheSameDn()
    {
        var transport = new Transport { ReplaceAfterAdd = true };
        using var session = new AdLdapDirectorySession(Scope, transport, () => Machine);
        Assert.Equal("ad_create_readback_failed", Assert.Throws<AdOperationDeniedException>(() => session.CreateDisabled("cerb_test")).Code);
        Assert.IsType<AddRequest>(Assert.Single(transport.Mutations));
        Assert.NotNull(transport.User);
    }

    private sealed class Transport : IAdLdapConnection
    {
        public AdUserIdentity? User;
        public string UserSid = DomainSid + "-1200";
        public string Username = "cerb_test";
        public bool InSelectedOu = true;
        public bool UserPrivileged;
        public bool GroupsUnavailable;
        public bool HasChildren;
        public bool ControllerMismatch;
        public bool ReplaceAfterAdd;
        public bool PasswordEncodedAsQuotedUtf16;
        private string _description = "";
        private long _uac = 514;
        private bool _passwordSet;
        public List<DirectoryRequest> Mutations { get; } = [];

        public IReadOnlyList<AdLdapEntry> Search(SearchRequest request)
        {
            Assert.InRange(request.SizeLimit, 1, 2);
            Assert.True(request.TimeLimit <= TimeSpan.FromSeconds(10));
            if (request.DistinguishedName == "") return [Entry("", ("defaultNamingContext", "DC=example,DC=test"),
                ("dnsHostName", ControllerMismatch ? "other.example.test" : Scope.ControllerFqdn),
                ("supportedCapabilities", "1.2.840.113556.1.4.800"), ("isSynchronized", "TRUE"))];
            if (request.DistinguishedName == "DC=example,DC=test") return [Entry("DC=example,DC=test",
                ("objectGUID", Scope.DomainGuid.ToByteArray()), ("objectSid", BinarySid(DomainSid)), ("canonicalName", "example.test/"))];
            if (request.DistinguishedName == AdLdapDirectorySession.GuidDn(Scope.DomainGuid))
            {
                if (request.Filter.ToString()!.Contains("organizationalUnit")) return [Entry("OU=Selected,DC=example,DC=test",
                    ("objectGUID", Scope.OuGuid.ToByteArray()), ("objectClass", "organizationalUnit"))];
                return User is null ? [] : [UserEntry()];
            }
            if (request.DistinguishedName == "<SID=" + Scope.MachineAccountSid + ">") return [Entry("CN=MEMBER,DC=example,DC=test",
                ("objectSid", BinarySid(Scope.MachineAccountSid!)), ("sAMAccountName", "MEMBER$"),
                ("primaryGroupID", "515"), ("tokenGroups", BinarySid(DomainSid + "-515")))];
            if (request.DistinguishedName == AdLdapDirectorySession.GuidDn(Scope.OuGuid))
                return User is not null && InSelectedOu ? [UserEntry()] : [];
            if (User is not null && request.DistinguishedName == AdLdapDirectorySession.GuidDn(User.ObjectGuid) && request.Scope == SearchScope.OneLevel)
                return HasChildren ? [Entry("CN=child", ("objectGUID", Guid.NewGuid().ToByteArray()))] : [];
            if (User is not null && (request.DistinguishedName == AdLdapDirectorySession.GuidDn(User.ObjectGuid) || request.DistinguishedName.StartsWith("CN=cerb_test,")))
                return [UserEntry()];
            return [];
        }

        public void Mutate(DirectoryRequest request)
        {
            Mutations.Add(request);
            switch (request)
            {
                case AddRequest add:
                    Assert.Null(User);
                    User = new(Guid.NewGuid(), UserSid);
                    _description = ReplaceAfterAdd ? "Replacement account" : (string)add.Attributes[3][0];
                    break;
                case ModifyRequest modify:
                    if (modify.Modifications[0].Name == "unicodePwd")
                    {
                        var bytes = Assert.IsType<byte[]>(modify.Modifications[0][0]);
                        var value = Encoding.Unicode.GetString(bytes);
                        PasswordEncodedAsQuotedUtf16 = value.StartsWith('"') && value.EndsWith('"');
                        _passwordSet = true;
                    }
                    else
                    {
                        Assert.Equal("userAccountControl", modify.Modifications[0].Name);
                        Assert.Equal(DirectoryAttributeOperation.Delete, modify.Modifications[0].Operation);
                        Assert.Equal(_uac.ToString(), modify.Modifications[0][0]);
                        Assert.Equal(DirectoryAttributeOperation.Add, modify.Modifications[1].Operation);
                        _uac = long.Parse((string)modify.Modifications[1][0]);
                    }
                    break;
                case DeleteRequest:
                    Assert.True((_uac & 2) != 0);
                    User = null;
                    break;
                default: throw new InvalidOperationException("Unexpected mutation type");
            }
        }

        private AdLdapEntry UserEntry()
        {
            var entry = Entry("CN=cerb_test,OU=Selected,DC=example,DC=test",
                ("objectGUID", User!.ObjectGuid.ToByteArray()), ("objectSid", BinarySid(UserSid)),
                ("objectClass", "user"), ("sAMAccountName", Username), ("userAccountControl", _uac.ToString()),
                ("description", _description),
                ("primaryGroupID", "513"), ("pwdLastSet", _passwordSet ? "12345" : "0"));
            if (!GroupsUnavailable) ((Dictionary<string, byte[][]>)entry.Attributes).Add("tokenGroups", [BinarySid(DomainSid + (UserPrivileged ? "-512" : "-513"))]);
            return entry;
        }

        public void Dispose() { }
        private static AdLdapEntry Entry(string dn, params (string Name, object Value)[] values) =>
            new(dn, values.ToDictionary(v => v.Name, v => new[] { v.Value is byte[] bytes ? bytes : Encoding.UTF8.GetBytes((string)v.Value) }, StringComparer.OrdinalIgnoreCase));
        private static byte[] BinarySid(string value)
        {
            var sid = new SecurityIdentifier(value);
            var bytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(bytes, 0);
            return bytes;
        }
    }
}
