using System.DirectoryServices.Protocols;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;

namespace Cerberus.Agent.Integrations.Ad;

public sealed class WindowsAdDirectoryBoundary : IAdDirectoryBoundary
{
    public IAdDirectorySession Open(AdScope scope, CancellationToken ct = default)
    {
        ProtectedAdScopePolicy.ValidateScope(scope);
        var machine = WindowsAdRuntime.Read();
        WindowsAdRuntime.Validate(machine, scope);
        var connection = new AdLdapConnection(scope, ct);
        return new AdLdapDirectorySession(scope, connection, WindowsAdRuntime.Read);
    }
}

/// <summary>
/// GUID-targeted AD DS operations. Exact-OU-only delegation is an administrator prerequisite, not an inferred ACL grant.
/// AD exposes no verified atomic assertion for concurrent administrator moves or privilege edits; these reads are preconditions,
/// while directory ACLs must prevent mutation outside the selected OU. No name-only mutation fallback is permitted.
/// </summary>
internal sealed class AdLdapDirectorySession(AdScope scope, IAdLdapConnection connection,
    Func<AdMachineEvidence> readMachine) : IAdDirectorySession
{
    private static readonly string[] UserAttributes = ["objectGUID", "objectSid", "objectClass", "sAMAccountName",
        "userAccountControl", "adminCount", "isCriticalSystemObject", "primaryGroupID", "tokenGroups", "sIDHistory",
        "msDS-AllowedToDelegateTo", "pwdLastSet"];
    private string? _domainSid;
    private string? _ouDn;

    public void VerifyScope()
    {
        ProtectedAdScopePolicy.ValidateScope(scope);
        var machine = readMachine();
        WindowsAdRuntime.Validate(machine, scope);
        var root = ExactlyOne(Search("", SearchScope.Base, "(objectClass=*)",
            "defaultNamingContext", "dnsHostName", "supportedCapabilities", "isSynchronized"));
        if (!StringComparer.OrdinalIgnoreCase.Equals(Text(root, "dnsHostName"), scope.ControllerFqdn) ||
            !Texts(root, "supportedCapabilities").Contains("1.2.840.113556.1.4.800", StringComparer.Ordinal) ||
            !StringComparer.OrdinalIgnoreCase.Equals(Text(root, "isSynchronized"), "TRUE"))
            throw Denied("ad_controller_mismatch");
        var domainDn = Text(root, "defaultNamingContext");
        var domain = ExactlyOne(Search(domainDn, SearchScope.Base, "(objectClass=domainDNS)",
            "objectGUID", "objectSid", "canonicalName"));
        if (ObjectGuid(domain) != scope.DomainGuid ||
            !StringComparer.OrdinalIgnoreCase.Equals(Text(domain, "canonicalName"), scope.DomainDnsName + "/"))
            throw Denied("ad_domain_mismatch");
        _domainSid = Sid(domain, "objectSid");
        // A domain-root search establishes domain membership; a DN suffix is never used as authority.
        var ou = ExactlyOne(Search(GuidDn(scope.DomainGuid), SearchScope.Subtree,
            "(&(objectClass=organizationalUnit)(objectGUID=" + EscapeBinary(scope.OuGuid.ToByteArray()) + "))",
            "objectGUID", "objectClass"));
        if (ObjectGuid(ou) != scope.OuGuid || !Texts(ou, "objectClass").Contains("organizationalUnit", StringComparer.OrdinalIgnoreCase))
            throw Denied("ad_ou_mismatch");
        _ouDn = ou.DistinguishedName;
        var principal = ExactlyOne(Search("<SID=" + scope.MachineAccountSid + ">", SearchScope.Base, "(objectClass=computer)", UserAttributes));
        if (Sid(principal, "objectSid") != scope.MachineAccountSid ||
            !StringComparer.OrdinalIgnoreCase.Equals(Text(principal, "sAMAccountName"), machine.MachineName + "$") ||
            !SameDomainSid(scope.MachineAccountSid!) || IsProtected(principal, expectedPrimaryGroup: 515))
            throw Denied("ad_machine_principal_denied");
    }

    public AdUserState? FindUsername(string username)
    {
        ValidateUsername(username);
        VerifyScope();
        var found = Search(GuidDn(scope.DomainGuid), SearchScope.Subtree,
            "(sAMAccountName=" + EscapeText(username) + ")", "objectGUID", "objectSid", "sAMAccountName");
        if (found.Count == 0) return null;
        var entry = ExactlyOne(found);
        // Any existing object blocks creation, including a non-user with the same account name.
        return new(new(ObjectGuid(entry), OptionalSid(entry, "objectSid") ?? ""), Guid.Empty,
            Text(entry, "sAMAccountName"), true, true, false);
    }

    public AdUserState? Read(Guid objectGuid)
    {
        var entry = ReadEntry(objectGuid);
        if (entry is null) return null;
        var children = Search(GuidDn(objectGuid), SearchScope.OneLevel, "(objectClass=*)", "objectGUID");
        var inExactOu = Search(GuidDn(scope.OuGuid), SearchScope.OneLevel,
            "(objectGUID=" + EscapeBinary(objectGuid.ToByteArray()) + ")", "objectGUID");
        var classes = Texts(entry, "objectClass");
        var userClass = classes.Contains("user", StringComparer.OrdinalIgnoreCase) &&
            classes.All(c => c is "top" or "person" or "organizationalPerson" or "user");
        return new(new(ObjectGuid(entry), Sid(entry, "objectSid")),
            inExactOu.Count == 1 && ObjectGuid(inExactOu[0]) == objectGuid ? scope.OuGuid : Guid.Empty,
            Text(entry, "sAMAccountName"), (Number(entry, "userAccountControl") & 2) != 0,
            !SameDomainSid(Sid(entry, "objectSid")) || IsProtected(entry, expectedPrimaryGroup: 513), userClass && children.Count == 0);
    }

    public AdUserState CreateDisabled(string username)
    {
        ValidateUsername(username);
        VerifyScope();
        if (FindUsername(username) is not null) throw Denied("ad_unowned_collision");
        // The only caller-selected value is a constrained sAMAccountName. All location data came from the pinned server.
        var dn = "CN=" + username + "," + _ouDn;
        var creationCorrelation = "Cerberus creation " + Guid.NewGuid().ToString("N");
        connection.Mutate(new AddRequest(dn,
            new DirectoryAttribute("objectClass", "user"),
            new DirectoryAttribute("sAMAccountName", username),
            new DirectoryAttribute("userAccountControl", "514"),
            new DirectoryAttribute("description", creationCorrelation)));
        var created = ExactlyOne(Search(dn, SearchScope.Base, "(objectClass=user)",
            "objectGUID", "description", "sAMAccountName", "userAccountControl", "objectClass"));
        // Correlation is checked only against this successful Add. It never authorizes adoption on a later retry.
        if (Text(created, "description") != creationCorrelation ||
            !StringComparer.OrdinalIgnoreCase.Equals(Text(created, "sAMAccountName"), username) ||
            (Number(created, "userAccountControl") & 2) == 0 ||
            !Texts(created, "objectClass").Contains("user", StringComparer.OrdinalIgnoreCase))
            throw Denied("ad_create_readback_failed");
        var state = Read(ObjectGuid(created)) ?? throw Denied("ad_create_readback_failed");
        if (!state.Disabled || !StringComparer.OrdinalIgnoreCase.Equals(state.Username, username))
            throw Denied("ad_create_readback_failed");
        return state;
    }

    public void InitializePassword(AdUserIdentity identity, string username, string password)
    {
        var current = Guard(identity, username);
        if (!current.Disabled) throw Denied("ad_password_requires_disabled_user");
        if (string.IsNullOrEmpty(password) || password.Length is < 24 or > 256)
            throw Denied("ad_invalid_password_input");
        // The native AD password policy remains authoritative. No password policy or expiry flags are weakened.
        var bytes = Encoding.Unicode.GetBytes("\"" + password + "\"");
        var passwordChange = new DirectoryAttributeModification { Name = "unicodePwd", Operation = DirectoryAttributeOperation.Replace };
        passwordChange.Add(bytes);
        try
        {
            connection.Mutate(new ModifyRequest(GuidDn(identity.ObjectGuid), passwordChange));
        }
        finally { CryptographicOperations.ZeroMemory(bytes); passwordChange.Clear(); }
        var verified = Guard(identity, username);
        var entry = ReadEntry(identity.ObjectGuid) ?? throw Denied("ad_password_readback_failed");
        if (!verified.Disabled || Number(entry, "pwdLastSet") <= 0) throw Denied("ad_password_readback_failed");
    }

    public void SetDisabled(AdUserIdentity identity, string username, bool disabled)
    {
        Guard(identity, username);
        var current = ReadEntry(identity.ObjectGuid) ?? throw Denied("ad_owned_object_missing");
        var before = Number(current, "userAccountControl");
        var after = disabled ? before | 2 : before & ~2L;
        if (before == after) return;
        // Delete-old/add-new in one LDAP modify refuses concurrent UAC edits instead of overwriting their flags.
        var remove = new DirectoryAttributeModification { Name = "userAccountControl", Operation = DirectoryAttributeOperation.Delete };
        remove.Add(before.ToString(CultureInfo.InvariantCulture));
        var add = new DirectoryAttributeModification { Name = "userAccountControl", Operation = DirectoryAttributeOperation.Add };
        add.Add(after.ToString(CultureInfo.InvariantCulture));
        connection.Mutate(new ModifyRequest(GuidDn(identity.ObjectGuid), remove, add));
        if (Guard(identity, username).Disabled != disabled) throw Denied("ad_readback_failed");
    }

    public void DeleteLeaf(AdUserIdentity identity, string username)
    {
        var current = Guard(identity, username);
        if (!current.Disabled) throw Denied("ad_disable_before_delete");
        // DeleteRequest has LDAP leaf semantics. Never add a subtree-delete control or fall back to a mutable DN.
        connection.Mutate(new DeleteRequest(GuidDn(identity.ObjectGuid)));
        if (ReadEntry(identity.ObjectGuid) is not null) throw Denied("ad_readback_failed");
    }

    private AdUserState Guard(AdUserIdentity identity, string username)
    {
        ValidateUsername(username);
        VerifyScope();
        var current = Read(identity.ObjectGuid) ?? throw Denied("ad_owned_object_missing");
        if (current.Identity != identity || !StringComparer.OrdinalIgnoreCase.Equals(current.Username, username) ||
            current.ParentGuid != scope.OuGuid || current.Protected || !current.LeafUser)
            throw Denied("ad_object_guard_denied");
        return current;
    }

    private AdLdapEntry? ReadEntry(Guid objectGuid)
    {
        try
        {
            var results = Search(GuidDn(objectGuid), SearchScope.Base, "(objectClass=*)", UserAttributes);
            return results.Count == 0 ? null : ExactlyOne(results);
        }
        catch (AdOperationDeniedException ex) when (ex.Code == "ad_object_missing") { return null; }
    }

    private IReadOnlyList<AdLdapEntry> Search(string dn, SearchScope searchScope, string filter, params string[] attributes)
        => connection.Search(new SearchRequest(dn, filter, searchScope, attributes)
            { SizeLimit = 2, TimeLimit = TimeSpan.FromSeconds(10) });

    private bool SameDomainSid(string sid) => new SecurityIdentifier(sid).AccountDomainSid?.Value == _domainSid;

    private static bool IsProtected(AdLdapEntry entry, int expectedPrimaryGroup)
    {
        var accountSid = Sid(entry, "objectSid");
        if (!int.TryParse(accountSid[(accountSid.LastIndexOf('-') + 1)..], out var rid) || rid < 1000 ||
            OptionalNumber(entry, "adminCount") > 0 || OptionalText(entry, "isCriticalSystemObject")?.Equals("TRUE", StringComparison.OrdinalIgnoreCase) == true ||
            Number(entry, "primaryGroupID") != expectedPrimaryGroup || Values(entry, "sIDHistory", required: false).Length != 0 ||
            Values(entry, "msDS-AllowedToDelegateTo", required: false).Length != 0)
            return true;
        // tokenGroups is the DC-computed transitive security membership, including primary group. Unavailable is a denial.
        var groups = Values(entry, "tokenGroups");
        if (groups.Length == 0 || groups.Length > 1024) throw Denied("ad_group_protection_unavailable");
        return groups.Any(value => IsPrivilegedSid(DecodeSid(value)));
    }

    internal static bool IsPrivilegedSid(string sid)
    {
        if (!int.TryParse(sid[(sid.LastIndexOf('-') + 1)..], out var rid)) return true;
        return sid == "S-1-5-9" || sid.StartsWith("S-1-5-32-", StringComparison.Ordinal) && rid is 544 or 548 or 549 or 550 or 551 or 552 or 568 or 569 ||
            sid.StartsWith("S-1-5-21-", StringComparison.Ordinal) && rid is 512 or 516 or 518 or 519 or 520 or 521 or 522 or 525 or 526 or 527;
    }

    internal static string GuidDn(Guid guid)
        => guid == Guid.Empty ? throw Denied("ad_object_identity_invalid") : "<GUID=" + guid.ToString("D") + ">";
    private static string EscapeBinary(byte[] bytes) => string.Concat(bytes.Select(b => "\\" + b.ToString("x2", CultureInfo.InvariantCulture)));
    private static string EscapeText(string text) => EscapeBinary(Encoding.UTF8.GetBytes(text));
    private static void ValidateUsername(string username)
    {
        if (username is null || !Regex.IsMatch(username, "\\A[a-zA-Z][a-zA-Z0-9_-]{0,19}\\z"))
            throw Denied("ad_username_invalid");
    }
    private static AdLdapEntry ExactlyOne(IReadOnlyList<AdLdapEntry> entries)
        => entries.Count == 1 ? entries[0] : throw Denied("ad_directory_identity_ambiguous");
    private static byte[][] Values(AdLdapEntry entry, string name, bool required = true)
        => entry.Attributes.TryGetValue(name, out var values) ? values : required ? throw Denied("ad_directory_attribute_missing") : [];
    private static byte[] Single(AdLdapEntry entry, string name)
    {
        var values = Values(entry, name);
        return values.Length == 1 ? values[0] : throw Denied("ad_directory_attribute_invalid");
    }
    private static string Text(AdLdapEntry entry, string name) => Encoding.UTF8.GetString(Single(entry, name));
    private static string? OptionalText(AdLdapEntry entry, string name) => Values(entry, name, false).Length == 0 ? null : Text(entry, name);
    private static string[] Texts(AdLdapEntry entry, string name) => Values(entry, name).Select(Encoding.UTF8.GetString).ToArray();
    private static long Number(AdLdapEntry entry, string name) => long.TryParse(Text(entry, name), NumberStyles.Integer,
        CultureInfo.InvariantCulture, out var value) ? value : throw Denied("ad_directory_attribute_invalid");
    private static long OptionalNumber(AdLdapEntry entry, string name) => Values(entry, name, false).Length == 0 ? 0 : Number(entry, name);
    private static Guid ObjectGuid(AdLdapEntry entry) => Single(entry, "objectGUID").Length == 16 ?
        new Guid(Single(entry, "objectGUID")) : throw Denied("ad_object_identity_invalid");
    private static string Sid(AdLdapEntry entry, string name)
        => DecodeSid(Single(entry, name));
    private static string DecodeSid(byte[] value)
    {
        try { return new SecurityIdentifier(value, 0).Value; }
        catch (ArgumentException) { throw Denied("ad_object_identity_invalid"); }
    }
    private static string? OptionalSid(AdLdapEntry entry, string name) => Values(entry, name, false).Length == 0 ? null : Sid(entry, name);
    private static AdOperationDeniedException Denied(string code) => new(code);
    public void Dispose() => connection.Dispose();
}
