using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;

namespace Cerberus.Agent.App.Legal;

/// <summary>Read-only HKLM acceptance; only a protected registry chain may authorize installation.</summary>
internal static class MsiMachineConsent
{
    private static readonly string[] ValueNames =
        ["accepted", "product", "eulaVersion", "privacyNoticeVersion", "securityDisclosureVersion", "acceptedVia", "acceptanceEvidence"];

    internal static bool TryReadCurrent(string path, Func<IReadOnlyDictionary<string, string?>, bool> matches)
    {
        try
        {
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            bool TrustedKey(string relative)
            {
                using var key = hklm.OpenSubKey(relative, writable: false);
                return key is not null && IsTrusted(key.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access));
            }
            IReadOnlyDictionary<string, string?>? ReadValues(string relative)
            {
                using var key = hklm.OpenSubKey(relative, writable: false);
                if (key is null || !IsTrusted(key.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access))) return null;
                var values = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
                foreach (var name in ValueNames) values[name] = key.GetValue(name)?.ToString();
                return values;
            }
            return CheckChainAndRead(path, TrustedKey, ReadValues, matches);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException or ArgumentException or InvalidOperationException or PlatformNotSupportedException)
        {
            return false;
        }
    }

    internal static bool CheckChainAndRead(string path, Func<string, bool> trusted,
        Func<string, IReadOnlyDictionary<string, string?>?> readValues, Func<IReadOnlyDictionary<string, string?>, bool> matches)
    {
        var parts = path.Split('\\', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0) return false;
        var accumulated = "";
        foreach (var part in parts)
        {
            accumulated = accumulated.Length == 0 ? part : accumulated + "\\" + part;
            if (!trusted(accumulated)) return false;
        }
        var values = readValues(accumulated);
        return values is not null && matches(values);
    }

    internal static bool IsTrusted(RegistrySecurity security)
        => IsTrusted(new RawSecurityDescriptor(security.GetSecurityDescriptorBinaryForm(), 0));

    internal static bool IsTrusted(RawSecurityDescriptor descriptor)
    {
        static bool Trusted(SecurityIdentifier? sid) => sid?.Value is
            "S-1-5-18" or "S-1-5-32-544" or "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
        if (!Trusted(descriptor.Owner) || descriptor.DiscretionaryAcl is null ||
            (descriptor.ControlFlags & ControlFlags.DiscretionaryAclPresent) == 0) return false;
        // Registry rights: SET_VALUE, CREATE_SUB_KEY, CREATE_LINK, DELETE, WRITE_DAC, WRITE_OWNER, GENERIC_WRITE, GENERIC_ALL.
        const uint forbidden = 0x500D0026;
        foreach (GenericAce ace in descriptor.DiscretionaryAcl)
        {
            if (ace is not QualifiedAce qualified) return false;
            if (qualified.AceQualifier == AceQualifier.AccessDenied) continue;
            if ((qualified.AceFlags & AceFlags.InheritOnly) != 0) continue;
            if (qualified.AceQualifier != AceQualifier.AccessAllowed || qualified.IsCallback) return false;
            if (!Trusted(qualified.SecurityIdentifier) && (unchecked((uint)qualified.AccessMask) & forbidden) != 0) return false;
        }
        return true;
    }
}
