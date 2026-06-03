using Cerberus.Agent.Security;
using Microsoft.Win32;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;

namespace Cerberus.Agent.App.Legal;

internal enum LegalConsentScope
{
    User,
    Machine,
}

internal sealed record AgentLegalConsentRecord(
    string SchemaVersion,
    string Product,
    string EulaVersion,
    string PrivacyNoticeVersion,
    string SecurityDisclosureVersion,
    DateTimeOffset AcceptedAtUtc,
    string AcceptedByWindowsUser,
    string AcceptedMachineName,
    string AcceptedVia);

internal static class AgentLegalConsent
{
    public const string ProductName = "Cerberus Windows Agent";
    public const string EulaVersion = "agent-eula-2026-06-02.v2";
    public const string PrivacyNoticeVersion = "agent-privacy-2026-06-02.v2";
    public const string SecurityDisclosureVersion = "agent-security-2026-05-23.v1";

    private const string SchemaVersion = "cerberus-agent-legal-consent.v1";
    private const string FileName = "legal-consent.json";
    private const string MsiConsentRegistryPath = @"Software\Cerberus\WindowsAgent\LegalConsent";
    private const string MsiConsentSource = "msi_eula_dialog";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
    };

    public static string CurrentConsentSummary =>
        $"{ProductName} EULA {EulaVersion}, Privacy Notice {PrivacyNoticeVersion}, Security Disclosure {SecurityDisclosureVersion}";

    public static string ConsentRequiredMessage =>
        "Cerberus Windows Agent cannot continue until the current EULA, Privacy Notice, and Security Disclosure are accepted. "
        + "Run with --accept-eula, or accept the legal package in the tray control center.";

    public static string GetDefaultPath(LegalConsentScope scope)
        => GetPath(scope, baseDir: null);

    internal static string GetPath(LegalConsentScope scope, string? baseDir)
    {
        baseDir ??= DpapiSecretStore.GetDefaultBaseDir(ToSecretStoreScope(scope));
        return Path.Combine(baseDir, FileName);
    }

    public static bool HasCurrentConsent(LegalConsentScope scope)
        => TryLoadCurrent(scope, baseDir: null, out _) || TryImportCurrentMsiConsent(scope, baseDir: null, out _);

    public static bool HasCurrentInstallConsent()
        => HasCurrentConsent(LegalConsentScope.Machine) || HasCurrentConsent(LegalConsentScope.User);

    public static AgentLegalConsentRecord Accept(LegalConsentScope scope, string acceptedVia)
        => Accept(scope, acceptedVia, baseDir: null);

    internal static AgentLegalConsentRecord Accept(LegalConsentScope scope, string acceptedVia, string? baseDir)
    {
        if (string.IsNullOrWhiteSpace(acceptedVia))
            throw new ArgumentException("Acceptance source is required.", nameof(acceptedVia));

        return WriteRecord(
            scope,
            acceptedVia,
            DateTimeOffset.UtcNow,
            Environment.UserName,
            Environment.MachineName,
            baseDir);
    }

    public static void RequireCurrentUserConsent()
    {
        if (!HasCurrentConsent(LegalConsentScope.User))
            throw new InvalidOperationException(ConsentRequiredMessage);
    }

    public static void RequireCurrentInstallConsent()
    {
        if (!HasCurrentInstallConsent())
            throw new InvalidOperationException(ConsentRequiredMessage);
    }

    public static void EnsureMachineConsentForInstall()
    {
        if (HasCurrentConsent(LegalConsentScope.Machine))
            return;

        RequireCurrentInstallConsent();
        Accept(LegalConsentScope.Machine, "install_service");
    }

    internal static bool TryLoadCurrent(LegalConsentScope scope, string? baseDir, out AgentLegalConsentRecord? record)
    {
        record = null;
        var path = GetPath(scope, baseDir);
        if (!File.Exists(path))
            return false;

        try
        {
            var loaded = JsonSerializer.Deserialize<AgentLegalConsentRecord>(
                File.ReadAllText(path),
                JsonOptions);

            if (loaded is null ||
                !string.Equals(loaded.SchemaVersion, SchemaVersion, StringComparison.Ordinal) ||
                !string.Equals(loaded.Product, ProductName, StringComparison.Ordinal) ||
                !string.Equals(loaded.EulaVersion, EulaVersion, StringComparison.Ordinal) ||
                !string.Equals(loaded.PrivacyNoticeVersion, PrivacyNoticeVersion, StringComparison.Ordinal) ||
                !string.Equals(loaded.SecurityDisclosureVersion, SecurityDisclosureVersion, StringComparison.Ordinal))
            {
                return false;
            }

            record = loaded;
            return true;
        }
        catch
        {
            return false;
        }
    }

    internal static bool TryImportCurrentMsiConsent(
        LegalConsentScope scope,
        string? baseDir,
        out AgentLegalConsentRecord? record)
    {
        record = null;
        if (scope != LegalConsentScope.User)
            return false;

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(MsiConsentRegistryPath);
            if (key is null)
                return false;

            var values = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase)
            {
                ["accepted"] = key.GetValue("accepted")?.ToString(),
                ["product"] = key.GetValue("product")?.ToString(),
                ["eulaVersion"] = key.GetValue("eulaVersion")?.ToString(),
                ["privacyNoticeVersion"] = key.GetValue("privacyNoticeVersion")?.ToString(),
                ["securityDisclosureVersion"] = key.GetValue("securityDisclosureVersion")?.ToString(),
                ["acceptedVia"] = key.GetValue("acceptedVia")?.ToString(),
            };

            return TryImportCurrentMsiConsentFromValues(values, baseDir, out record);
        }
        catch
        {
            return false;
        }
    }

    internal static bool TryImportCurrentMsiConsentFromValues(
        IReadOnlyDictionary<string, string?> values,
        string? baseDir,
        out AgentLegalConsentRecord? record)
    {
        record = null;
        if (!string.Equals(GetValue(values, "accepted"), "1", StringComparison.Ordinal) ||
            !string.Equals(GetValue(values, "product"), ProductName, StringComparison.Ordinal) ||
            !string.Equals(GetValue(values, "eulaVersion"), EulaVersion, StringComparison.Ordinal) ||
            !string.Equals(GetValue(values, "privacyNoticeVersion"), PrivacyNoticeVersion, StringComparison.Ordinal) ||
            !string.Equals(GetValue(values, "securityDisclosureVersion"), SecurityDisclosureVersion, StringComparison.Ordinal) ||
            !string.Equals(GetValue(values, "acceptedVia"), MsiConsentSource, StringComparison.Ordinal))
        {
            return false;
        }

        record = WriteRecord(
            LegalConsentScope.User,
            MsiConsentSource,
            DateTimeOffset.UtcNow,
            Environment.UserName,
            Environment.MachineName,
            baseDir);
        return true;
    }

    private static string? GetValue(IReadOnlyDictionary<string, string?> values, string key)
        => values.TryGetValue(key, out var value) ? value : null;

    private static AgentLegalConsentRecord WriteRecord(
        LegalConsentScope scope,
        string acceptedVia,
        DateTimeOffset acceptedAtUtc,
        string acceptedByWindowsUser,
        string acceptedMachineName,
        string? baseDir)
    {
        var path = GetPath(scope, baseDir);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);

        var record = new AgentLegalConsentRecord(
            SchemaVersion,
            ProductName,
            EulaVersion,
            PrivacyNoticeVersion,
            SecurityDisclosureVersion,
            acceptedAtUtc,
            acceptedByWindowsUser,
            acceptedMachineName,
            acceptedVia);

        File.WriteAllText(path, JsonSerializer.Serialize(record, JsonOptions));
        TryHardenAcl(path, scope);
        return record;
    }

    private static SecretStoreScope ToSecretStoreScope(LegalConsentScope scope)
        => scope == LegalConsentScope.User ? SecretStoreScope.User : SecretStoreScope.Machine;

    private static void TryHardenAcl(string filePath, LegalConsentScope scope)
    {
        try
        {
            var fileInfo = new FileInfo(filePath);
            var fs = new FileSecurity();
            fs.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

            fs.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                FileSystemRights.FullControl,
                AccessControlType.Allow));
            fs.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                FileSystemRights.FullControl,
                AccessControlType.Allow));

            if (scope == LegalConsentScope.User)
            {
                var me = WindowsIdentity.GetCurrent().User;
                if (me is not null)
                {
                    fs.AddAccessRule(new FileSystemAccessRule(
                        me,
                        FileSystemRights.FullControl,
                        AccessControlType.Allow));
                }
            }

            fileInfo.SetAccessControl(fs);
        }
        catch
        {
            // Legal consent is not a secret. ACL hardening is best-effort, never a license bypass.
        }
    }
}
