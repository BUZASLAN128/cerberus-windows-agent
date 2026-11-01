using Cerberus.Agent.Core;
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
    public const string ProductName = AgentInstallIdentity.ConsentProductName;
    public const string EulaVersion = "agent-eula-2026-06-02.v2";
    public const string PrivacyNoticeVersion = "agent-privacy-2026-06-02.v2";
    public const string SecurityDisclosureVersion = "agent-security-2026-05-23.v1";

    private const string SchemaVersion = "cerberus-agent-legal-consent.v1";
    private const string FileName = "legal-consent.json";
    private const string MsiConsentRegistryPath = AgentInstallIdentity.LegalConsentRegistryPath;
    private const string MsiConsentSource = "msi_eula_dialog";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
    };

    public static string CurrentConsentSummary =>
        $"{ProductName} EULA {EulaVersion}, Privacy Notice {PrivacyNoticeVersion}, Security Disclosure {SecurityDisclosureVersion}";

    public static string ConsentRequiredMessage =>
        $"{ProductName} cannot continue until the current EULA, Privacy Notice, and Security Disclosure are accepted. "
        + "Run with --accept-eula, or accept the legal package in the tray control center.";

    public static string GetDefaultPath(LegalConsentScope scope)
        => GetPath(scope, baseDir: null);

    internal static string GetPath(LegalConsentScope scope, string? baseDir)
    {
        baseDir ??= DpapiSecretStore.GetDefaultBaseDir(ToSecretStoreScope(scope));
        return Path.Combine(baseDir, FileName);
    }

    public static bool HasCurrentConsent(LegalConsentScope scope)
    {
        if (scope == LegalConsentScope.Machine && !IsTrustedOrMissingMachineFile(GetPath(scope, baseDir: null)))
            return false;
        return TryLoadCurrent(scope, baseDir: null, out _) ||
               (scope == LegalConsentScope.Machine
                   ? MsiMachineConsent.TryReadCurrent(MsiConsentRegistryPath, IsCurrentMachineMsiConsent)
                   : TryImportCurrentMsiConsent(scope, baseDir: null, out _));
    }

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
        => EnsureMachineConsentForInstall(null, () => HasCurrentConsent(LegalConsentScope.User));

    internal static void EnsureMachineConsentForInstall(string? machineBaseDir, Func<bool> hasUserConsent)
    {
        if (!IsTrustedOrMissingMachineFile(GetPath(LegalConsentScope.Machine, machineBaseDir)))
            throw new UnauthorizedAccessException("Machine consent storage is untrusted.");
        if (TryLoadCurrent(LegalConsentScope.Machine, machineBaseDir, out _))
            return;
        if (machineBaseDir is null && MsiMachineConsent.TryReadCurrent(MsiConsentRegistryPath, IsCurrentMachineMsiConsent))
            return;
        if (!hasUserConsent())
            throw new InvalidOperationException(ConsentRequiredMessage);
        Accept(LegalConsentScope.Machine, "install_service", machineBaseDir);
    }

    internal static bool IsTrustedOrMissingMachineFile(string path)
    {
        try
        {
            var attributes = File.GetAttributes(path);
            if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0) return false;
            AgentUpdateSecurity.ValidateProtectedPath(path, Path.GetDirectoryName(path)!, allowMissing: false);
            return true;
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException) { return true; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or System.Security.SecurityException) { return false; }
    }

    internal static bool TryLoadCurrent(LegalConsentScope scope, string? baseDir, out AgentLegalConsentRecord? record)
    {
        record = null;
        var path = GetPath(scope, baseDir);
        if (!File.Exists(path))
            return false;

        try
        {
            if (scope == LegalConsentScope.Machine)
                AgentUpdateSecurity.ValidateProtectedPath(path, Path.GetDirectoryName(path)!, allowMissing: false);
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
        if (!AreCurrentMsiValues(values) || !string.Equals(GetValue(values, "acceptedVia"), MsiConsentSource, StringComparison.Ordinal))
            return false;

        record = WriteRecord(
            LegalConsentScope.User,
            MsiConsentSource,
            DateTimeOffset.UtcNow,
            Environment.UserName,
            Environment.MachineName,
            baseDir);
        return true;
    }

    internal static bool IsCurrentMachineMsiConsent(IReadOnlyDictionary<string, string?> values)
        => AreCurrentMsiValues(values) &&
           string.Equals(GetValue(values, "acceptedVia"), "msi_explicit", StringComparison.Ordinal) &&
           (GetValue(values, "acceptanceEvidence") is "explicit-v1" or "1");

    private static bool AreCurrentMsiValues(IReadOnlyDictionary<string, string?> values)
        => string.Equals(GetValue(values, "accepted"), "1", StringComparison.Ordinal) &&
           string.Equals(GetValue(values, "product"), ProductName, StringComparison.Ordinal) &&
           string.Equals(GetValue(values, "eulaVersion"), EulaVersion, StringComparison.Ordinal) &&
           string.Equals(GetValue(values, "privacyNoticeVersion"), PrivacyNoticeVersion, StringComparison.Ordinal) &&
           string.Equals(GetValue(values, "securityDisclosureVersion"), SecurityDisclosureVersion, StringComparison.Ordinal);

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

        var contents = JsonSerializer.Serialize(record, JsonOptions);
        if (scope == LegalConsentScope.Machine)
            WriteMachineRecord(path, baseDir, contents);
        else
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, contents);
            TryHardenAcl(path, scope);
        }
        return record;
    }

    private static void WriteMachineRecord(string path, string? baseDir, string contents)
    {
        var root = Path.GetDirectoryName(path)!;
        // Stage inside protected storage, never beside the target in the user-creatable product root.
        var staging = baseDir is null ? AgentUpdateSecurity.DefaultPrivilegedRoot : root;
        AgentUpdateSecurity.EnsureProtectedRoot(staging);
        AgentUpdateSecurity.ValidateProtectedPath(path, root, allowMissing: true);
        var exists = File.Exists(path);
        if (exists)
            AgentUpdateSecurity.ValidateProtectedPath(path, root, allowMissing: false);
        var temp = Path.Combine(staging, "legal-consent-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            using (var output = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            using (var writer = new StreamWriter(output, System.Text.Encoding.UTF8, leaveOpen: true))
            {
                writer.Write(contents);
                writer.Flush();
                output.Flush(flushToDisk: true);
            }
            AgentUpdateSecurity.ValidateProtectedPath(temp, staging, allowMissing: false);
            AgentUpdateSecurity.ValidateProtectedPath(path, root, allowMissing: true);
            // No overwrite for a missing target: a concurrently planted object must cause failure.
            File.Move(temp, path, overwrite: exists);
            AgentUpdateSecurity.ValidateProtectedPath(path, root, allowMissing: false);
        }
        finally
        {
            if (File.Exists(temp)) File.Delete(temp);
        }
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
