#if !CERBERUS_SERVER_PROFILE
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Cerberus.Agent.App;
using Cerberus.Agent.App.Legal;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class EnrollHeadlessModeTests
{
    private static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static string CreateConsentFixture()
    {
        var root = Path.Combine(Path.GetTempPath(), "cerberus-machine-consent-" + Guid.NewGuid().ToString("N"));
        AgentUpdateSecurity.EnsureProtectedRoot(root);
        return root;
    }

    [Fact]
    public void Machine_consent_creates_and_reads_a_trusted_record_atomically()
    {
        if (!IsElevated()) return;
        var root = CreateConsentFixture();
        try
        {
            AgentLegalConsent.EnsureMachineConsentForInstall(root, () => true);
            Assert.True(AgentLegalConsent.TryLoadCurrent(LegalConsentScope.Machine, root, out var loaded));
            Assert.Equal("install_service", loaded!.AcceptedVia);
            AgentLegalConsent.Accept(LegalConsentScope.Machine, "explicit_fixture", root);
            Assert.True(AgentLegalConsent.TryLoadCurrent(LegalConsentScope.Machine, root, out loaded));
            Assert.Equal("explicit_fixture", loaded!.AcceptedVia);
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public async Task User_owned_machine_consent_refuses_before_proof_and_is_not_repaired()
    {
        if (!IsElevated()) return;
        var root = CreateConsentFixture();
        try
        {
            var path = AgentLegalConsent.GetPath(LegalConsentScope.Machine, root);
            var fake = new AgentLegalConsentRecord("cerberus-agent-legal-consent.v1", AgentLegalConsent.ProductName,
                AgentLegalConsent.EulaVersion, AgentLegalConsent.PrivacyNoticeVersion, AgentLegalConsent.SecurityDisclosureVersion,
                DateTimeOffset.UtcNow, "fixture", "fixture", "fixture");
            var contents = JsonSerializer.Serialize(fake, new JsonSerializerOptions(JsonSerializerDefaults.Web));
            File.WriteAllText(path, contents);
            var file = new FileInfo(path);
            var acl = file.GetAccessControl();
            using var identity = WindowsIdentity.GetCurrent();
            acl.SetOwner(identity.User!);
            file.SetAccessControl(acl);
            Assert.False(AgentLegalConsent.TryLoadCurrent(LegalConsentScope.Machine, root, out _));
            Assert.Throws<InvalidOperationException>(() => AgentLegalConsent.Accept(LegalConsentScope.Machine, "fixture", root));

            var host = new FakeHost { BootstrapAction = _ => AgentLegalConsent.EnsureMachineConsentForInstall(root, () => true) };
            var result = await Execute(host, installService: true);
            Assert.Equal(HeadlessEnrollmentExit.Refused, result.Exit);
            Assert.Contains("bootstrap_unavailable", result.Stderr);
            Assert.Empty(host.Http.Requests);
            Assert.Equal(0, host.Store.SaveCount);
            Assert.Equal(0, host.InstallCalls);
            Assert.Equal(contents, File.ReadAllText(path));
            Assert.Equal(identity.User, file.GetAccessControl().GetOwner(typeof(SecurityIdentifier)));
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public async Task Reparse_consent_refuses_before_proof_without_touching_target()
    {
        if (!IsElevated()) return;
        var root = CreateConsentFixture();
        try
        {
            var path = AgentLegalConsent.GetPath(LegalConsentScope.Machine, root);
            var target = Path.Combine(root, "sentinel.txt");
            File.WriteAllText(target, "unchanged");
            File.CreateSymbolicLink(path, target);
            Assert.Throws<InvalidOperationException>(() => AgentLegalConsent.Accept(LegalConsentScope.Machine, "fixture", root));
            var host = new FakeHost { BootstrapAction = _ => AgentLegalConsent.EnsureMachineConsentForInstall(root, () => true) };
            var result = await Execute(host, installService: true);
            Assert.Equal(HeadlessEnrollmentExit.Refused, result.Exit);
            Assert.Contains("bootstrap_unavailable", result.Stderr);
            Assert.Empty(host.Http.Requests);
            Assert.Equal(0, host.Store.SaveCount);
            Assert.Equal(0, host.InstallCalls);
            Assert.Equal("unchanged", File.ReadAllText(target));
            Assert.True((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0);
        }
        finally { Directory.Delete(root, recursive: true); }
    }
}
#endif
