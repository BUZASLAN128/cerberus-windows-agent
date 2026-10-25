using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace Cerberus.Agent.Core.Tests;

// Support tier: the server MSI enrollment-code dialog, the rollback action, the 1722 text and the exit dialog,
// read from the preprocessed Package.wxs and ServerEnrollmentDlg.wxs. Dialog behaviour and rollback are proven
// only by an install, not here.
public sealed class ServerEnrollmentInstallerStaticTests
{
    private static readonly XNamespace Wix = "http://wixtoolset.org/schemas/v4/wxs";
    private const string Fresh = "NOT Installed AND NOT WIX_UPGRADE_DETECTED";
    private static readonly string[] LocKeys =
    {
        "ServerEnrollmentDlgTitle", "ServerEnrollmentDlgDescription", "ServerEnrollmentDlgCodeLabel",
        "ServerEnrollmentRequiredText", "ServerExitDialogNote", "ServerCustomActionFailed",
    };

    private static XDocument Dialogs(string profile) =>
        XDocument.Parse(ServerPackageStaticTests.Evaluate(profile, "stable", "ServerEnrollmentDlg.wxs"));

    private static string Installer(string name) =>
        Path.Combine(ServerPackageStaticTests.FindRepoRoot(), "src", "Cerberus.Agent.Installer", name);

    private static XElement Dialog(XDocument doc, string id) =>
        doc.Descendants(Wix + "Dialog").Single(d => (string?)d.Attribute("Id") == id);

    private static XElement Control(XElement dialog, string id) =>
        dialog.Elements(Wix + "Control").Single(c => (string?)c.Attribute("Id") == id);

    private static (string Event, string Value, string? Order, string? Condition)[] Publishes(XElement control) =>
        control.Elements(Wix + "Publish")
            .Select(p => ((string)p.Attribute("Event")!, (string)p.Attribute("Value")!, (string?)p.Attribute("Order"), (string?)p.Attribute("Condition")))
            .ToArray();

    [Fact]
    public void Dialog_TakesAHiddenBoundCodeAndOnlyAdvancesWhenItIsSet()
    {
        var dialog = Dialog(Dialogs("server"), "ServerEnrollmentDlg");

        var edit = Control(dialog, "Code");
        Assert.Equal("Edit", (string)edit.Attribute("Type")!);
        Assert.Equal("CERBERUS_ENROLLMENT_PROOF", (string)edit.Attribute("Property")!);
        Assert.Equal("yes", (string)edit.Attribute("Password")!);
        Assert.Equal("{8192}", (string)edit.Attribute("Text")!);

        var next = Publishes(Control(dialog, "Next"));
        Assert.Equal(2, next.Length);
        Assert.Contains(("SpawnDialog", "ServerEnrollmentRequiredDlg", "1", "NOT CERBERUS_ENROLLMENT_PROOF"), next);
        Assert.Contains(("NewDialog", "VerifyReadyDlg", "2", "CERBERUS_ENROLLMENT_PROOF"), next);
        Assert.Equal(new[] { ("NewDialog", "InstallDirDlg", (string?)null, (string?)null) }, Publishes(Control(dialog, "Back")));
    }

    [Fact]
    public void RequiredDialog_ExplainsAndClosesWithOk()
    {
        var dialog = Dialog(Dialogs("server"), "ServerEnrollmentRequiredDlg");

        Assert.Equal("!(loc.ServerEnrollmentRequiredText)", (string)Control(dialog, "Text").Attribute("Text")!);
        Assert.Equal(new[] { ("EndDialog", "Return", (string?)null, (string?)null) }, Publishes(Control(dialog, "OK")));
    }

    [Fact]
    public void Chain_InsertsTheDialogAfterTheStockRowsOnFreshInstallsOnly()
    {
        var publishes = Dialogs("server").Descendants(Wix + "UI").Single().Elements(Wix + "Publish").ToArray();

        var forward = publishes.Single(p => (string?)p.Attribute("Dialog") == "InstallDirDlg" && (string?)p.Attribute("Control") == "Next");
        Assert.Equal("NewDialog", (string)forward.Attribute("Event")!);
        Assert.Equal("ServerEnrollmentDlg", (string)forward.Attribute("Value")!);
        Assert.Equal(Fresh, (string)forward.Attribute("Condition")!);
        Assert.True(int.Parse((string)forward.Attribute("Order")!) > 4, "must outrank the stock InstallDirDlg Next -> VerifyReadyDlg row (Order 4)");

        var back = publishes.Single(p => (string?)p.Attribute("Dialog") == "VerifyReadyDlg" && (string?)p.Attribute("Control") == "Back");
        Assert.Equal("ServerEnrollmentDlg", (string)back.Attribute("Value")!);
        Assert.Equal(Fresh, (string)back.Attribute("Condition")!);
        Assert.True(int.Parse((string)back.Attribute("Order")!) > 1, "must outrank the stock VerifyReadyDlg Back -> InstallDirDlg row (Order 1)");
    }

    [Fact]
    public void Package_ReferencesTheDialogsOnlyInTheServerBranch()
    {
        Assert.Contains(ServerPackageStaticTests.Evaluate("server", "stable").Split('\n'), l => l.Contains("<UIRef Id=\"ServerEnrollmentUI\"") );
        Assert.DoesNotContain("ServerEnrollmentUI", ServerPackageStaticTests.Evaluate("desktop", "stable"));
    }

    [Fact]
    public void Error1722_NamesTheStepButNeverTheCommandLine()
    {
        var error = Dialogs("server").Descendants(Wix + "Error").Single();
        Assert.Equal("1722", (string)error.Attribute("Id")!);
        Assert.Equal("!(loc.ServerCustomActionFailed)", (string)error.Attribute("Message")!);

        foreach (var file in new[] { "Server.en-us.wxl", "Server.tr-tr.wxl" })
        {
            var text = Strings(file)["ServerCustomActionFailed"];
            Assert.Contains("[2]", text);
            Assert.DoesNotContain("[3]", text);
            Assert.DoesNotContain("[4]", text);
            Assert.Contains(@"C:\ProgramData\CerberusServerAgent\logs", text);
        }
    }

    [Fact]
    public void ExitDialog_ShowsOnlyTheNextStepNoteOnFreshInstalls()
    {
        var doc = Dialogs("server");
        Assert.DoesNotContain(doc.Descendants(Wix + "Publish"), p => (string?)p.Attribute("Dialog") == "ExitDialog");
        Assert.DoesNotContain(doc.Descendants(Wix + "CustomAction"), a => (string?)a.Attribute("Id") == "ServerShowFingerprint");
        Assert.DoesNotContain(doc.Descendants(Wix + "Property"), p => ((string?)p.Attribute("Id"))?.StartsWith("WIXUI_EXITDIALOGOPTIONALCHECKBOX", StringComparison.Ordinal) == true);
        Assert.DoesNotContain(doc.Descendants(Wix + "SetProperty"), s => ((string?)s.Attribute("Id"))?.StartsWith("WIXUI_EXITDIALOGOPTIONALCHECKBOX", StringComparison.Ordinal) == true);

        var text = File.ReadAllText(Installer("ServerEnrollmentDlg.wxs"));
        Assert.DoesNotContain("notepad", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("enrollment-fingerprint.txt", text);

        var note = doc.Descendants(Wix + "SetProperty").Single(s => (string?)s.Attribute("Id") == "WIXUI_EXITDIALOGOPTIONALTEXT");
        Assert.Equal("!(loc.ServerExitDialogNote)", (string)note.Attribute("Value")!);
        Assert.Equal("ui", (string)note.Attribute("Sequence")!);
        var condition = (string)note.Attribute("Condition")!;
        Assert.Contains("NOT Installed", condition);
        Assert.Contains("NOT WIX_UPGRADE_DETECTED", condition);

        Assert.Equal("Last step: approve this server in the panel.", Strings("Server.en-us.wxl")["ServerExitDialogNote"]);
        Assert.Equal("Son adım: bu sunucuyu panelde onaylayın.", Strings("Server.tr-tr.wxl")["ServerExitDialogNote"]);
        Assert.Equal("Enter the enrollment code from the panel.", Strings("Server.en-us.wxl")["ServerEnrollmentDlgDescription"]);
        Assert.Equal("Panelden aldığınız kayıt kodunu girin.", Strings("Server.tr-tr.wxl")["ServerEnrollmentDlgDescription"]);
        Assert.All(new[] { "Server.en-us.wxl", "Server.tr-tr.wxl" }, f => Assert.DoesNotContain("ServerExitDialogShowFingerprint", Strings(f).Keys));
    }

    [Fact]
    public void LocStrings_ExistInBothServerCulturesAndNeverInTheSharedFiles()
    {
        foreach (var file in new[] { "Server.en-us.wxl", "Server.tr-tr.wxl" })
        {
            var strings = Strings(file);
            Assert.Equal(LocKeys.OrderBy(k => k), strings.Keys.OrderBy(k => k));
            Assert.All(strings.Values, v => Assert.False(string.IsNullOrWhiteSpace(v)));
        }

        foreach (var shared in new[] { "Package.en-us.wxl", "Package.tr-tr.wxl" })
        {
            var text = File.ReadAllText(Installer(shared));
            Assert.All(LocKeys, key => Assert.DoesNotContain(key, text));
        }

        // Every loc reference in the server fragment resolves in the stock WixUI strings or in the server files.
        var used = Regex.Matches(File.ReadAllText(Installer("ServerEnrollmentDlg.wxs")), @"!\(loc\.(Server\w+)\)").Select(m => m.Groups[1].Value).Distinct();
        Assert.All(used, key => Assert.Contains(key, LocKeys));
    }

    [Fact]
    public void Desktop_HasNoEnrollmentDialogsOverridesOrServerStrings()
    {
        var doc = Dialogs("desktop");
        Assert.Empty(doc.Descendants(Wix + "Fragment"));
        Assert.Empty(doc.Descendants(Wix + "Dialog"));
        Assert.Empty(doc.Descendants(Wix + "Error"));

        var package = ServerPackageStaticTests.Evaluate("desktop", "stable");
        foreach (var forbidden in new[] { "ServerEnrollment", "ServerShowFingerprint", "ServerEnrollFromInstaller", "CERBERUS_ENROLLMENT_PROOF", "Error Id" })
        {
            Assert.DoesNotContain(forbidden, package);
        }

        var project = File.ReadAllText(Installer("Cerberus.Agent.Installer.wixproj"));
        Assert.Matches(@"<ItemGroup Condition=""'\$\(AgentBuildProfile\)' != 'server'"">\s*<EmbeddedResource Remove=""Server\.\*\.wxl"" />", project);
    }

    private static Dictionary<string, string> Strings(string file)
    {
        var ns = XNamespace.Get("http://wixtoolset.org/schemas/v4/wxl");
        return XDocument.Load(Installer(file)).Descendants(ns + "String")
            .ToDictionary(s => (string)s.Attribute("Id")!, s => (string)s.Attribute("Value")!);
    }
}
