using System.Diagnostics;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace Cerberus.Agent.Core.Tests;

// Support tier: evaluates the WiX preprocessor branches of Package.wxs per build profile and checks the
// release-script profile helper. The MSI itself is proven by the table dump of the built packages, not here.
public sealed class ServerPackageStaticTests
{
    private static readonly XNamespace Wix = "http://wixtoolset.org/schemas/v4/wxs";
    private static readonly XNamespace Util = "http://wixtoolset.org/schemas/v4/wxs/util";

    private const string DesktopUpgradeCode = "{8F7E4C22-4D3E-4D50-9B31-0D969B3D0D1E}";
    private const string ServerUpgradeCode = "{686EF4F7-AC5C-4459-B2B9-540920991AAF}";

    [Fact]
    public void DesktopBranch_KeepsTheShippedPackageIdentity()
    {
        var text = Evaluate("desktop", "stable");
        var doc = XDocument.Parse(text);
        var package = doc.Descendants(Wix + "Package").Single();

        Assert.Equal("$(var.UpgradeCodeValue)", (string?)package.Attribute("UpgradeCode"));
        Assert.Contains($"<?define UpgradeCodeValue = \"{DesktopUpgradeCode}\" ?>", text);
        Assert.Contains("DowngradeErrorMessage=\"A newer version of Cerberus Windows Agent is already installed.\"", text);
        Assert.Equal(new[] { "Cerberus.Agent.exe", "Cerberus.Agent.App.exe", "Cerberus.Agent.Tray.exe", "Cerberus.Agent.Setup.exe" },
            doc.Descendants(Util + "CloseApplication").Select(e => (string)e.Attribute("Target")!).ToArray());
        Assert.Contains(doc.Descendants(Wix + "Directory"), d => (string?)d.Attribute("Name") == "Windows Agent");
        Assert.Equal(
            new[] { "{7C6D5F34-379E-4B19-9BC3-4F840E07C765}", "{6FD72DD1-B76B-4E07-94A2-4355A5FB403D}" },
            Guids(doc, "AgentInstallRegistryComponent", "LegalConsentRegistryComponent"));
        Assert.Equal(4, doc.Descendants(Wix + "Shortcut").Count());
        Assert.Contains(doc.Descendants(Wix + "CustomAction"), a => (string?)a.Attribute("Id") == "LaunchAgentUi");
        Assert.Contains("LaunchAgentUi", text);
        Assert.DoesNotContain("Server", Regex.Replace(text, @"Cerberus Server Agent|\$\(var\.ProductName\)", ""));
        Assert.DoesNotContain("CERBERUS_ENROLLMENT_PROOF", text);
        Assert.DoesNotContain("ServiceInstall", text);
        Assert.DoesNotContain("RemoveFolderEx", text);
        Assert.DoesNotContain(doc.Descendants(Wix + "RegistryValue"), r => ((string?)r.Attribute("Key"))!.Contains("ServerAgent"));
        Assert.Contains(doc.Descendants(Wix + "RegistryValue"), r => ((string?)r.Attribute("Key")) == @"Software\Cerberus\WindowsAgent");
    }

    [Theory]
    [InlineData("dev")]
    [InlineData("stable")]
    public void ServerBranch_MatchesTheContractIdentityTable(string channel)
    {
        var text = Evaluate("server", channel);
        var doc = XDocument.Parse(text);

        Assert.Contains($"<?define UpgradeCodeValue = \"{ServerUpgradeCode}\" ?>", text);
        Assert.DoesNotContain(DesktopUpgradeCode, text);
        Assert.Equal("$(var.ProductName)", (string?)doc.Descendants(Wix + "Package").Single().Attribute("Name"));

        var directories = doc.Descendants(Wix + "Directory").ToDictionary(d => (string)d.Attribute("Id")!, d => (string)d.Attribute("Name")!);
        Assert.Equal("Server Agent", directories["INSTALLFOLDER"]);
        Assert.Equal("app", directories["APPFOLDER"]);
        Assert.Equal("CerberusServerAgent", directories["SERVERDATADIR"]);
        Assert.Equal("Cerberus", directories["CompanyFolder"]);
        Assert.DoesNotContain("Windows Agent", directories.Values);

        Assert.Equal(
            new[] { "{0C98AA33-79C6-4E21-AD39-E50C2B895B21}", "{D3741C30-B58B-4F95-940E-F51B5BA80F84}", "{1A8485C8-A5AC-4C0D-94E2-D17390941535}" },
            Guids(doc, "ServerAgentInstallRegistryComponent", "ServerLegalConsentRegistryComponent", "ServerDataCleanupComponent"));

        var keys = doc.Descendants(Wix + "RegistryValue").Select(r => (string)r.Attribute("Key")!).Distinct().ToArray();
        Assert.All(keys, k => Assert.StartsWith(@"Software\Cerberus\ServerAgent", k));

        var service = doc.Descendants(Wix + "ServiceControl").Single();
        Assert.Equal("CerberusServerAgent", (string)service.Attribute("Name")!);
        Assert.Equal("uninstall", (string)service.Attribute("Remove")!);
        Assert.Equal("both", (string)service.Attribute("Stop")!);
        Assert.Equal("CerberusServerAgent", (string)doc.Descendants(Wix + "ServiceInstall").Single().Attribute("Name")!);

        var cleanup = doc.Descendants(Util + "RemoveFolderEx").Single();
        Assert.Equal("uninstall", (string)cleanup.Attribute("On")!);
        // Wix4RemoveFoldersEx_X64 runs before CostInitialize, so the property must be a plain path set before it, never a Directory id.
        var cleanupProperty = (string)cleanup.Attribute("Property")!;
        Assert.Equal("SERVERDATAPATH", cleanupProperty);
        Assert.DoesNotContain(cleanupProperty, directories.Keys);
        var setPath = doc.Descendants(Wix + "SetProperty").Single(p => (string?)p.Attribute("Id") == cleanupProperty);
        Assert.Equal("Wix4RemoveFoldersEx_X64", (string)setPath.Attribute("Before")!);
        Assert.Equal("execute", (string)setPath.Attribute("Sequence")!);
        Assert.Null(setPath.Attribute("Condition"));
        Assert.Equal($"[CommonAppDataFolder]{directories["SERVERDATADIR"]}\\", (string)setPath.Attribute("Value")!);

        // Side by side: no element Id may collide with the desktop package.
        var desktopIds = Ids(XDocument.Parse(Evaluate("desktop", channel)));
        var shared = Ids(doc).Intersect(desktopIds).Where(id => !SharedIds.Contains(id)).ToArray();
        Assert.Empty(shared);
    }

    [Fact]
    public void ServerBranch_HasNoDesktopUiOrProcessClosing()
    {
        var text = Evaluate("server", "stable");
        var doc = XDocument.Parse(text);

        Assert.Empty(doc.Descendants(Util + "CloseApplication"));
        Assert.Empty(doc.Descendants(Wix + "Shortcut"));
        Assert.DoesNotContain("LaunchAgentUi", text);
        Assert.DoesNotContain("WIXUI_EXITDIALOGOPTIONALCHECKBOX", text);
        Assert.DoesNotContain("Wix4CloseApplications", text);
        Assert.DoesNotContain("StartupFolder", text);
        Assert.DoesNotContain("CREATE_DESKTOP_SHORTCUT", text);
    }

    [Fact]
    public void ServerBranch_EnrollmentProofIsHiddenAndRunsOnceBeforeFinalize()
    {
        var doc = XDocument.Parse(Evaluate("server", "stable"));

        var property = doc.Descendants(Wix + "Property").Single(p => (string?)p.Attribute("Id") == "CERBERUS_ENROLLMENT_PROOF");
        Assert.Equal("yes", (string)property.Attribute("Secure")!);
        Assert.Equal("yes", (string)property.Attribute("Hidden")!);
        Assert.Null(property.Attribute("Value"));

        var action = doc.Descendants(Wix + "CustomAction").Single(a => (string?)a.Attribute("Id") == "ServerEnrollFromInstaller");
        Assert.Equal("deferred", (string)action.Attribute("Execute")!);
        Assert.Equal("no", (string)action.Attribute("Impersonate")!);
        Assert.Equal("yes", (string)action.Attribute("HideTarget")!);
        Assert.Equal("check", (string)action.Attribute("Return")!);
        var command = (string)action.Attribute("ExeCommand")!;
        Assert.Contains("--enroll-headless --proof-from-installer \"[CERBERUS_ENROLLMENT_PROOF]\" --install-service", command);

        var step = doc.Descendants(Wix + "Custom").Single(c => (string?)c.Attribute("Action") == "ServerEnrollFromInstaller");
        Assert.Equal("InstallFinalize", (string)step.Attribute("Before")!);
        Assert.Equal("NOT Installed AND NOT WIX_UPGRADE_DETECTED AND CERBERUS_ENROLLMENT_PROOF", (string)step.Attribute("Condition")!);
    }

    [Fact]
    public void ServerBranch_ConsentKeepsTheProductValueTheAgentValidates()
    {
        var doc = XDocument.Parse(Evaluate("server", "stable"));
        var consent = doc.Descendants(Wix + "RegistryValue")
            .Where(r => (string?)r.Attribute("Key") == @"Software\Cerberus\ServerAgent\LegalConsent")
            .ToDictionary(r => (string)r.Attribute("Name")!, r => (string)r.Attribute("Value")!);

        Assert.Equal("Cerberus Server Agent", consent["product"]);
        Assert.Equal("1", consent["accepted"]);
        Assert.Contains("BlockInstallWithoutEula", Evaluate("server", "stable"));
        Assert.Contains("CERBERUS_EULA_ACCEPTED = 1", Evaluate("server", "stable"));
    }

    [Theory]
    [InlineData("desktop", "", true)]
    [InlineData("server", "-server", false)]
    public void ReleasePublish_AliasNamesAndGateFollowTheProfile(string profile, string suffix, bool shipsUninstall)
    {
        var dir = Path.Combine(Path.GetTempPath(), $"publish-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        try
        {
            var lib = Path.Combine(FindRepoRoot(), "scripts", "release-publish-lib.ps1");
            var command =
                $". '{lib}'; $d = '{dir}'; " +
                "foreach ($n in 'Agent.msi','Bundle.zip','Bundle.sbom.json','Bundle.provenance.json') { Set-Content -LiteralPath (Join-Path $d $n) -Value $n }; " +
                "$m = [ordered]@{ sha256 = 'abc'; sequence = 1; expires_at_utc = 'x'; signer_key_identity = 'k' }; " +
                $"Publish-ReleaseOutputs -PublishDir $d -Channel dev -AssetBase Bundle -InstallerBase Agent -Manifest $m -LegacyManifest $null -AllowUnsignedBuildMetadata $true -Signed $false -BuildProfile {profile}";
            var run = RunPwsh(command);
            Assert.True(run.ExitCode == 0, run.Output);

            var names = Directory.GetFiles(dir).Select(Path.GetFileName).Where(n => n!.Contains("-latest", StringComparison.Ordinal)).OrderBy(n => n, StringComparer.Ordinal).ToArray();
            var expected = new[]
            {
                $"Cerberus.Agent-dev-latest{suffix}.msi",
                $"Cerberus.Agent.Bundle-dev-latest{suffix}.provenance.json",
                $"Cerberus.Agent.Bundle-dev-latest{suffix}.release-gate.json",
                $"Cerberus.Agent.Bundle-dev-latest{suffix}.sbom.json",
                $"Cerberus.Agent.Bundle-dev-latest{suffix}.sha256",
                $"Cerberus.Agent.Bundle-dev-latest{suffix}.update-manifest.v2.json",
                $"Cerberus.Agent.Bundle-dev-latest{suffix}.zip",
            }.OrderBy(n => n, StringComparer.Ordinal).ToArray();
            Assert.Equal(expected, names);

            var gate = File.ReadAllText(Path.Combine(dir, $"Cerberus.Agent.Bundle-dev-latest{suffix}.release-gate.json"));
            Assert.Equal(shipsUninstall, gate.Contains("uninstall_binary", StringComparison.Ordinal));
            Assert.DoesNotContain("Uninstall", shipsUninstall ? "" : gate);
            Assert.Contains("\"updater_binary\": \"app/Cerberus.Agent.Updater.exe\"", gate);
            Assert.DoesNotContain("tray", gate, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Theory]
    [InlineData("desktop", "Cerberus.Agent.Uninstall.exe", 4)]
    [InlineData("server", "Cerberus.Agent.Uninstall.exe", 3)]
    public void ReleaseSigningList_ServerOmitsTheDesktopUninstaller(string profile, string uninstall, int count)
    {
        var lib = Path.Combine(FindRepoRoot(), "scripts", "release-publish-lib.ps1");
        var run = RunPwsh($". '{lib}'; (Get-ReleaseRuntimeExecutableNames '{profile}') -join '|'");
        Assert.Equal(0, run.ExitCode);
        var names = run.Output.Trim().Split('|');
        Assert.Equal(count, names.Length);
        Assert.Equal(profile == "desktop", names.Contains(uninstall));
        Assert.Contains("Cerberus.Agent.Service.exe", names);
    }

    [Fact]
    public void Wixproj_PassesProfileProductNameAndEulaToTheWixPreprocessor()
    {
        var project = File.ReadAllText(Path.Combine(FindRepoRoot(), "src", "Cerberus.Agent.Installer", "Cerberus.Agent.Installer.wixproj"));

        Assert.Contains("AgentBuildProfile=$(AgentBuildProfile);", project);
        Assert.Contains("ProductName=$(ProductName);", project);
        Assert.Contains("EulaRtf=$(EulaRtf);", project);
        Assert.Matches(@"<AgentBuildProfile Condition=""'\$\(AgentBuildProfile\)' == ''"">desktop</AgentBuildProfile>", project);
        Assert.Matches(@"<ProductName Condition=""'\$\(ProductName\)' == '' and '\$\(AgentBuildProfile\)' == 'server'"">Cerberus Server Agent</ProductName>", project);
        Assert.Matches(@"<ProductName Condition=""'\$\(ProductName\)' == ''"">Cerberus Windows Agent</ProductName>", project);
    }

    [Fact]
    public void ReleaseScript_SharesTheProfileArgumentsWithEveryBuildStep()
    {
        var script = File.ReadAllText(Path.Combine(FindRepoRoot(), "scripts", "build-agent-public-release.ps1"));

        // Publish-AgentProject, the Helper publish and the MSI build.
        Assert.Equal(3, Regex.Matches(script, Regex.Escape("$releaseProfile.MsBuildArgs")).Count);
        Assert.Contains("@($releaseProfile.MsiArgs)", script);
        Assert.Contains("Publish-AgentProject \"src/Cerberus.Agent.App/Cerberus.Agent.App.csproj\"", script);
        Assert.Contains("Publish-AgentProject \"src/Cerberus.Agent.Service/Cerberus.Agent.Service.csproj\"", script);
        Assert.Contains("Publish-AgentProject \"src/Cerberus.Agent.Updater/Cerberus.Agent.Updater.csproj\"", script);
        Assert.Matches(@"if \(\$BuildProfile -ne ""server""\) \{ Publish-AgentProject ""src/Cerberus\.Agent\.Uninstall/", script);
        Assert.True(script.Split('\n').Length < 500, "build-agent-public-release.ps1 must stay under 500 lines.");
    }

    [Fact]
    public void ReleaseProfileLib_ServerBuildRequiresAnchorsAndDesktopAddsNothing()
    {
        var anchors = Path.Combine(Path.GetTempPath(), $"anchors-{Guid.NewGuid():N}.b64");
        var anchorValue = File.ReadAllText(Path.Combine(FindRepoRoot(), "tests", "fixtures", "agent-command-test-anchors.b64")).Trim();
        File.WriteAllText(anchors, anchorValue + "\n");
        try
        {
            var missing = RunProfileLib("'server' '' @{} '' ''");
            Assert.NotEqual(0, missing.ExitCode);
            Assert.Contains("requires -AgentCommandTrustAnchorsFile", missing.Output);

            var server = RunProfileLib($"'server' '{anchors}' @{{ AgentPollFloorSeconds = 30 }} 'Acme Server' ''");
            Assert.Equal(0, server.ExitCode);
            Assert.Contains("ARGS=-p:AgentBuildProfile=server|-p:AgentCommandTrustAnchorsB64=" + anchorValue + "|-p:AgentPollFloorSeconds=30", server.Output);
            Assert.Contains("MSI=-p:ProductName=Acme Server", server.Output);
            Assert.Contains("SUFFIX=-server", server.Output);

            var badKey = RunProfileLib($"'server' '{anchors}' @{{ NotATimingKey = 1 }} '' ''");
            Assert.NotEqual(0, badKey.ExitCode);
            var badValue = RunProfileLib($"'server' '{anchors}' @{{ AgentPollFloorSeconds = 'x' }} '' ''");
            Assert.NotEqual(0, badValue.ExitCode);

            var desktop = RunProfileLib("'desktop' '' @{} '' ''");
            Assert.Equal(0, desktop.ExitCode);
            Assert.Contains("ARGS=" + Environment.NewLine, desktop.Output + Environment.NewLine);
            Assert.Contains("SUFFIX=" + Environment.NewLine, desktop.Output + Environment.NewLine);
        }
        finally
        {
            File.Delete(anchors);
        }
    }

    [Theory]
    [InlineData("preview", false)]
    [InlineData("stable", false)]
    [InlineData("dev", true)]
    public void ReleaseProfileLib_RefusesTestFixtureAnchorsOnPreviewAndStable(string channel, bool accepted)
    {
        var anchors = Path.Combine(Path.GetTempPath(), $"anchors-{Guid.NewGuid():N}.b64");
        File.WriteAllText(anchors, File.ReadAllText(Path.Combine(FindRepoRoot(), "tests", "fixtures", "agent-command-test-anchors.b64")).Trim() + "\n");
        try
        {
            var result = RunProfileLib($"'server' '{anchors}' @{{}} '' '' '{channel}'");
            Assert.Equal(accepted, result.ExitCode == 0);
            if (!accepted)
                Assert.Contains("repository test fixture", result.Output);
        }
        finally
        {
            File.Delete(anchors);
        }
    }

    [Fact]
    public void ReleaseScript_SignsAndGatesTheInstallerHelperBeforeTheMsiBuild()
    {
        var script = File.ReadAllText(Path.Combine(FindRepoRoot(), "scripts", "build-agent-public-release.ps1"));
        var sign = script.IndexOf("Invoke-FirstPartySigning @(Get-FirstPartyPeFiles $installerHelperOutput)", StringComparison.Ordinal);
        Assert.True(sign > script.IndexOf("Installer helper publish failed", StringComparison.Ordinal));
        Assert.Contains("Assert-FirstPartyPeFilesSigned $installerHelperOutput", script);
        Assert.True(sign < script.IndexOf("dotnet build $installerProject", StringComparison.Ordinal));
    }

    [Fact]
    public void SmokeScript_SelectsTheServiceNameByProfile()
    {
        var script = File.ReadAllText(Path.Combine(FindRepoRoot(), "scripts", "clean-install-smoke.ps1"));

        Assert.Contains("[ValidateSet(\"desktop\", \"server\")][string]$BuildProfile = \"desktop\"", script);
        Assert.Contains("if ($BuildProfile -eq \"server\") { \"CerberusServerAgent\" } else { \"CerberusAgent\" }", script);
        Assert.Contains("-p:AgentBuildProfile=server", script);
    }

    // Shared on purpose: the bootstrap and EULA actions and the directory skeleton are not listed here (directories are not compared).
    private static readonly HashSet<string> SharedIds = new(StringComparer.Ordinal)
    {
        "BlockInstallWithoutEula", "BlockUpgradeWithoutRollback", "BootstrapCerberusMachineNamespace",
    };

    private static readonly string[] IdentityElements =
        { "Component", "ComponentGroup", "Feature", "CustomAction", "File", "RemoveFolder", "ServiceControl", "ServiceInstall", "Shortcut", "CloseApplication" };

    private static IEnumerable<string> Ids(XDocument doc) =>
        doc.Descendants().Where(e => IdentityElements.Contains(e.Name.LocalName))
            .Select(e => (string?)e.Attribute("Id")).Where(id => id is not null).Select(id => id!).Distinct();

    private static string[] Guids(XDocument doc, params string[] componentIds) =>
        componentIds.Select(id => (string)doc.Descendants(Wix + "Component").Single(c => (string?)c.Attribute("Id") == id).Attribute("Guid")!).ToArray();

    // Evaluates <?define?>, <?if $(var.X) = / != Y?>, <?else?> and <?endif?> lines. Other lines are kept verbatim.
    internal static string Evaluate(string profile, string channel, string file = "Package.wxs")
    {
        var vars = new Dictionary<string, string>(StringComparer.Ordinal) { ["AgentBuildProfile"] = profile, ["ReleaseChannel"] = channel };
        var output = new List<string>();
        var stack = new Stack<(bool Parent, bool Taken, bool Active)>();
        var active = true;
        foreach (var line in File.ReadAllLines(Path.Combine(FindRepoRoot(), "src", "Cerberus.Agent.Installer", file)))
        {
            var trimmed = line.Trim();
            var condition = Regex.Match(trimmed, @"^<\?if \$\(var\.(?<n>\w+)\)\s*(?<op>!=|=)\s*(?<v>\w+)\s*\?>$");
            if (condition.Success)
            {
                var actual = vars.TryGetValue(condition.Groups["n"].Value, out var found) ? found : "";
                var equal = actual == condition.Groups["v"].Value;
                var taken = condition.Groups["op"].Value == "=" ? equal : !equal;
                stack.Push((active, taken, active));
                active = active && taken;
            }
            else if (trimmed.StartsWith("<?else", StringComparison.Ordinal))
            {
                var (parent, taken, _) = stack.Pop();
                stack.Push((parent, taken, parent));
                active = parent && !taken;
            }
            else if (trimmed.StartsWith("<?endif", StringComparison.Ordinal))
            {
                active = stack.Pop().Parent;
            }
            else if (active)
            {
                output.Add(line);
            }
        }

        Assert.Empty(stack);
        return string.Join('\n', output);
    }

    private static (int ExitCode, string Output) RunPwsh(string command)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "pwsh",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        foreach (var argument in new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", $"$ErrorActionPreference='Stop'; {command}" })
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("Could not start pwsh.");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(120_000))
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException("pwsh check did not finish within 2 minutes.");
        }

        Task.WaitAll(stdout, stderr);
        return (process.ExitCode, stdout.Result + stderr.Result);
    }

    internal static (int ExitCode, string Output) RunProfileLib(string arguments)
    {
        var lib = Path.Combine(FindRepoRoot(), "scripts", "release-profile-lib.ps1");
        var command =
            $". '{lib}'; $r = Get-ReleaseProfileBuild {arguments}; " +
            "Write-Output ('ARGS=' + ($r.MsBuildArgs -join '|')); Write-Output ('MSI=' + ($r.MsiArgs -join '|')); Write-Output ('SUFFIX=' + $r.AssetSuffix)";
        var startInfo = new ProcessStartInfo
        {
            FileName = "pwsh",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        foreach (var argument in new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", $"$ErrorActionPreference='Stop'; {command}" })
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("Could not start pwsh.");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(120_000))
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException("release-profile-lib check did not finish within 2 minutes.");
        }

        Task.WaitAll(stdout, stderr);
        return (process.ExitCode, stdout.Result + stderr.Result);
    }

    internal static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "scripts", "release-profile-lib.ps1")) &&
                Directory.Exists(Path.Combine(dir.FullName, "tests", "Cerberus.Agent.Core.Tests")))
            {
                return dir.FullName;
            }

            dir = dir.Parent;
        }

        throw new DirectoryNotFoundException("Repository root not found.");
    }
}
