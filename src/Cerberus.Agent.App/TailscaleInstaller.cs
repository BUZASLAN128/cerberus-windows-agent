using Cerberus.Agent.Integrations.Tailscale;
using Cerberus.Agent.Observability;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Runtime.InteropServices;

namespace Cerberus.Agent.App;

internal static class TailscaleInstaller
{
    // Official Tailscale stable download endpoints (Windows MSI installers).
    // MSI is enterprise-friendly and supports policy properties (hide menus, no-launch, etc.).
    private const string StableBaseUrl = "https://pkgs.tailscale.com/stable/";
    private const string DefaultMsiAmd64 = StableBaseUrl + "tailscale-setup-latest-amd64.msi";
    private const string DefaultMsiX86 = StableBaseUrl + "tailscale-setup-latest-x86.msi";
    private const string DefaultMsiArm64 = StableBaseUrl + "tailscale-setup-latest-arm64.msi";

    public static async Task EnsureInstalledAsync(
        Action<string> log,
        CancellationToken ct)
    {
        var (installed, _, _, _) = await TailscaleStatusProbe.ProbeAsync(
            timeout: TimeSpan.FromSeconds(2),
            ct: ct);
        if (installed)
        {
            log("Tailscale already installed.");
            return;
        }

        // Optional override (enterprise mirrors). Otherwise use official "latest" MSI for arch.
        var url = Environment.GetEnvironmentVariable("CERBERUS_TAILSCALE_DOWNLOAD_URL")?.Trim();
        if (string.IsNullOrWhiteSpace(url))
            url = GetDefaultMsiUrlForThisMachine();

        // MSI properties to make the UI more "managed"/corporate (hide admin/update/debug menus).
        // These are stored under HKLM\\SOFTWARE\\Policies\\Tailscale by the MSI. (Tailscale docs)
        var extraProps = Environment.GetEnvironmentVariable("CERBERUS_TAILSCALE_MSI_PROPERTIES")?.Trim();
        var msiProps = string.IsNullOrWhiteSpace(extraProps)
            ? @"TS_ADMINCONSOLE=""hide"" TS_UPDATEMENU=""hide"" TS_TESTMENU=""hide"" TS_NETWORKDEVICES=""hide"" TS_PREFERENCESMENU=""show"" TS_NOLAUNCH=""1"""
            : extraProps;

        var destDir = Environment.GetEnvironmentVariable("CERBERUS_TAILSCALE_DOWNLOAD_DIR")?.Trim();
        if (string.IsNullOrWhiteSpace(destDir))
            destDir = GetDefaultDownloadsDir();

        var installerPath = await DownloadLatestAsync(url, destDir, log, ct);

        // Require a valid Authenticode signature. If this fails, do not install.
        await RequireValidSignatureAsync(installerPath, log, ct);

        log("Starting silent MSI install (UAC may prompt)...");
        StartMsiInstall(installerPath, msiProps, log);
        log("Install started. You may need to wait 30-60 seconds.");
    }

    private static async Task<string> DownloadLatestAsync(
        string downloadUrl,
        string destDir,
        Action<string> log,
        CancellationToken ct)
    {
        if (!Uri.TryCreate(downloadUrl, UriKind.Absolute, out var url) || url.Scheme != Uri.UriSchemeHttps)
            throw new InvalidOperationException("Invalid Tailscale download URL (must be https).");

        Directory.CreateDirectory(destDir);

        var fileName = downloadUrl.EndsWith(".msi", StringComparison.OrdinalIgnoreCase)
            ? "tailscale-setup-latest.msi"
            : "tailscale-setup-latest.exe";
        var destPath = Path.Combine(destDir, fileName);
        var tmpPath = destPath + ".download";

        log("Downloading Tailscale installer...");
        log($"URL: {Sanitizer.Redact(downloadUrl)}");
        log($"To: {destPath}");

        using var http = new HttpClient { Timeout = TimeSpan.FromMinutes(3) };
        using var resp = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct);
        resp.EnsureSuccessStatusCode();

        await using (var src = await resp.Content.ReadAsStreamAsync(ct))
        await using (var dst = File.Create(tmpPath))
        {
            await src.CopyToAsync(dst, ct);
        }

        File.Move(tmpPath, destPath, overwrite: true);

        var len = new FileInfo(destPath).Length;
        if (len < 500_000)
            throw new InvalidOperationException("Downloaded file is unexpectedly small; aborting.");

        log($"Download complete ({len} bytes).");
        return destPath;
    }

    private static async Task RequireValidSignatureAsync(string filePath, Action<string> log, CancellationToken ct)
    {
        // Use PowerShell Authenticode check.
        var escapedPath = filePath.Replace("'", "''");
        var psArgs =
            "-NoProfile -Command " +
            $"\"$s=(Get-AuthenticodeSignature '{escapedPath}'); " +
            "$status=$s.Status; $sub=$s.SignerCertificate.Subject; " +
            "Write-Output ($status + '|' + $sub)\"";

        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = psArgs,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        using var p = Process.Start(psi);
        if (p is null)
            throw new InvalidOperationException("Failed to start signature check.");

        var output = await p.StandardOutput.ReadToEndAsync();
        var err = await p.StandardError.ReadToEndAsync();
        await p.WaitForExitAsync(ct);

        var line = (output ?? "").Trim();
        var parts = line.Split('|', 2);
        var status = parts.Length > 0 ? parts[0].Trim() : "";
        var subject = parts.Length > 1 ? parts[1].Trim() : "";

        if (!string.IsNullOrWhiteSpace(status))
            log($"Installer signature status: {status}");
        if (!string.IsNullOrWhiteSpace(subject))
            log($"Installer signer: {subject}");

        if (!string.Equals(status, "Valid", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.IsNullOrWhiteSpace(err))
                log($"Signature check stderr: {Sanitizer.Redact(err)}");
            throw new InvalidOperationException($"Installer signature is not valid ({status}).");
        }
    }

    private static void StartMsiInstall(string installerPath, string msiProps, Action<string> log)
    {
        try
        {
            if (!installerPath.EndsWith(".msi", StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Expected MSI installer (.msi).");

            // /qn = quiet, /norestart = do not auto-reboot.
            var args = $"/i \"{installerPath}\" /qn /norestart {msiProps}";

            var psi = new ProcessStartInfo
            {
                FileName = "msiexec.exe",
                Arguments = args,
                UseShellExecute = true,
                Verb = "runas", // request elevation when needed
                WindowStyle = ProcessWindowStyle.Hidden,
            };
            Process.Start(psi);
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            // User canceled UAC
            log("Install canceled (UAC denied).");
        }
    }

    private static string GetDefaultDownloadsDir()
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (string.IsNullOrWhiteSpace(home))
            home = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        return Path.Combine(home, "Downloads");
    }

    private static string GetDefaultMsiUrlForThisMachine()
    {
        // Tailscale docs note: On Windows ARM64, the x86 MSI may be recommended.
        // Prefer x86 for Arm64 for compatibility, unless the operator overrides the URL.
        // (The stable packages page also provides an arm64 MSI, but the docs guidance is authoritative.)
        var arch = RuntimeInformation.OSArchitecture;
        return arch switch
        {
            Architecture.X64 => DefaultMsiAmd64,
            Architecture.X86 => DefaultMsiX86,
            Architecture.Arm64 => DefaultMsiX86,
            _ => DefaultMsiAmd64,
        };
    }
}
