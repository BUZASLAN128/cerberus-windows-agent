using System.Diagnostics;
using Cerberus.Agent.App.Telemetry.Sections;
using Microsoft.Win32.SafeHandles;

namespace Cerberus.Agent.Core.Tests;

/// <summary>
/// The signer open that cannot follow a reparse point: NT path building and status acceptance (support), plus real
/// opens of local files, a real junction, and Authenticode verification through the handle against real files.
/// </summary>
public sealed class ProcessesImageHandleTests
{
    [Theory]
    [InlineData(@"C:\Windows\x.exe", @"\??\C:\Windows\x.exe")]
    [InlineData(@"c:\Windows\x.exe", @"\??\c:\Windows\x.exe")]
    [InlineData(@"C:/Windows/./a/../x.exe", @"\??\C:\Windows\x.exe")]
    public void BuildNtPath_PrefixesNormalizedDriveLetterPath(string path, string expected)
        => Assert.Equal(expected, LocalImageFile.BuildNtPath(path));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(@"C:\")]
    [InlineData(@"\\host\share\x.exe")]
    [InlineData(@"\\?\UNC\host\share\x.exe")]
    [InlineData(@"\\?\C:\x.exe")]
    [InlineData(@"\\.\C:\x.exe")]
    [InlineData("//host/share/x.exe")]
    [InlineData("x.exe")]
    [InlineData("C:x.exe")]
    [InlineData(@"\Windows\x.exe")]
    public void BuildNtPath_RejectsEverythingButADriveLetterFile(string? path)
        => Assert.Null(LocalImageFile.BuildNtPath(path));

    [Fact]
    public void BuildNtPath_RejectsNamesLongerThanAUnicodeString()
    {
        var segment = new string('a', 200);
        var path = @"C:\" + string.Join('\\', Enumerable.Repeat(segment, 170)) + @"\x.exe";
        Assert.Null(LocalImageFile.BuildNtPath(path));
        Assert.NotNull(LocalImageFile.BuildNtPath(@"C:\" + string.Join('\\', Enumerable.Repeat(segment, 150)) + @"\x.exe"));
    }

    [Theory]
    [InlineData(0x00000104)] // STATUS_REPARSE: a success code, still not an open
    [InlineData(unchecked((int)0xC000050B))] // STATUS_REPARSE_POINT_ENCOUNTERED
    [InlineData(unchecked((int)0xC000000D))] // STATUS_INVALID_PARAMETER: OBJ_DONT_REPARSE unsupported
    [InlineData(unchecked((int)0xC0000034))] // STATUS_OBJECT_NAME_NOT_FOUND
    [InlineData(unchecked((int)0xC0000022))] // STATUS_ACCESS_DENIED
    [InlineData(unchecked((int)0xC00000BA))] // STATUS_FILE_IS_A_DIRECTORY
    public void IsOpened_AcceptsOnlyStatusSuccess(int status)
    {
        Assert.False(LocalImageFile.IsOpened(status));
        Assert.True(LocalImageFile.IsOpened(0));
    }

    [Fact]
    public void TryOpen_UnsignedLocalFile_OpensAndReportsNoSigner()
    {
        using var dir = new TempDir();
        var file = dir.File("plain.exe", "not a signed image");

        using (var handle = LocalImageFile.TryOpen(file))
        {
            Assert.NotNull(handle);
            Assert.False(AgentUpdateAuthenticode.TryGetValidSignerSubject(handle, file, out _));
        }

        Assert.Null(ProcessesTelemetrySectionCollector.ReadSignerCached(file));
        Assert.Null(LocalImageFile.TryOpen(Path.Combine(dir.Path, "missing.exe")));
        Assert.Null(LocalImageFile.TryOpen(dir.Path)); // a directory is never an image
    }

    [Fact]
    public void TryOpen_JunctionInThePath_FailsWhileTheRealPathOpens()
    {
        using var dir = new TempDir();
        var real = Directory.CreateDirectory(Path.Combine(dir.Path, "real")).FullName;
        var file = Path.Combine(real, "a.exe");
        File.WriteAllText(file, "x");
        var junction = Path.Combine(dir.Path, "link");
        // mklink /J needs no elevation (a file or directory symlink would).
        using (var mklink = Process.Start(new ProcessStartInfo("cmd.exe") { ArgumentList = { "/c", "mklink", "/J", junction, real }, UseShellExecute = false, RedirectStandardOutput = true, CreateNoWindow = true })!)
        {
            mklink.StandardOutput.ReadToEnd();
            mklink.WaitForExit();
            Assert.Equal(0, mklink.ExitCode);
        }

        using (var direct = LocalImageFile.TryOpen(file))
            Assert.NotNull(direct);
        Assert.Null(LocalImageFile.TryOpen(Path.Combine(junction, "a.exe")));
    }

    [Fact]
    public void HandleOverload_ReadsTheHandleNotTheDisplayPath()
    {
        var signed = typeof(object).Assembly.Location; // embedded Authenticode signature in an official runtime
        Assert.True(AgentUpdateAuthenticode.TryGetValidSignerSubject(signed, out var expected));

        using var dir = new TempDir();
        var unsigned = dir.File("plain.exe", "not a signed image");
        var missing = Path.Combine(dir.Path, "missing.dll");

        using (var handle = Open(signed))
        {
            Assert.True(AgentUpdateAuthenticode.TryGetValidSignerSubject(handle, missing, out var subject));
            Assert.Equal(expected, subject);
        }

        using (var handle = Open(unsigned))
            Assert.False(AgentUpdateAuthenticode.TryGetValidSignerSubject(handle, signed, out _));

        using (var handle = LocalImageFile.TryOpen(signed))
        {
            Assert.NotNull(handle);
            Assert.True(AgentUpdateAuthenticode.TryGetValidSignerSubject(handle, signed, out var viaNoReparse));
            Assert.Equal(expected, viaNoReparse);
        }

        Assert.Equal(ProcessesTelemetrySectionCollector.SimpleNameFromSubject(expected), ProcessesTelemetrySectionCollector.ReadSignerCached(signed));
    }

    private static SafeFileHandle Open(string path)
        => File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);

    private sealed class TempDir : IDisposable
    {
        public string Path { get; } = Directory.CreateDirectory(System.IO.Path.Combine(System.IO.Path.GetTempPath(), "cerberus-image-" + Guid.NewGuid().ToString("N"))).FullName;

        public string File(string name, string content)
        {
            var path = System.IO.Path.Combine(Path, name);
            System.IO.File.WriteAllText(path, content);
            return path;
        }

        public void Dispose()
        {
            // Remove the junction itself first so the recursive delete never walks through it.
            var link = System.IO.Path.Combine(Path, "link");
            if (Directory.Exists(link))
                Directory.Delete(link);
            Directory.Delete(Path, recursive: true);
        }
    }
}
