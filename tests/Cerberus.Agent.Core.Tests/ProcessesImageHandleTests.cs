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

    [Theory]
    [InlineData(0, false)]
    [InlineData(0x00000104, false)]
    [InlineData(unchecked((int)0xC000050B), false)] // a reparse point was refused: never retried
    [InlineData(unchecked((int)0xC0000034), false)]
    [InlineData(unchecked((int)0xC0000022), false)]
    [InlineData(unchecked((int)0xC000000D), true)] // OBJ_DONT_REPARSE unsupported (Server 2016)
    public void ShouldRetryWithoutDontReparse_OnlyForInvalidParameter(int status, bool expected)
        => Assert.Equal(expected, LocalImageFile.ShouldRetryWithoutDontReparse(status));

    [Theory]
    [InlineData(@"C:\Program Files\App\a.exe", @"\\?\C:\Program Files\App\a.exe", true)]
    [InlineData(@"C:\Program Files\App\a.exe", @"\\?\c:\PROGRAM FILES\app\A.EXE", true)]
    [InlineData(@"C:\Program Files\App\a.exe", @"\\?\C:\Other\App\a.exe", false)]
    [InlineData(@"C:\Program Files\App\a.exe", @"\\?\D:\Program Files\App\a.exe", false)]
    [InlineData(@"C:\Program Files\App\a.exe", @"\\?\UNC\host\share\App\a.exe", false)]
    [InlineData(@"C:\Program Files\App\a.exe", @"\\?\Volume{00000000-0000-0000-0000-000000000000}\Program Files\App\a.exe", false)]
    [InlineData(@"C:\Program Files\App\a.exe", @"\\?\C:\Program Files\App\a.exe\", false)]
    [InlineData(@"C:\PROGRA~1\App\a.exe", @"\\?\C:\Program Files\App\a.exe", false)]
    [InlineData(@"C:\Program Files\App\a.exe", @"C:\Program Files\App\a.exe", false)]
    [InlineData(@"C:\Program Files\App\a.exe", null, false)]
    public void FinalPathMatches_RequiresTheSamePathIgnoringCaseOnly(string requested, string? final, bool expected)
        => Assert.Equal(expected, LocalImageFile.FinalPathMatches(requested, final));

    [Fact]
    public void TryOpen_FallbackWalk_OpensTheRealFileAndStopsAtAJunction()
    {
        using var dir = new TempDir();
        var real = Directory.CreateDirectory(Path.Combine(dir.Path, "real")).FullName;
        var file = Path.Combine(real, "a.exe");
        File.WriteAllText(file, "x");
        var junction = Path.Combine(dir.Path, "link");
        CreateJunction(junction, real);
        var throughJunction = Path.Combine(junction, "a.exe");

        using (var direct = LocalImageFile.TryOpen(file, forceFallback: true))
            Assert.NotNull(direct);
        // A plain open follows the junction; the walk opens the junction itself and stops at that directory.
        using (Open(throughJunction)) { }
        Assert.Equal(LocalImageFile.WalkStep.ReparsePoint, LocalImageFile.OpenByWalk(throughJunction, out var walked));
        Assert.Null(walked);
        Assert.Null(LocalImageFile.TryOpen(throughJunction, forceFallback: true));

        // A junction as the image name itself, aimed at the real file: opened as itself, never followed. It is a
        // directory, so the non-directory open is refused before any attribute read.
        var finalJunction = Path.Combine(dir.Path, "b.exe");
        CreateJunction(finalJunction, file);
        Assert.Equal(LocalImageFile.WalkStep.OpenFailed, LocalImageFile.OpenByWalk(finalJunction, out var final));
        Assert.Null(final);
        Assert.Null(LocalImageFile.TryOpen(finalJunction, forceFallback: true));
    }

    [Fact]
    public void TryOpen_FallbackWalk_VerifiesTheSignerThroughTheWalkedHandle()
    {
        var signed = typeof(object).Assembly.Location;
        Assert.True(AgentUpdateAuthenticode.TryGetValidSignerSubject(signed, out var expected));

        using var handle = LocalImageFile.TryOpen(signed, forceFallback: true);
        Assert.NotNull(handle);
        Assert.True(AgentUpdateAuthenticode.TryGetValidSignerSubject(handle, signed, out var subject));
        Assert.Equal(expected, subject);
    }

    [Fact]
    public void SplitComponents_AcceptsADriveLetterPathOfPlainNames()
    {
        Assert.Equal(["Program Files", "App", "a.exe"], LocalImageFile.SplitComponents(@"C:\Program Files\App\a.exe")!);
        Assert.Equal(["a.exe"], LocalImageFile.SplitComponents(@"d:\a.exe")!);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(@"C:\")]
    [InlineData(@"C:a.exe")]
    [InlineData(@"\\host\share\a.exe")]
    [InlineData(@"\\?\C:\a.exe")]
    [InlineData(@"\\?\UNC\host\share\a.exe")]
    [InlineData(@"\\?\Volume{00000000-0000-0000-0000-000000000000}\a.exe")]
    [InlineData(@"\??\C:\a.exe")]
    [InlineData(@"C:\App\..\a.exe")]
    [InlineData(@"C:\App\.\a.exe")]
    [InlineData(@"C:\App\\a.exe")]
    [InlineData(@"C:\App\")]
    [InlineData(@"C:\App\a.exe:stream")]
    [InlineData(@"C:\App/x\a.exe")]
    public void SplitComponents_RejectsAnythingButPlainNamesUnderADriveRoot(string? path)
        => Assert.Null(LocalImageFile.SplitComponents(path));

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
        CreateJunction(junction, real);

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

    [Fact]
    public void TryOpen_PrimaryPath_OpensCommonImagesAndMixedCasePaths()
    {
        var notepad = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "notepad.exe");
        var coreLib = typeof(object).Assembly.Location;
        foreach (var path in new[] { notepad, coreLib, notepad.ToUpperInvariant(), coreLib.ToLowerInvariant() })
        {
            using var handle = LocalImageFile.TryOpen(path);
            Assert.NotNull(handle);
        }

        Assert.True(AgentUpdateAuthenticode.TryGetValidSignerSubject(coreLib, out var expected));
        using var viaPrimary = LocalImageFile.TryOpen(coreLib.ToUpperInvariant());
        Assert.True(AgentUpdateAuthenticode.TryGetValidSignerSubject(viaPrimary!, coreLib, out var subject));
        Assert.Equal(expected, subject);
    }

    [Fact]
    public void Accept_RefusesAFinalPathThatIsNotTheRequestedPath()
    {
        using var dir = new TempDir();
        var file = dir.File("a.exe", "x");
        var other = dir.File("b.exe", "x");

        using (var ok = LocalImageFile.Accept(Open(file), requested: file.ToUpperInvariant()))
            Assert.NotNull(ok);
        Assert.Null(LocalImageFile.Accept(Open(file), requested: other));
    }

    [Fact]
    public void TryGetKey_ChangesAfterAnInPlaceRewriteWithTheTimestampRestored_OrIsNullWithoutAJournal()
    {
        using var dir = new TempDir();
        var file = dir.File("a.exe", "AAAAAAAA");
        var written = File.GetLastWriteTimeUtc(file);

        using var handle = LocalImageFile.TryOpen(file);
        Assert.NotNull(handle);
        var hasKey = ProcessesTelemetrySectionCollector.TryGetKey(handle, file, out var before);
        Console.WriteLine("signer key available on the temp volume: " + hasKey);

        using (var writer = new FileStream(file, FileMode.Open, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete))
            writer.Write("BBBBBBBB"u8);
        File.SetLastWriteTimeUtc(file, written);

        var hasKeyAfter = ProcessesTelemetrySectionCollector.TryGetKey(handle, file, out var after);
        Assert.Equal(hasKey, hasKeyAfter);
        if (hasKey)
            Assert.NotEqual(before, after); // same size, same mtime, same file id: the USN still moved
    }

    [Fact]
    public void TryParseUsn_ReadsV2AndV3AndRejectsMalformedOrZero()
    {
        static byte[] Record(ushort major, int usnOffset, long usn, uint length)
        {
            var b = new byte[64];
            BitConverter.TryWriteBytes(b.AsSpan(0), length);
            BitConverter.TryWriteBytes(b.AsSpan(4), major);
            BitConverter.TryWriteBytes(b.AsSpan(usnOffset), usn);
            return b;
        }

        Assert.True(ProcessesTelemetrySectionCollector.TryParseUsn(Record(2, 24, 1234, 60), 64, out var v2));
        Assert.Equal(1234, v2);
        Assert.True(ProcessesTelemetrySectionCollector.TryParseUsn(Record(3, 32, 5678, 60), 64, out var v3));
        Assert.Equal(5678, v3);
        Assert.False(ProcessesTelemetrySectionCollector.TryParseUsn(Record(2, 24, 0, 60), 64, out _));
        Assert.False(ProcessesTelemetrySectionCollector.TryParseUsn(Record(4, 24, 9, 60), 64, out _));
        Assert.False(ProcessesTelemetrySectionCollector.TryParseUsn(Record(2, 24, 9, 200), 64, out _)); // record longer than the data
        Assert.False(ProcessesTelemetrySectionCollector.TryParseUsn(Record(2, 24, 9, 20), 64, out _)); // record too short for a Usn
        Assert.False(ProcessesTelemetrySectionCollector.TryParseUsn(Record(2, 24, 9, 60), 16, out _));
    }

    [Fact]
    public void SignerFor_CachesOnlyWhileTheKeyIsTheSame_AndNeverWithoutAKey()
    {
        using var dir = new TempDir();
        var file = dir.File("a.exe", "x");
        using var handle = Open(file);
        var path = file + Guid.NewGuid().ToString("N"); // cache key path unique to this test
        var verifications = 0;
        bool Verify(SafeFileHandle h, string p, out string? signer) { verifications++; signer = "Signer"; return true; }
        var usn = 10L;
        bool Key(SafeFileHandle h, string p, out ProcessesTelemetrySectionCollector.SignerKey key)
        {
            key = new(p, 1, 2, 3, usn);
            return true;
        }

        Assert.Equal("Signer", ProcessesTelemetrySectionCollector.SignerFor(handle, path, Key, Verify));
        Assert.Equal("Signer", ProcessesTelemetrySectionCollector.SignerFor(handle, path, Key, Verify));
        Assert.Equal(1, verifications); // same key: a hit

        usn = 11; // content changed: new key, verified again
        Assert.Equal("Signer", ProcessesTelemetrySectionCollector.SignerFor(handle, path, Key, Verify));
        Assert.Equal(2, verifications);

        // The key moves during verification: reported nothing, cached nothing.
        var calls = 0;
        bool Moving(SafeFileHandle h, string p, out ProcessesTelemetrySectionCollector.SignerKey key)
        {
            key = new(p, 1, 2, 3, 100 + calls++);
            return true;
        }
        Assert.Null(ProcessesTelemetrySectionCollector.SignerFor(handle, path + "m", Moving, Verify));
        Assert.Equal(3, verifications);

        // No key (no change journal): verified on every call, never stored.
        bool NoKey(SafeFileHandle h, string p, out ProcessesTelemetrySectionCollector.SignerKey key) { key = default; return false; }
        Assert.Equal("Signer", ProcessesTelemetrySectionCollector.SignerFor(handle, path + "n", NoKey, Verify));
        Assert.Equal("Signer", ProcessesTelemetrySectionCollector.SignerFor(handle, path + "n", NoKey, Verify));
        Assert.Equal(5, verifications);
    }

    /// <summary>Real junction through <c>mklink /J</c>, which needs no elevation (a file or directory symlink would).</summary>
    private static void CreateJunction(string junction, string target)
    {
        using var mklink = Process.Start(new ProcessStartInfo("cmd.exe") { ArgumentList = { "/c", "mklink", "/J", junction, target }, UseShellExecute = false, RedirectStandardOutput = true, CreateNoWindow = true })!;
        mklink.StandardOutput.ReadToEnd();
        mklink.WaitForExit();
        Assert.Equal(0, mklink.ExitCode);
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
            // Remove the junctions themselves first (non-recursive) so the recursive delete never meets one.
            foreach (var entry in new DirectoryInfo(Path).EnumerateFileSystemInfos())
            {
                if (entry.Attributes.HasFlag(FileAttributes.ReparsePoint))
                    Directory.Delete(entry.FullName);
            }
            Directory.Delete(Path, recursive: true);
        }
    }
}
