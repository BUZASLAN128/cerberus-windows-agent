#if !CERBERUS_EXCLUDE_UPDATE_CAMPAIGN // Campaign code is not compiled with -p:ExcludeUpdateCampaignCode=true.
using System.Runtime.InteropServices;
using System.Text;
using Cerberus.Agent.App.Updates;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class AgentUpdateLabRemediationTests
{
    [Fact]
    public void NativeProductVersionMatchesWindowsStringProjection()
    {
        var image = typeof(AgentUpdateLabRemediationTests).Assembly.Location;
        var expected = System.Diagnostics.FileVersionInfo.GetVersionInfo(image).ProductVersion;
        Assert.False(string.IsNullOrEmpty(expected));
        Assert.Equal(expected, AgentInstalledProductVersion.Read(image));
    }

    [Fact]
    public void NativeProductVersionRejectsMissingAndMalformedImages()
    {
        Assert.Throws<InvalidOperationException>(() => AgentInstalledProductVersion.Read("relative.exe"));
        Assert.Throws<InvalidOperationException>(() => AgentInstalledProductVersion.Read("C:\\bad\0.exe"));
        var path = Path.Combine(Path.GetTempPath(), "cerberus-version-" + Guid.NewGuid().ToString("N"));
        Assert.Throws<InvalidOperationException>(() => AgentInstalledProductVersion.Read(path));
        try
        {
            File.WriteAllBytes(path, [0x4d, 0x5a, 0, 0, 0, 0]);
            Assert.Throws<InvalidOperationException>(() => AgentInstalledProductVersion.Read(path));
        }
        finally { File.Delete(path); }
    }

    [Theory]
    [InlineData(0U)]
    [InlineData(5U)]
    [InlineData(1048577U)]
    [InlineData(uint.MaxValue)]
    public void NativeProductVersionRejectsInvalidAllocationSizes(uint size) =>
        Assert.Throws<InvalidOperationException>(() => AgentInstalledProductVersion.RequireResourceSize(size));

    [Fact]
    public void NativeProductVersionBoundsBorrowedPointersBeforeDereferencing()
    {
        var block = Marshal.AllocHGlobal(32);
        try
        {
            AgentInstalledProductVersion.RequireSlice(block, 32, block + 28, 4);
            Assert.Throws<InvalidOperationException>(() => AgentInstalledProductVersion.RequireSlice(block, 32, IntPtr.Zero, 4));
            Assert.Throws<InvalidOperationException>(() => AgentInstalledProductVersion.RequireSlice(block, 32, block - 2, 4));
            Assert.Throws<InvalidOperationException>(() => AgentInstalledProductVersion.RequireSlice(block, 32, block + 30, 4));
            Assert.Throws<InvalidOperationException>(() => AgentInstalledProductVersion.RequireSlice(block, 32, block + 1, 4));
            Assert.Throws<InvalidOperationException>(() => AgentInstalledProductVersion.RequireSlice(new IntPtr(-4), 32, new IntPtr(-4), 4));
            Assert.Throws<InvalidOperationException>(() => AgentInstalledProductVersion.ReadUnicode(block, 32, block, uint.MaxValue));
        }
        finally { Marshal.FreeHGlobal(block); }
    }

    [Fact]
    public void NativeProductVersionTranslationUsesBytesAndFirstLanguageCodePage()
    {
        byte[] data = [0x09, 0x04, 0xb0, 0x04, 0x1f, 0x04, 0xe4, 0x04];
        var block = Marshal.AllocHGlobal(data.Length);
        try
        {
            Marshal.Copy(data, 0, block, data.Length);
            Assert.Equal(0x040904B0U, AgentInstalledProductVersion.ReadTranslation(block, data.Length, block, 8));
            Assert.Throws<InvalidOperationException>(() => AgentInstalledProductVersion.ReadTranslation(block, data.Length, block, 2));
            Assert.Throws<InvalidOperationException>(() => AgentInstalledProductVersion.ReadTranslation(block, data.Length, block, 6));
        }
        finally { Marshal.FreeHGlobal(block); }
    }

    [Fact]
    public void NativeProductVersionPreservesUnicodeProductStringAndChecksTermination()
    {
        const string value = "0.2.1011+\u00e7\u4e2d\U0001f680";
        var data = Encoding.Unicode.GetBytes(value + "\0");
        var block = Marshal.AllocHGlobal(data.Length);
        try
        {
            Marshal.Copy(data, 0, block, data.Length);
            Assert.Equal(value, AgentInstalledProductVersion.ReadUnicode(block, data.Length, block, (uint)data.Length / 2));
            Assert.Throws<InvalidOperationException>(() => AgentInstalledProductVersion.ReadUnicode(block, data.Length, block, 0));
            Marshal.WriteInt16(block, data.Length - 2, 1);
            Assert.Throws<InvalidOperationException>(() => AgentInstalledProductVersion.ReadUnicode(block, data.Length, block, (uint)data.Length / 2));
            Marshal.WriteInt16(block, data.Length - 2, 0);
            Marshal.WriteInt16(block, 2, 0);
            Assert.Throws<InvalidOperationException>(() => AgentInstalledProductVersion.ReadUnicode(block, data.Length, block, (uint)data.Length / 2));
            Marshal.WriteInt16(block, 2, unchecked((short)0xd800));
            Assert.Throws<InvalidOperationException>(() => AgentInstalledProductVersion.ReadUnicode(block, data.Length, block, (uint)data.Length / 2));
        }
        finally { Marshal.FreeHGlobal(block); }
    }
}
#endif
