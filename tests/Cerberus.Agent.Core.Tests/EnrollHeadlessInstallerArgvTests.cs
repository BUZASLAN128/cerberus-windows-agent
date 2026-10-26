using Cerberus.Agent.App;

namespace Cerberus.Agent.Core.Tests;

// Support tier: the argv shape the MSI custom action produces, and the shapes a quote in the proof property could produce.
public sealed class EnrollHeadlessInstallerArgvTests
{
    private const string Proof = "aaaaaaaaaa.bbbbbbbbbb.cccccccccc";

    [Fact]
    public void Exact_installer_shape_returns_the_proof()
    {
        string[] argv = ["--enroll-headless", "--proof-from-installer", Proof, "--install-service"];

        Assert.Equal(Proof, EnrollHeadlessMode.ReadInstallerValue(argv));
    }

    [Theory]
    [InlineData("--enroll-headless", "--proof-from-installer", Proof, "--install-service", "--extra")]
    [InlineData("--enroll-headless", "--proof-from-installer", Proof)]
    [InlineData("--enroll-headless", "--proof-from-installer", Proof, "--install-service", "--proof-file", "x.txt")]
    [InlineData("--enroll-headless", "--proof-from-installer", "a.b.c", "--proof-stdin", "--install-service")]
    [InlineData("--enroll-headless", "--proof-from-installer=" + Proof, "--install-service", "--install-service")]
    [InlineData("--proof-from-installer", Proof, "--enroll-headless", "--install-service")]
    [InlineData("--enroll-headless", "--proof-from-installer", "\"" + Proof, "--install-service")]
    [InlineData("--enroll-headless", "--proof-from-installer", Proof + " --extra", "--install-service")]
    [InlineData("--enroll-headless", "--proof-from-installer", " " + Proof, "--install-service")]
    [InlineData("--enroll-headless", "--proof-from-installer", "", "--install-service")]
    public void Any_other_shape_is_refused(params string[] argv)
    {
        Assert.Null(EnrollHeadlessMode.ReadInstallerValue(argv));
    }
}
