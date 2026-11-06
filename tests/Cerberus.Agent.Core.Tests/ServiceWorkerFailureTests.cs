using System.Runtime.CompilerServices;
using Cerberus.Agent.App;

namespace Cerberus.Agent.Core.Tests;

public sealed class ServiceWorkerFailureTests
{
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static Exception CaptureFailure()
    {
        try
        {
            throw new UnauthorizedAccessException("SECRET-message C:/private/location token=private-value");
        }
        catch (Exception failure)
        {
            failure.Data["private-data"] = "SECRET-data";
            return failure;
        }
    }

    [Fact]
    public void DescriptionKeepsActualThrowLocationAndCode_WithoutExceptionContents()
    {
        var failure = CaptureFailure();
        var message = ServiceWorkerFailure.Describe(failure);

        Assert.Contains("UnauthorizedAccessException", message);
        Assert.Contains("HResult=0x80070005", message);
        Assert.Contains("ServiceWorkerFailureTests.CaptureFailure", message);
        Assert.DoesNotContain("SECRET", message);
        Assert.DoesNotContain("private", message);
        Assert.DoesNotContain("C:/", message);
        Assert.True(message.Length < 1800);
    }

    [Fact]
    public void MissingFailureStillHasSafeFailFastMessage()
        => Assert.Equal("Cerberus agent worker failed (unknown).", ServiceWorkerFailure.Describe(null));
}
