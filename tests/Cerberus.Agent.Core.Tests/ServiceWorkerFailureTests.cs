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

    [Fact]
    public async Task SelectedBaseExceptionKeepsAsyncThrowOriginAndCode()
    {
        var worker = Task.Run(ThrowAcrossTaskBoundaryAsync);
        var thrown = await Assert.ThrowsAsync<UnauthorizedAccessException>(() => worker);
        var selected = worker.Exception!.GetBaseException();
        Assert.Same(thrown, selected);

        var message = ServiceWorkerFailure.Describe(selected);
        Assert.Contains("HResult=0x80070005", message);
        Assert.Contains(nameof(ThrowAcrossTaskBoundaryAsync), message);
        Assert.Contains("MoveNext", message);
        Assert.DoesNotContain("SECRET", message);
        Assert.DoesNotContain("private", message);
        Assert.DoesNotContain("C:/", message);
    }

    private static async Task ThrowAcrossTaskBoundaryAsync()
    {
        await Task.Yield();
        var failure = new UnauthorizedAccessException("SECRET-message C:/private token=private-value");
        failure.Data["private"] = "SECRET-data";
        throw failure;
    }

    [Fact]
    public void UnavailableMethodMetadataKeepsCodeWithoutExceptionContents()
    {
        var message = ServiceWorkerFailure.Describe(new UnauthorizedAccessException("SECRET C:/private"));
        Assert.Equal("Cerberus agent worker failed (UnauthorizedAccessException). HResult=0x80070005", message);
    }

    [Fact]
    public void LongDeclaringTypeKeepsThrowMethodWithinOriginBudget()
    {
        var failure = Assert.Throws<UnauthorizedAccessException>(
            LongDeclaringTypeForTestingTheBoundedFailureOriginWithoutDroppingTheThrowMethod
                .AdditionalLongDeclaringTypeForTestingThatTheOriginCannotExceedItsDeclaredBudget.ThrowForCap);
        var message = ServiceWorkerFailure.Describe(failure);
        Assert.True(failure.TargetSite!.DeclaringType!.FullName!.Length > 200);
        var origin = message[(message.IndexOf("; origin=", StringComparison.Ordinal) + 9)..];
        Assert.InRange(origin.Length, 1, 200);
        Assert.EndsWith(".ThrowForCap", origin);
    }

    private static class LongDeclaringTypeForTestingTheBoundedFailureOriginWithoutDroppingTheThrowMethod
    {
        internal static class AdditionalLongDeclaringTypeForTestingThatTheOriginCannotExceedItsDeclaredBudget
        {
            [MethodImpl(MethodImplOptions.NoInlining)]
            internal static void ThrowForCap() => throw new UnauthorizedAccessException("SECRET");
        }
    }
}
