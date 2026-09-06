using System.ComponentModel;
using System.Text.Json;

namespace Cerberus.Agent.Core;

public enum AgentInstallerHealthPhase
{
    RuntimePath, ServiceExecutableHash, ServiceAssemblyHash, ServiceState, ServiceImage,
    PipeConnect, PipeAuthority, StatusRequest, StatusResponse, ResponseSuccess, ResponseVersion,
    LifecycleAuthority, LifecycleOpen, LifecycleLength, LifecycleJson, LifecycleState,
}

/// <summary>Failure-only installer evidence. Never includes exception messages, paths or raw local-control data.</summary>
public sealed record AgentInstallerHealthDiagnostic(
    string SchemaVersion, string Operation, DateTimeOffset RecordedAtUtc, string Phase, string ErrorCategory, string ExceptionType,
    int? NativeErrorCode, string? ExpectedVersion, string? ObservedVersion, uint? ServiceProcessId,
    uint? PipeProcessId, bool? ResponseSuccess)
{
    public static AgentInstallerHealthDiagnostic Capture(AgentInstallerHealthPhase phase, Exception error,
        string? expectedVersion, string? observedVersion, uint? serviceProcessId, uint? pipeProcessId, bool? responseSuccess)
    {
        if (!Enum.IsDefined(phase)) throw new ArgumentOutOfRangeException(nameof(phase));
        var category = error switch
        {
            UnauthorizedAccessException => "access_denied",
            System.Security.SecurityException => "security_error",
            Win32Exception => "win32_error",
            OperationCanceledException => "cancelled",
            TimeoutException => "timeout",
            JsonException => "invalid_json",
            InvalidDataException => "invalid_data",
            IOException => "io_error",
            InvalidOperationException => "invalid_operation",
            ArgumentException => "invalid_argument",
            _ => "unexpected_error",
        };
        var exceptionType = error switch
        {
            UnauthorizedAccessException => nameof(UnauthorizedAccessException),
            System.Security.SecurityException => nameof(System.Security.SecurityException),
            Win32Exception => nameof(Win32Exception),
            TaskCanceledException => nameof(TaskCanceledException),
            OperationCanceledException => nameof(OperationCanceledException),
            TimeoutException => nameof(TimeoutException),
            JsonException => nameof(JsonException),
            InvalidDataException => nameof(InvalidDataException),
            FileNotFoundException => nameof(FileNotFoundException),
            DirectoryNotFoundException => nameof(DirectoryNotFoundException),
            EndOfStreamException => nameof(EndOfStreamException),
            IOException => nameof(IOException),
            InvalidOperationException => nameof(InvalidOperationException),
            ArgumentException => nameof(ArgumentException),
            _ => "UnexpectedException",
        };
        return new("agent.installer.health-diagnostic.v1", "health", DateTimeOffset.UtcNow,
            JsonNamingPolicy.SnakeCaseLower.ConvertName(phase.ToString()), category, exceptionType,
            error is Win32Exception native ? native.NativeErrorCode : null,
            PublicVersion(expectedVersion), PublicVersion(observedVersion), serviceProcessId, pipeProcessId, responseSuccess);
    }

    private static string? PublicVersion(string? value)
        => value is { Length: > 0 and <= 96 } && value.All(character =>
            char.IsAsciiLetterOrDigit(character) || character is '.' or '-' or '+' or '_') ? value : null;
}
