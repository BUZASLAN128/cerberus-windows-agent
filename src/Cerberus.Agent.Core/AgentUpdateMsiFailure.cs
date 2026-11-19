using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace Cerberus.Agent.Core;

public enum AgentUpdateMsiFailureKind
{
    Busy,
    HealthRollback,
    Environment,
    InstallerFailed,
    GrantRefused,
}

internal enum AgentUpdateGrantRefusalDisposition
{
    Retry,
    Terminal,
    Alert,
}

internal sealed record AgentUpdateGrantRefusal(string ReasonCode, AgentUpdateGrantRefusalDisposition Disposition);

public static class AgentUpdateMsiFailure
{
    private const int MaxLogBytes = 64 * 1024 * 1024;

    private static readonly Regex EnvironmentErrorLine = new(
        @"^(?:MSI \([cs]\) \([^)]*\) \[[^\]]+\]:[ \t]*)?" +
        @"(?:CustomAction \S+ returned actual error code |MainEngineThread is returning |Note: 1: |DEBUG: Error )" +
        @"(?:1310|1336)(?:[ \t:]|$)",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);

    /// <summary>Labels a failed MSI exit, reading at most 64 MiB of a caller-owned log.</summary>
    public static AgentUpdateMsiFailureKind Classify(
        int exitCode, Stream? log, AgentInstallerHealthPhase? rollbackPhase)
    {
        if (exitCode == 1618)
            return AgentUpdateMsiFailureKind.Busy;

        // Ask the existing pin policy whether this helper phase would pin a new sequence.
        if (AgentUpdateRollbackPolicy.NextFailedInstallSequence(previous: 0, AgentUpdateErrorCodes.MsiFailed,
                planSequence: 1, rollbackPhase) > 0)
            return AgentUpdateMsiFailureKind.HealthRollback;

        if (exitCode is 1601 or 1622 or 1632 || HasEnvironmentError(log))
            return AgentUpdateMsiFailureKind.Environment;

        return AgentUpdateMsiFailureKind.InstallerFailed;
    }

    /// <summary>Classifies one completed rollback invocation, with a protected grant denial taking precedence over MSI log evidence.</summary>
    internal static (AgentUpdateMsiFailureKind Kind, AgentUpdateGrantRefusal? GrantRefusal) ClassifyRollback(
        int exitCode, Stream? log, string updatesRoot, Guid targetProductCode,
        DateTimeOffset invocationStartedUtc, DateTimeOffset invocationCompletedUtc)
        => ClassifyRollback(exitCode, log, updatesRoot, targetProductCode, invocationStartedUtc, invocationCompletedUtc,
            AgentUpdateSecurity.ValidateProtectedPath);

    internal static (AgentUpdateMsiFailureKind Kind, AgentUpdateGrantRefusal? GrantRefusal) ClassifyRollback(
        int exitCode, Stream? log, string updatesRoot, Guid targetProductCode,
        DateTimeOffset invocationStartedUtc, DateTimeOffset invocationCompletedUtc,
        Action<string, string, bool> validateProtectedPath)
    {
        if (exitCode == 1603 && targetProductCode != Guid.Empty &&
            IsUtc(invocationStartedUtc) && IsUtc(invocationCompletedUtc) && invocationStartedUtc <= invocationCompletedUtc &&
            ReadGrantResult(updatesRoot, targetProductCode, validateProtectedPath) is { Result: "denied" } result &&
            IsUtc(result.Utc) && result.Utc >= invocationStartedUtc && result.Utc <= invocationCompletedUtc)
        {
            var reasonCode = result.ReasonCode.ValueKind == JsonValueKind.String ? result.ReasonCode.GetString() : null;
            return (AgentUpdateMsiFailureKind.GrantRefused, MapGrantRefusal(reasonCode));
        }

        return (Classify(exitCode, log, rollbackPhase: null), null);
    }

    private static GrantResultRecord? ReadGrantResult(string updatesRoot, Guid targetProductCode,
        Action<string, string, bool> validateProtectedPath)
    {
        try
        {
            var root = AgentUpdateSecurity.NormalizeRoot(updatesRoot);
            var path = Path.Combine(root, AgentUpdaterContract.InstallerTransactionsDirectoryName,
                targetProductCode.ToString("N") + ".rollback-grant.json");
            validateProtectedPath(path, root, true);
            return AgentUpdateDurableFile.Read<GrantResultRecord>(path, root);
        }
        catch (Exception ex) when (AgentUpdateRollbackGrant.IsStorageFailure(ex))
        {
            return null;
        }
    }

    private static bool IsUtc(DateTimeOffset value) => value != default && value.Offset == TimeSpan.Zero;

    private static AgentUpdateGrantRefusal MapGrantRefusal(string? reasonCode)
        => reasonCode switch
        {
            "grant_floor" or "grant_version" or "grant_product_code" or "grant_msi_hash"
                => new(reasonCode, AgentUpdateGrantRefusalDisposition.Terminal),
            "grant_expired" or "grant_boot_id" or "grant_attempt_id"
                => new(reasonCode, AgentUpdateGrantRefusalDisposition.Retry),
            "grant_profile" or "grant_schema" or "grant_parse" or "grant_path" or "grant_consume"
                => new(reasonCode, AgentUpdateGrantRefusalDisposition.Alert),
            _ => new("grant_unknown", AgentUpdateGrantRefusalDisposition.Alert),
        };

    private sealed record GrantResultRecord(string? Result, [property: JsonPropertyName("reason_code")] JsonElement ReasonCode,
        DateTimeOffset Utc);

    private static bool HasEnvironmentError(Stream? log)
    {
        if (log is null || !log.CanRead)
            return false;

        try
        {
            using var boundedLog = new BoundedLogStream(log);
            using var reader = new StreamReader(boundedLog, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
            Span<char> buffer = stackalloc char[4096];
            var partialLine = new StringBuilder();
            int count;
            while ((count = reader.Read(buffer)) != 0)
            {
                var text = buffer[..count];
                int end;
                while ((end = text.IndexOfAny('\r', '\n')) >= 0)
                {
                    var line = text[..end];
                    var matches = partialLine.Length == 0
                        ? EnvironmentErrorLine.IsMatch(line)
                        : EnvironmentErrorLine.IsMatch(partialLine.Append(line).ToString());
                    partialLine.Clear();
                    if (matches)
                        return true;
                    text = text[(end + 1)..];
                }
                partialLine.Append(text);
            }

            // A line cut at the byte limit can end in the middle of an error code.
            return !boundedLog.LimitReached && partialLine.Length > 0 &&
                EnvironmentErrorLine.IsMatch(partialLine.ToString());
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ObjectDisposedException or NotSupportedException)
        {
            return false;
        }
    }

    private sealed class BoundedLogStream(Stream source) : Stream
    {
        private int _remaining = MaxLogBytes;

        public bool LimitReached => _remaining == 0;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override int Read(byte[] buffer, int offset, int count)
            => Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            var allowed = Math.Min(buffer.Length, _remaining);
            if (allowed == 0)
                return 0;

            var read = source.ReadAtLeast(buffer[..allowed], allowed, throwOnEndOfStream: false);
            _remaining -= read;
            return read;
        }

        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
