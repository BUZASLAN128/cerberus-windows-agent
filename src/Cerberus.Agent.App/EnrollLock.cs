using System.IO;
using System.Runtime.Versioning;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.App;

internal enum EnrollLockOutcome { Acquired, Busy, Untrusted }

/// <summary>
/// Cross-process lock of the enroll run (server profile): one run, or one rollback, at a time may stage, discard or
/// remove credentials. An exclusive file inside the protected data folder, so a standard user can neither pre-create
/// nor hold it. Take it only after the data-root gate has passed.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class EnrollLock : IDisposable
{
    internal const string FileName = "enroll.lock";
    private const int SharingViolation = 32;
    private const int LockViolation = 33;

    private readonly FileStream _file;

    private EnrollLock(FileStream file) => _file = file;

    internal static string DefaultPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), AgentInstallIdentity.DataDirName, FileName);

    /// <summary>
    /// Waits up to <paramref name="wait"/> (zero = do not wait). <see cref="EnrollLockOutcome.Untrusted"/> when the file
    /// cannot be opened for a reason other than another holder.
    /// </summary>
    internal static EnrollLockOutcome TryAcquire(TimeSpan wait, out EnrollLock? held, string? path = null)
    {
        held = null;
        var deadline = DateTime.UtcNow + wait;
        while (true)
        {
            try
            {
                held = new EnrollLock(new FileStream(path ?? DefaultPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None));
                return EnrollLockOutcome.Acquired;
            }
            catch (IOException ex) when ((ex.HResult & 0xFFFF) is SharingViolation or LockViolation)
            {
                if (DateTime.UtcNow >= deadline)
                    return EnrollLockOutcome.Busy;
                Thread.Sleep(100);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                return EnrollLockOutcome.Untrusted;
            }
        }
    }

    public void Dispose() => _file.Dispose();
}
