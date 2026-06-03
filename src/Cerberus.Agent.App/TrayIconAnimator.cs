using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Runtime.InteropServices;
using System.Windows.Threading;
using NotifyIcon = System.Windows.Forms.NotifyIcon;

namespace Cerberus.Agent.App;

internal sealed class TrayIconAnimator : IDisposable
{
    private const int FrameCount = 24;
    private static readonly Size FrameSize = new(64, 64);
    private static readonly TimeSpan MinimumVisibleDuration = TimeSpan.FromMilliseconds(4000);

    private readonly NotifyIcon _notifyIcon;
    private readonly Icon _idleIcon;
    private readonly Icon[] _frames;
    private readonly DispatcherTimer _timer;
    private DispatcherTimer? _pendingStopTimer;
    private DateTimeOffset _startedAtUtc;
    private int _frameIndex;
    private bool _running;
    private bool _disposed;

    public TrayIconAnimator(NotifyIcon notifyIcon)
    {
        _notifyIcon = notifyIcon ?? throw new ArgumentNullException(nameof(notifyIcon));
        _idleIcon = CloneIcon(notifyIcon.Icon ?? Icon.ExtractAssociatedIcon(Environment.ProcessPath ?? "") ?? SystemIcons.Application);
        _frames = CreateRotationFrames(_idleIcon);
        _timer = new DispatcherTimer(DispatcherPriority.Background)
        {
            Interval = TimeSpan.FromMilliseconds(80),
        };
        _timer.Tick += (_, _) => AdvanceFrame();
    }

    public void Start()
    {
        if (_disposed || _frames.Length == 0)
            return;

        CancelPendingStop();
        if (_running)
            return;

        _running = true;
        _startedAtUtc = DateTimeOffset.UtcNow;
        _frameIndex = 0;
        _notifyIcon.Icon = _frames[_frameIndex];
        _timer.Start();
    }

    public void Stop()
    {
        if (_disposed || !_running)
            return;

        var remaining = MinimumVisibleDuration - (DateTimeOffset.UtcNow - _startedAtUtc);
        if (remaining > TimeSpan.Zero)
        {
            ScheduleStop(remaining);
            return;
        }

        StopNow();
    }

    private void ScheduleStop(TimeSpan delay)
    {
        CancelPendingStop();
        _pendingStopTimer = new DispatcherTimer(DispatcherPriority.Background)
        {
            Interval = delay,
        };
        _pendingStopTimer.Tick += (_, _) => StopNow();
        _pendingStopTimer.Start();
    }

    private void StopNow()
    {
        CancelPendingStop();
        _timer.Stop();
        _running = false;
        _notifyIcon.Icon = _idleIcon;
    }

    private void CancelPendingStop()
    {
        _pendingStopTimer?.Stop();
        _pendingStopTimer = null;
    }

    private void AdvanceFrame()
    {
        if (!_running || _disposed || _frames.Length == 0)
            return;

        _frameIndex = (_frameIndex + 1) % _frames.Length;
        _notifyIcon.Icon = _frames[_frameIndex];
    }

    private static Icon[] CreateRotationFrames(Icon source)
    {
        var frames = new Icon[FrameCount];
        using var sourceIcon = new Icon(source, FrameSize);
        using var sourceBitmap = sourceIcon.ToBitmap();

        for (var i = 0; i < FrameCount; i++)
        {
            using var canvas = new Bitmap(FrameSize.Width, FrameSize.Height, PixelFormat.Format32bppArgb);
            using (var graphics = Graphics.FromImage(canvas))
            {
                graphics.Clear(Color.Transparent);
                graphics.CompositingMode = CompositingMode.SourceOver;
                graphics.CompositingQuality = CompositingQuality.HighQuality;
                graphics.InterpolationMode = InterpolationMode.HighQualityBicubic;
                graphics.PixelOffsetMode = PixelOffsetMode.HighQuality;
                graphics.SmoothingMode = SmoothingMode.AntiAlias;
                DrawRotatedLogo(graphics, sourceBitmap, i);
            }

            frames[i] = IconFromBitmap(canvas);
        }

        return frames;
    }

    private static void DrawRotatedLogo(Graphics graphics, Image sourceBitmap, int frameIndex)
    {
        const float drawSize = 54f;
        const float center = 32f;
        var angle = frameIndex * (360f / FrameCount);
        var target = new RectangleF(center - drawSize / 2f, center - drawSize / 2f, drawSize, drawSize);

        using var glow = new SolidBrush(Color.FromArgb(65, 45, 212, 255));
        graphics.FillEllipse(glow, 5f, 5f, 54f, 54f);

        graphics.TranslateTransform(center, center);
        graphics.RotateTransform(angle);
        graphics.TranslateTransform(-center, -center);
        graphics.DrawImage(sourceBitmap, target);
        graphics.ResetTransform();
    }

    private static Icon CloneIcon(Icon icon)
        => (Icon)icon.Clone();

    private static Icon IconFromBitmap(Bitmap bitmap)
    {
        var handle = bitmap.GetHicon();
        try
        {
            using var icon = Icon.FromHandle(handle);
            return CloneIcon(icon);
        }
        finally
        {
            _ = DestroyIcon(handle);
        }
    }

    public void Dispose()
    {
        if (_disposed)
            return;

        _timer.Stop();
        CancelPendingStop();
        _disposed = true;

        foreach (var frame in _frames)
            frame.Dispose();

        _idleIcon.Dispose();
    }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool DestroyIcon(IntPtr hIcon);
}
