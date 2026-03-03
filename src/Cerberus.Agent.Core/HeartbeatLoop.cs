using System.Security.Cryptography;

namespace Cerberus.Agent.Core;

public sealed class HeartbeatLoop
{
    private readonly AgentApiClient _api;
    private readonly CommandDispatcher _dispatcher;
    private readonly TimeSpan _minDelayOnError;
    private readonly IAgentLogger _log;
    private readonly IAgentStatusProvider? _status;
    private readonly Func<CancellationToken, Task<object?>>? _adStatusProvider;

    public HeartbeatLoop(
        AgentApiClient api,
        CommandDispatcher dispatcher,
        TimeSpan minDelayOnError,
        IAgentStatusProvider? statusProvider = null,
        Func<CancellationToken, Task<object?>>? adStatusProvider = null,
        IAgentLogger? log = null)
    {
        _api = api;
        _dispatcher = dispatcher;
        _minDelayOnError = minDelayOnError;
        _status = statusProvider;
        _adStatusProvider = adStatusProvider;
        _log = log ?? NullAgentLogger.Instance;
    }

    public async Task RunAsync(CancellationToken ct)
    {
        var degraded = false;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                object? tailscale = null;
                if (_status is not null)
                {
                    try
                    {
                        tailscale = await _status.GetTailscaleAsync(ct);
                    }
                    catch (Exception ex)
                    {
                        _log.Warn($"Status provider error: {ex.GetType().Name}: {ex.Message}");
                    }
                }

                var hbReq = new
                {
                    status = degraded ? "degraded" : "connected",
                    tailscale,
                    ad = _adStatusProvider is null ? null : await _adStatusProvider(ct),
                    capabilities = _dispatcher.HandlerTypes,
                };

                var hb = await _api.HeartbeatAsync(hbReq, ct);

                degraded = false;

                foreach (var cmd in hb.PendingCommands)
                {
                    var res = await _dispatcher.DispatchAsync(cmd, ct);
                    var resultBody = new
                    {
                        status = res.Status,
                        exit_code = res.ExitCode,
                        stdout = res.Stdout,
                        stderr = res.Stderr,
                        post_verify = res.PostVerify,
                    };
                    await _api.SubmitCommandResultAsync(cmd.Id, resultBody, ct);
                }

                var delay = ApplyJitter(hb.NextPollSeconds, 0.20);
                await Task.Delay(TimeSpan.FromSeconds(delay), ct);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                degraded = true;
                _log.Warn($"Heartbeat loop error: {ex.GetType().Name}: {ex.Message}");
                await Task.Delay(_minDelayOnError, ct);
            }
        }
    }

    private static int ApplyJitter(int seconds, double pct)
    {
        var baseSec = Math.Max(1, seconds);
        var delta = (int)Math.Ceiling(baseSec * pct);
        var off = RandomNumberGenerator.GetInt32(-delta, delta + 1);
        return Math.Max(1, baseSec + off);
    }
}
