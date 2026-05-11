using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Cerberus.Agent.App;

// Minimal loopback redirect receiver for OAuth Authorization Code flow.
// Implemented via TcpListener to avoid HttpListener URLACL requirements.
internal sealed class LoopbackRedirectServer : IDisposable
{
    private readonly TcpListener _listener;

    public LoopbackRedirectServer(int port)
    {
        _listener = new TcpListener(IPAddress.Loopback, port);
        _listener.Start();
    }

    public async Task<(string Code, string State)> WaitForCodeAsync(CancellationToken ct)
    {
        using var reg = ct.Register(() => _listener.Stop());

        TcpClient client;
        try
        {
            client = await _listener.AcceptTcpClientAsync(ct);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException("Failed to accept OAuth redirect connection.", ex);
        }

        using var _ = client;
        using var stream = client.GetStream();

        // Read request (best-effort; we only need the first line).
        var firstLine = await ReadLineAsync(stream, ct);
        if (string.IsNullOrWhiteSpace(firstLine))
            throw new InvalidOperationException("OAuth redirect request is empty.");

        // Example: GET /callback?code=...&state=... HTTP/1.1
        var parts = firstLine.Split(' ');
        if (parts.Length < 2 || !string.Equals(parts[0], "GET", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("OAuth redirect request is not a GET.");

        var pathAndQuery = parts[1];
        var uri = new Uri("http://127.0.0.1" + pathAndQuery);
        var qs = ParseQuery(uri.Query);

        qs.TryGetValue("code", out var code);
        qs.TryGetValue("state", out var state);

        // Drain headers until blank line.
        while (true)
        {
            var line = await ReadLineAsync(stream, ct);
            if (line.Length == 0)
                break;
        }

        // Respond with a simple HTML page so the user understands they can close the browser tab.
        // Keep it vendor-neutral (no internal product names) and safe for customer-facing UX.
        var html =
            "<!doctype html>" +
            "<html lang=\"tr\">" +
            "<head>" +
            "<meta charset=\"utf-8\"/>" +
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"/>" +
            "<title>Giris tamam</title>" +
            "<style>" +
            "html,body{height:100%;margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:#ffffff;color:#111827;}" +
            ".wrap{height:100%;display:flex;align-items:center;justify-content:center;padding:24px;}" +
            ".card{max-width:520px;width:100%;border:1px solid #e5e7eb;border-radius:12px;padding:20px;box-shadow:0 6px 24px rgba(0,0,0,.06);}" +
            "h1{font-size:18px;margin:0 0 8px 0;}" +
            "p{margin:0;color:#374151;line-height:1.4;}" +
            ".hint{margin-top:14px;font-size:12px;color:#6b7280;}" +
            "</style>" +
            "</head>" +
            "<body>" +
            "<div class=\"wrap\"><div class=\"card\">" +
            "<h1>Giris tamamlandi</h1>" +
            "<p>Uygulamaya geri donebilirsiniz. Bu sekmeyi kapatabilirsiniz.</p>" +
            "<p class=\"hint\">Bu pencere otomatik olarak kapanmayabilir.</p>" +
            "</div></div>" +
            "</body></html>";
        var body = Encoding.UTF8.GetBytes(html);
        var header = Encoding.ASCII.GetBytes(
            "HTTP/1.1 200 OK\r\n" +
            "Content-Type: text/html; charset=utf-8\r\n" +
            $"Content-Length: {body.Length}\r\n" +
            "Connection: close\r\n" +
            "\r\n");
        await stream.WriteAsync(header, ct);
        await stream.WriteAsync(body, ct);

        if (string.IsNullOrWhiteSpace(code))
            throw new InvalidOperationException("OAuth redirect missing 'code'.");
        if (string.IsNullOrWhiteSpace(state))
            throw new InvalidOperationException("OAuth redirect missing 'state'.");

        return (code!, state!);
    }

    private static async Task<string> ReadLineAsync(NetworkStream stream, CancellationToken ct)
    {
        var sb = new StringBuilder();
        var buf = new byte[1];
        while (true)
        {
            var n = await stream.ReadAsync(buf, ct);
            if (n <= 0)
                break;

            var ch = (char)buf[0];
            if (ch == '\n')
                break;
            if (ch != '\r')
                sb.Append(ch);

            // Limit line length to avoid oversized redirect/header lines.
            if (sb.Length > 8192)
                throw new InvalidOperationException("OAuth redirect request line is too long.");
        }
        return sb.ToString();
    }

    private static Dictionary<string, string> ParseQuery(string query)
    {
        var dict = new Dictionary<string, string>(StringComparer.Ordinal);
        if (string.IsNullOrWhiteSpace(query))
            return dict;

        var q = query.StartsWith("?") ? query[1..] : query;
        foreach (var part in q.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var kv = part.Split('=', 2);
            var k = Uri.UnescapeDataString(kv[0]);
            var v = kv.Length > 1 ? Uri.UnescapeDataString(kv[1]) : "";
            dict[k] = v;
        }
        return dict;
    }

    public void Dispose()
    {
        try { _listener.Stop(); } catch { }
    }
}
