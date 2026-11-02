using System.Net;
using System.Runtime.InteropServices;
using System.Security;
using Microsoft.Win32;

namespace Cerberus.Agent.Core;

/// <summary>Optional product-scoped machine proxy; an invalid setting never falls back to a direct connection.</summary>
public static class AgentProxySettings
{
    internal const string RegistryValueName = "proxyUrl";
    internal static string RegistryPath => AgentInstallIdentity.RegistryPath + @"\Network";

    public static Uri? Parse(string? value)
    {
        if (value is null or "") return null;
        if (value.Length > 2048 || value.Any(c => char.IsWhiteSpace(c) || char.IsControl(c)) ||
            value.IndexOfAny(['@', '\\', ';', ',', '"', '|']) >= 0 ||
            !Uri.TryCreate(value, UriKind.Absolute, out var proxy) ||
            proxy.Scheme is not ("http" or "https") || string.IsNullOrEmpty(proxy.Host) ||
            proxy.HostNameType is not (UriHostNameType.Dns or UriHostNameType.IPv4 or UriHostNameType.IPv6) ||
            Uri.CheckHostName(proxy.IdnHost) == UriHostNameType.Unknown ||
            proxy.Port is < 1 or > 65535 || proxy.UserInfo.Length != 0 ||
            proxy.AbsolutePath != "/" || proxy.Query.Length != 0 || proxy.Fragment.Length != 0 || !HasExplicitPort(value))
            throw new InvalidOperationException("Agent proxy URL must be an HTTP(S) authority with an explicit port and without credentials, path, query or fragment.");
        return new UriBuilder(proxy) { Host = proxy.IdnHost.ToLowerInvariant() }.Uri;
    }

    private static bool HasExplicitPort(string value)
    {
        var schemeEnd = value.IndexOf("://", StringComparison.Ordinal);
        if (schemeEnd < 0) return false;
        var authority = value.AsSpan(schemeEnd + 3).TrimEnd('/');
        var separator = authority.LastIndexOf(':');
        var port = authority[(separator + 1)..];
        return separator >= 0 && !port.IsEmpty && port.IndexOfAnyExceptInRange('0', '9') < 0;
    }

    internal static Uri? Read() => Read(ReadMachineValue);

    internal static Uri? Read(Func<object?> read)
    {
        object? value;
        try { value = read(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException)
        { throw new InvalidOperationException("Agent proxy configuration could not be read.", ex); }
        return value switch
        {
            null => null,
            string text => Parse(text),
            _ => throw new InvalidOperationException("Agent proxy configuration must be a registry string."),
        };
    }

    private static object? ReadMachineValue()
    {
        if (!OperatingSystem.IsWindows()) return null;
        using var machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = machine.OpenSubKey(RegistryPath, writable: false);
        var value = key?.GetValue(RegistryValueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
        if (value is not null && key!.GetValueKind(RegistryValueName) != RegistryValueKind.String)
            throw new InvalidOperationException("Agent proxy configuration must be a registry string.");
        return value;
    }

    internal static HttpClientHandler Apply(HttpClientHandler handler) => Apply(handler, Read());

    internal static HttpClientHandler Apply(HttpClientHandler handler, Uri? proxy)
    {
        ArgumentNullException.ThrowIfNull(handler);
        if (proxy is not null)
        {
            handler.Proxy = new WebProxy(proxy) { BypassProxyOnLocal = false, Credentials = null };
            handler.UseProxy = true;
        }
        return handler;
    }

    internal static void ApplyBits(Func<uint, string?, string?, int> setProxy, Uri? proxy)
    {
        ArgumentNullException.ThrowIfNull(setProxy);
        if (proxy is null) return; // Leave BITS PRECONFIG untouched when no machine override exists.
        var host = proxy.HostNameType == UriHostNameType.IPv6 ? $"[{proxy.DnsSafeHost}]" : proxy.IdnHost;
        // Retain the URI's scheme and port explicitly instead of relying on native default interpretation.
        var result = setProxy(2, $"{proxy.Scheme}://{host}:{proxy.Port}", null); // BG_JOB_PROXY_USAGE_OVERRIDE
        if (result < 0)
            throw new InvalidOperationException("BITS proxy configuration failed.", Marshal.GetExceptionForHR(result));
    }
}
