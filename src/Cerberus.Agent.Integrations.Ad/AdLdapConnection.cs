using System.Diagnostics;
using System.DirectoryServices.Protocols;
using System.Text;

namespace Cerberus.Agent.Integrations.Ad;

internal sealed record AdLdapEntry(string DistinguishedName, IReadOnlyDictionary<string, byte[][]> Attributes);

internal interface IAdLdapConnection : IDisposable
{
    IReadOnlyList<AdLdapEntry> Search(SearchRequest request);
    void Mutate(DirectoryRequest request);
}

/// <summary>Windows native LDAP, with Kerberos machine credentials and no referrals, fallback credentials, or reconnect replay.</summary>
internal sealed class AdLdapConnection : IAdLdapConnection
{
    private readonly LdapConnection _connection;
    private readonly CancellationToken _ct;
    private readonly Stopwatch _elapsed = Stopwatch.StartNew();
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan OperationTimeout = TimeSpan.FromSeconds(90);

    public AdLdapConnection(AdScope scope, CancellationToken ct)
    {
        _ct = ct;
        _connection = new LdapConnection(new LdapDirectoryIdentifier(scope.ControllerFqdn, 389, true, false),
            null, AuthType.Kerberos) { AutoBind = false, Timeout = RequestTimeout };
        try
        {
            _connection.SessionOptions.ProtocolVersion = 3;
            _connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
            _connection.SessionOptions.AutoReconnect = false;
            _connection.SessionOptions.Signing = true;
            _connection.SessionOptions.Sealing = true;
            _connection.SessionOptions.SendTimeout = RequestTimeout;
            ct.ThrowIfCancellationRequested();
            _connection.Bind();
            if (!_connection.SessionOptions.Signing || !_connection.SessionOptions.Sealing)
                throw new AdOperationDeniedException("ad_secure_channel_required");
        }
        catch (LdapException) { _connection.Dispose(); throw new AdOperationDeniedException("ad_directory_unavailable"); }
        catch { _connection.Dispose(); throw; }
    }

    public IReadOnlyList<AdLdapEntry> Search(SearchRequest request)
    {
        var response = (SearchResponse)Send(request);
        if (response.References.Count != 0 || response.Entries.Count > 2)
            throw new AdOperationDeniedException("ad_directory_result_out_of_bounds");
        var entries = new List<AdLdapEntry>(response.Entries.Count);
        foreach (SearchResultEntry entry in response.Entries)
        {
            if (entry.DistinguishedName.Length > 4096 || entry.Attributes.Count > 32)
                throw new AdOperationDeniedException("ad_directory_result_out_of_bounds");
            var attributes = new Dictionary<string, byte[][]>(StringComparer.OrdinalIgnoreCase);
            foreach (string name in entry.Attributes.AttributeNames)
            {
                var attribute = entry.Attributes[name];
                if (attribute.Count > 1024) throw new AdOperationDeniedException("ad_directory_result_out_of_bounds");
                var values = new List<byte[]>(attribute.Count);
                foreach (var value in attribute)
                {
                    var bytes = value switch
                    {
                        byte[] binary => binary,
                        string text => Encoding.UTF8.GetBytes(text),
                        _ => throw new AdOperationDeniedException("ad_directory_value_invalid")
                    };
                    if (bytes.Length > 65536) throw new AdOperationDeniedException("ad_directory_result_out_of_bounds");
                    values.Add(bytes);
                }
                attributes.Add(name, values.ToArray());
            }
            entries.Add(new(entry.DistinguishedName, attributes));
        }
        return entries;
    }

    public void Mutate(DirectoryRequest request) => Send(request);

    private DirectoryResponse Send(DirectoryRequest request)
    {
        _ct.ThrowIfCancellationRequested();
        var remaining = OperationTimeout - _elapsed.Elapsed;
        if (remaining <= TimeSpan.Zero) throw new AdOperationDeniedException("ad_outcome_uncertain");
        try
        {
            // SendRequest is synchronous: cancellation never leaves a detached worker that can continue mutating.
            return _connection.SendRequest(request, remaining < RequestTimeout ? remaining : RequestTimeout);
        }
        catch (DirectoryOperationException ex)
        {
            var code = ex.Response?.ResultCode;
            throw new AdOperationDeniedException(code switch
            {
                ResultCode.NoSuchObject => "ad_object_missing",
                ResultCode.EntryAlreadyExists => "ad_unowned_collision",
                ResultCode.InsufficientAccessRights => "ad_directory_access_denied",
                ResultCode.ConstraintViolation or ResultCode.UnwillingToPerform => "ad_directory_policy_denied",
                ResultCode.NotAllowedOnNonLeaf => "ad_leaf_user_required",
                _ => "ad_outcome_uncertain"
            });
        }
        catch (LdapException) { throw new AdOperationDeniedException("ad_outcome_uncertain"); }
    }

    public void Dispose() => _connection.Dispose();
}
