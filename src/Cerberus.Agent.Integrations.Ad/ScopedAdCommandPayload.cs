using System.Globalization;
using System.Security.Principal;
using System.Text.Json;
using System.Text.RegularExpressions;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Integrations.Ad;

internal sealed record ScopedAdCommandPayload(AdCommandTarget Target, string? Phase, string AuditCorrelationId, string Reason,
    AdCredentialRequest? CredentialRequest, AdUserIdentity? ExpectedIdentity, string? CredentialProfileId, bool ConfirmDelete)
{
    private static readonly string[] CommonFields = ["schema_version", "managed_account_id", "assignment_id", "scope_id",
        "username", "domain_guid", "ou_guid", "domain_dns_name", "audit_correlation_id", "reason"];
    private static readonly string[] PrepareFields = ["phase", "credential_request_id", "credential_expires_at", "rdp_credential_profile_id",
        "rdp_tenant_key_id", "rdp_key_version", "rdp_public_key_pem", "rdp_public_key_fingerprint", "rdp_cipher_alg", "rdp_aad", "rdp_aad_hash"];
    internal const string SchemaVersion = "agent.ad-user.command.v1";

    internal static ScopedAdCommandPayload Parse(AgentCommand command, AgentIdentity identity)
    {
        try
        {
            var json = command.Payload is JsonElement element ? element : JsonSerializer.SerializeToElement(command.Payload);
            if (json.ValueKind != JsonValueKind.Object || json.GetRawText().Length > 32768) throw Invalid();
            var fields = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
            foreach (var property in json.EnumerateObject()) if (!fields.TryAdd(property.Name, property.Value)) throw Invalid();
            string Text(string name, int max = 128, bool multiline = false)
            {
                if (!fields.TryGetValue(name, out var value) || value.ValueKind != JsonValueKind.String) throw Invalid();
                var text = value.GetString();
                if (string.IsNullOrWhiteSpace(text) || text.Length > max || text.Any(c => char.IsControl(c) && (!multiline || c is not ('\r' or '\n')))) throw Invalid();
                return text;
            }
            string Uuid(string name) => Guid.TryParseExact(Text(name), "D", out var guid) && guid != Guid.Empty ? guid.ToString("D") : throw Invalid();
            string? phase = command.Type == "windows.ad_user.create" ? Text("phase", 16) : null;
            var extra = command.Type switch
            {
                "windows.ad_user.create" when phase == "prepare" => PrepareFields,
                "windows.ad_user.create" when phase == "activate" => ["phase", "credential_profile_id", "expected_object_guid", "expected_sid"],
                "windows.ad_user.disable" => new[] { "expected_object_guid", "expected_sid" },
                "windows.ad_user.delete" => ["expected_object_guid", "expected_sid", "confirm_delete"],
                _ => throw Invalid()
            };
            var allowed = new HashSet<string>(CommonFields.Concat(extra), StringComparer.Ordinal);
            if (fields.Count != allowed.Count || fields.Keys.Any(key => !allowed.Contains(key)) || Text("schema_version") != SchemaVersion) throw Invalid();
            var username = Text("username", 20);
            if (!Regex.IsMatch(username, "\\A[a-zA-Z][a-zA-Z0-9_-]{0,19}\\z")) throw Invalid();
            var domainName = Text("domain_dns_name", 253);
            if (Uri.CheckHostName(domainName) != UriHostNameType.Dns) throw Invalid();
            var target = new AdCommandTarget(new(identity.TenantId, identity.AgentId, Uuid("managed_account_id"),
                Uuid("assignment_id"), Uuid("scope_id"), username), Guid.Parse(Uuid("domain_guid")), Guid.Parse(Uuid("ou_guid")), domainName);
            AdCredentialRequest? credential = null;
            AdUserIdentity? expected = null;
            string? profile = null;
            var confirm = false;
            if (phase == "prepare")
            {
                var expiresText = Text("credential_expires_at", 48);
                if (!expiresText.Contains('T') || !DateTimeOffset.TryParse(expiresText, CultureInfo.InvariantCulture,
                    DateTimeStyles.RoundtripKind, out var expires) || expires.Offset != TimeSpan.Zero) throw Invalid();
                if (!fields["rdp_key_version"].TryGetInt32(out var version) || version <= 0) throw Invalid();
                profile = Uuid("rdp_credential_profile_id");
                credential = new(Uuid("credential_request_id"), expires, new(profile, Text("rdp_tenant_key_id"), version,
                    Text("rdp_public_key_pem", 4096, multiline: true), Text("rdp_public_key_fingerprint", 64),
                    Text("rdp_cipher_alg", 64), Text("rdp_aad", 2048), Text("rdp_aad_hash", 64)));
                ScopedAdUserProvider.ValidateCredentialRequest(credential, requireFresh: false);
            }
            else
            {
                var sidText = Text("expected_sid", 184);
                var sid = new SecurityIdentifier(sidText);
                if (sid.Value != sidText || sid.AccountDomainSid is null) throw Invalid();
                expected = new(Guid.Parse(Uuid("expected_object_guid")), sid.Value);
                if (phase == "activate") profile = Uuid("credential_profile_id");
                if (command.Type == "windows.ad_user.delete")
                {
                    if (fields["confirm_delete"].ValueKind is not (JsonValueKind.True or JsonValueKind.False)) throw Invalid();
                    confirm = fields["confirm_delete"].GetBoolean();
                }
            }
            return new(target, phase, Text("audit_correlation_id"), Text("reason", 512), credential, expected, profile, confirm);
        }
        catch (Exception ex) when (ex is JsonException or ArgumentException or InvalidOperationException or KeyNotFoundException or FormatException)
        { throw Invalid(); }
    }

    private static AdOperationDeniedException Invalid() => new("ad_command_invalid");
}
