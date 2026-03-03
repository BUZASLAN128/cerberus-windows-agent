using System.Text.Json;

namespace Cerberus.Agent.Core;

// Directory integrations (AD/LDAP/etc) must remain a module boundary.
// Core depends only on these contracts. Provider implementations live in integration projects.

public interface IDirectoryProvider
{
    DirectoryCapabilities Capabilities { get; }

    Task<DirectoryResult> CreateUserAsync(DirectoryCreateUserRequest request, CancellationToken ct);
    Task<DirectoryResult> UpdateUserAsync(DirectoryUpdateUserRequest request, CancellationToken ct);
    Task<DirectoryResult> DisableUserAsync(DirectoryDisableUserRequest request, CancellationToken ct);
}

public sealed record DirectoryCapabilities(
    bool SupportsCreate,
    bool SupportsUpdate,
    bool SupportsDisable,
    IReadOnlyList<string> DomainScopes);

public sealed record DirectoryResult(
    bool Success,
    string Code,
    string Message,
    object? PostVerify = null);

public sealed record DirectoryCreateUserRequest(
    string Email,
    string Password,
    string FirstName,
    string LastName,
    string Ou,
    IReadOnlyList<string> Groups);

public sealed record DirectoryUpdateUserRequest(
    string Email,
    string? FirstName,
    string? LastName,
    IReadOnlyList<string>? GroupsAdd,
    IReadOnlyList<string>? GroupsRemove);

public sealed record DirectoryDisableUserRequest(
    string Email,
    string? Reason);

public static class DirectoryErrorCodes
{
    public const string NotDomainJoined = "not_domain_joined";
    public const string NotImplemented = "not_implemented";
    public const string InvalidPayload = "invalid_payload";
    public const string PermissionDenied = "permission_denied";
    public const string Unknown = "unknown";
}

public static class CommandPayload
{
    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web);

    public static bool TryDeserialize<T>(object payload, out T? value)
    {
        value = default;
        try
        {
            if (payload is JsonElement el)
            {
                value = el.Deserialize<T>(JsonOpts);
                return value is not null;
            }

            // Sometimes System.Text.Json gives us a Dictionary or anonymous object.
            var raw = JsonSerializer.Serialize(payload, JsonOpts);
            value = JsonSerializer.Deserialize<T>(raw, JsonOpts);
            return value is not null;
        }
        catch
        {
            return false;
        }
    }
}
