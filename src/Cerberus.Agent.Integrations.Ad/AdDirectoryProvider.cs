using Cerberus.Agent.Core;

namespace Cerberus.Agent.Integrations.Ad;

// Placeholder AD provider for v1 wiring.
// Implements the directory module boundary without pulling provider-specific logic into Core.
//
// For MVP/local testing, we only verify domain-joined status and return a clear error otherwise.
// Full AD create/update/disable can be implemented behind this provider later.
public sealed class AdDirectoryProvider : IDirectoryProvider
{
    public DirectoryCapabilities Capabilities { get; } = new(
        SupportsCreate: false,
        SupportsUpdate: false,
        SupportsDisable: false,
        DomainScopes: Array.Empty<string>());

    public Task<DirectoryResult> CreateUserAsync(DirectoryCreateUserRequest request, CancellationToken ct)
        => Task.FromResult(GuardAndPlaceholder("create", request.Email));

    public Task<DirectoryResult> UpdateUserAsync(DirectoryUpdateUserRequest request, CancellationToken ct)
        => Task.FromResult(GuardAndPlaceholder("update", request.Email));

    public Task<DirectoryResult> DisableUserAsync(DirectoryDisableUserRequest request, CancellationToken ct)
        => Task.FromResult(GuardAndPlaceholder("disable", request.Email));

    private static DirectoryResult GuardAndPlaceholder(string op, string email)
    {
        var (joined, domain, err) = AdStatusProbe.Probe();
        if (!joined)
        {
            return new DirectoryResult(
                Success: false,
                Code: DirectoryErrorCodes.NotDomainJoined,
                Message: "Machine is not domain-joined (AD operations are unavailable).",
                PostVerify: new { domain_joined = false, domain, error = err });
        }

        // Intentionally a placeholder until we implement real AD logic.
        return new DirectoryResult(
            Success: false,
            Code: DirectoryErrorCodes.NotImplemented,
            Message: $"AD operation '{op}' is not implemented yet (module wiring only).",
            PostVerify: new { domain_joined = true, domain, email });
    }
}
