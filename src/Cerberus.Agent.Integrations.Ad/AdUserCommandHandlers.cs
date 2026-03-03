using System.Text.Json.Serialization;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Integrations.Ad;

public static class AdUserCommandHandlers
{
    public static ICommandHandler[] CreateDefaultHandlers(IDirectoryProvider provider)
        =>
        [
            new Create(provider),
            new Update(provider),
            new Disable(provider),
        ];

    private sealed class Create : ICommandHandler
    {
        private readonly IDirectoryProvider _provider;
        public Create(IDirectoryProvider provider) => _provider = provider;
        public string Type => "ad.user.create";

        public async Task<CommandResult> HandleAsync(AgentCommand command, CancellationToken ct)
        {
            if (!CommandPayload.TryDeserialize<CreatePayload>(command.Payload, out var payload) || payload is null)
                return FailInvalidPayload();

            var req = new DirectoryCreateUserRequest(
                Email: payload.Email,
                Password: payload.Password,
                FirstName: payload.FirstName,
                LastName: payload.LastName,
                Ou: payload.Ou,
                Groups: payload.Groups ?? Array.Empty<string>());

            var res = await _provider.CreateUserAsync(req, ct);
            return Map(res);
        }
    }

    private sealed class Update : ICommandHandler
    {
        private readonly IDirectoryProvider _provider;
        public Update(IDirectoryProvider provider) => _provider = provider;
        public string Type => "ad.user.update";

        public async Task<CommandResult> HandleAsync(AgentCommand command, CancellationToken ct)
        {
            if (!CommandPayload.TryDeserialize<UpdatePayload>(command.Payload, out var payload) || payload is null)
                return FailInvalidPayload();

            var req = new DirectoryUpdateUserRequest(
                Email: payload.Email,
                FirstName: payload.FirstName,
                LastName: payload.LastName,
                GroupsAdd: payload.GroupsAdd,
                GroupsRemove: payload.GroupsRemove);

            var res = await _provider.UpdateUserAsync(req, ct);
            return Map(res);
        }
    }

    private sealed class Disable : ICommandHandler
    {
        private readonly IDirectoryProvider _provider;
        public Disable(IDirectoryProvider provider) => _provider = provider;
        public string Type => "ad.user.disable";

        public async Task<CommandResult> HandleAsync(AgentCommand command, CancellationToken ct)
        {
            if (!CommandPayload.TryDeserialize<DisablePayload>(command.Payload, out var payload) || payload is null)
                return FailInvalidPayload();

            var req = new DirectoryDisableUserRequest(
                Email: payload.Email,
                Reason: payload.Reason);

            var res = await _provider.DisableUserAsync(req, ct);
            return Map(res);
        }
    }

    private static CommandResult FailInvalidPayload()
        => new("FAILED", 2, null, "Invalid AD command payload.", new { code = DirectoryErrorCodes.InvalidPayload });

    private static CommandResult Map(DirectoryResult res)
        => res.Success
            ? new CommandResult("DONE", 0, null, null, new { code = res.Code, message = res.Message, post_verify = res.PostVerify })
            : new CommandResult("FAILED", 1, null, res.Message, new { code = res.Code, post_verify = res.PostVerify });

    private sealed record CreatePayload(
        [property: JsonPropertyName("email")] string Email,
        [property: JsonPropertyName("password")] string Password,
        [property: JsonPropertyName("first_name")] string FirstName,
        [property: JsonPropertyName("last_name")] string LastName,
        [property: JsonPropertyName("ou")] string Ou,
        [property: JsonPropertyName("groups")] string[]? Groups);

    private sealed record UpdatePayload(
        [property: JsonPropertyName("email")] string Email,
        [property: JsonPropertyName("first_name")] string? FirstName,
        [property: JsonPropertyName("last_name")] string? LastName,
        [property: JsonPropertyName("groups_add")] string[]? GroupsAdd,
        [property: JsonPropertyName("groups_remove")] string[]? GroupsRemove);

    private sealed record DisablePayload(
        [property: JsonPropertyName("email")] string Email,
        [property: JsonPropertyName("reason")] string? Reason);
}

