using System.DirectoryServices;
using System.Runtime.InteropServices;
using System.Security;
using Cerberus.Agent.Core;
using Microsoft.Win32;

namespace Cerberus.Agent.Integrations.Ad;

public sealed record ManagedLocalOwnership(ManagedAccountEntry Account, string AgentId, string TenantId,
    string StoredSid, string CurrentSid)
{
    public bool MatchesIdentity(AgentIdentity identity, ManagedAccountEntry requested, bool allowLegacy = false)
    {
        if (Account.AssignmentId != requested.AssignmentId || Account.ManagedAccountId != requested.ManagedAccountId ||
            Account.UserId != requested.UserId || Account.MarkerId != requested.MarkerId || Account.Username != requested.Username)
            return false;
        if (allowLegacy && AgentId.Length == 0 && TenantId.Length == 0 && StoredSid.Length == 0)
            return !string.IsNullOrWhiteSpace(CurrentSid);
        return AgentId == identity.AgentId && TenantId == identity.TenantId &&
            !string.IsNullOrWhiteSpace(StoredSid) && StoredSid == CurrentSid;
    }
}

public interface IManagedLocalAccountStore
{
    IReadOnlyList<ManagedLocalOwnership> ReadAccounts();
    void Disable(ManagedLocalOwnership ownership);
}

public static partial class LocalUserCommandHandlers
{
    public static IManagedAccountReconciler CreateManifestReconciler(IAgentLogger? log = null,
        IManagedLocalAccountStore? store = null)
        => new ManifestReconciler(log ?? NullAgentLogger.Instance, store ?? new WindowsManagedAccountStore());

    private static bool RegistryOwnershipMatches(DirectoryEntry user, LocalUserPayload payload, bool allowLegacy)
    {
        using var key = Registry.LocalMachine.OpenSubKey(ManagedUserRegistryPath(payload.Username));
        if (key is null || payload.BoundIdentity is null) return false;
        string Read(string name) => Convert.ToString(key.GetValue(name)) ?? string.Empty;
        // A complete legacy registry tuple can only be adopted by an explicit authorized create.
        var owned = new ManagedLocalOwnership(new(Read("assignment_id"), Read("managed_account_id"),
            Read("membership_user_id"), payload.Username, Read("marker_id"), "active"),
            Read("agent_id"), Read("tenant_id"), Read("local_sid"), GetLocalSid(user).Value ?? "");
        return owned.MatchesIdentity(payload.BoundIdentity, new(payload.AssignmentId!, payload.ManagedAccountId!,
            payload.MembershipUserId!, payload.Username, NormalizeMarkerId(payload.MarkerId!), "active"), allowLegacy);
    }

    private sealed class ManifestReconciler(IAgentLogger log, IManagedLocalAccountStore store) : IManagedAccountReconciler
    {
        public Task ReconcileAsync(AgentIdentity identity, IReadOnlyList<ManagedAccountEntry> allowed, CancellationToken ct)
            => Task.Run(() =>
            {
                ct.ThrowIfCancellationRequested();
                foreach (var owned in store.ReadAccounts())
                {
                    ct.ThrowIfCancellationRequested();
                    var account = owned.Account;
                    if (!IsAllowedUsername(account.Username)) continue;
                    try
                    {
                        if (string.IsNullOrWhiteSpace(owned.AgentId) || string.IsNullOrWhiteSpace(owned.TenantId) || string.IsNullOrWhiteSpace(owned.StoredSid))
                        {
                            log.Warn("managed_account_legacy_ownership_unresolved: explicit authorized adoption required.");
                            continue;
                        }
                        if (owned.AgentId != identity.AgentId || owned.TenantId != identity.TenantId) continue;
                        if (new[] { account.ManagedAccountId, account.AssignmentId, account.UserId, account.MarkerId }
                            .Any(string.IsNullOrWhiteSpace)) continue;
                        if (owned.StoredSid != owned.CurrentSid)
                        {
                            log.Warn("managed_account_ownership_mismatch: reconciliation skipped.");
                            continue;
                        }
                        if (allowed.Any(a => ManagedAccountManifestPolicy.Allows(a) &&
                            a.AssignmentId == account.AssignmentId && a.ManagedAccountId == account.ManagedAccountId &&
                            a.UserId == account.UserId && a.Username == account.Username &&
                            NormalizeMarkerId(a.MarkerId) == NormalizeMarkerId(account.MarkerId))) continue;
                        store.Disable(owned);
                        log.Warn("managed_account_manifest_disabled");
                    }
                    catch (Exception ex) when (ex is COMException or UnauthorizedAccessException or InvalidOperationException or
                        IOException or SecurityException)
                    {
                        log.Warn("managed_account_manifest_reconciliation_failed");
                    }
                }
            }, ct);
    }

    private sealed class WindowsManagedAccountStore : IManagedLocalAccountStore
    {
        public IReadOnlyList<ManagedLocalOwnership> ReadAccounts()
        {
            if (IsDomainController()) return [];
            using var root = Registry.LocalMachine.OpenSubKey(ManagedUsersRegistryPath);
            if (root is null) return [];
            var result = new List<ManagedLocalOwnership>();
            using var computer = OpenComputer();
            foreach (var username in root.GetSubKeyNames())
            {
                if (!IsAllowedUsername(username)) continue;
                using var key = root.OpenSubKey(username);
                if (key is null) continue;
                string Read(string name) => Convert.ToString(key.GetValue(name)) ?? string.Empty;
                if (!TryFindUser(computer, username, out var user) || user is null) continue;
                using (user)
                    result.Add(new(new(Read("assignment_id"), Read("managed_account_id"), Read("membership_user_id"),
                        username, Read("marker_id"), "active"), Read("agent_id"), Read("tenant_id"), Read("local_sid"), GetLocalSid(user).Value ?? ""));
            }
            return result;
        }

        public void Disable(ManagedLocalOwnership ownership)
        {
            if (IsDomainController()) return;
            var account = ownership.Account;
            var payload = new LocalUserPayload(account.Username, null, null, account.ManagedAccountId,
                account.AssignmentId, account.UserId, account.MarkerId)
                { BoundIdentity = new(ownership.AgentId, ownership.TenantId) };
            using var computer = OpenComputer();
            if (!TryFindUser(computer, account.Username, out var user) || user is null) return;
            using (user)
            {
                if (!RegistryOwnershipMatches(user, payload, allowLegacy: false) || GetLocalSid(user).Value != ownership.StoredSid)
                    throw new InvalidOperationException("Managed account ownership changed.");
                user.InvokeSet("AccountDisabled", true);
                user.CommitChanges();
                using var group = OpenRemoteDesktopUsersGroup();
                if (IsGroupMember(group, account.Username)) group.Invoke("Remove", user.Path);
            }
        }
    }
}
