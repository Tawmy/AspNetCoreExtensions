using AspNetCoreExtensions.Keycloak.Options;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging;
using StackExchange.Redis;

namespace AspNetCoreExtensions.Keycloak.Internal.Valkey;

/// <summary>
/// Session store backed by Valkey. Index entries are only ever added, never moved or deleted, so revocation may find
/// one session too many, never one too few.
/// </summary>
internal sealed class SessionStoreDistributed(
    IConnectionMultiplexer connection,
    ValkeyKeys keys,
    ValkeyOptions options,
    IDataProtectionProvider dataProtectionProvider,
    ILogger<SessionStoreDistributed> logger) : ITicketStore, ISessionRevocationStore
{
    private readonly IDataProtector _protector =
        dataProtectionProvider.CreateProtector("AspNetCoreExtensions.Keycloak.SessionStore.v1");

    private IDatabase Database => connection.GetDatabase();

    public async Task<int> RevokeSessionAsync(string sid, CancellationToken cancellationToken = default)
    {
        var sessionKey = await Database.StringGetAsync(keys.SessionIdIndex(sid));

        if (!sessionKey.IsNullOrEmpty)
        {
            return await RemoveCoreAsync(Database, sessionKey!) ? 1 : 0;
        }

        logger.LogDebug("No session found for sid {Sid}", sid);
        return 0;
    }

    public async Task<int> RevokeUserSessionsAsync(string sub, CancellationToken cancellationToken = default)
    {
        var database = Database;
        var userSessions = keys.UserSessions(sub);

        var sessionKeys = await database.SortedSetRangeByRankAsync(userSessions);
        var revoked = 0;

        // one at a time so a Valkey Cluster can route each to its own slot
        foreach (var sessionKey in sessionKeys)
        {
            if (await database.KeyDeleteAsync(keys.Session(sessionKey!)))
            {
                revoked++;
            }
        }

        await database.KeyDeleteAsync(userSessions);
        await database.KeyDeleteAsync(keys.UserTokens(sub));

        logger.LogInformation("Revoked {Count} session(s) for subject {Sub}", revoked, sub);
        return revoked;
    }

    public async Task<string> StoreAsync(AuthenticationTicket ticket)
    {
        var sub = ticket.Principal.GetRequiredClaim("sub");
        var sid = ticket.Principal.FindFirst("sid")?.Value;

        var now = DateTimeOffset.UtcNow;
        var timeToLive = GetTimeToLive(ticket, now);
        var sessionKey = Guid.CreateVersion7().ToString();

        var database = Database;

        await IndexAsync(database, sub, sid, sessionKey, now, timeToLive);

        var stored = await database.StringSetAsync(keys.Session(sessionKey), Protect(ticket), timeToLive,
            When.NotExists);

        if (!stored)
        {
            throw new InvalidOperationException("Failed to store session, key already in use.");
        }

        logger.LogDebug("Stored session for subject {Sub} with a lifetime of {TimeToLive}", sub, timeToLive);
        return sessionKey;
    }

    public async Task RenewAsync(string key, AuthenticationTicket ticket)
    {
        var sub = ticket.Principal.GetRequiredClaim("sub");
        var sid = ticket.Principal.FindFirst("sid")?.Value;

        var now = DateTimeOffset.UtcNow;
        var timeToLive = GetTimeToLive(ticket, now);

        var database = Database;

        // XX: never resurrect a session revoked while this refresh was in flight
        var renewed = await database.StringSetAsync(keys.Session(key), Protect(ticket), timeToLive, When.Exists);

        if (!renewed)
        {
            logger.LogDebug("Skipped renewal of session for subject {Sub}, it no longer exists", sub);
            return;
        }

        await IndexAsync(database, sub, sid, key, now, timeToLive);
    }

    public async Task<AuthenticationTicket?> RetrieveAsync(string key)
    {
        var payload = await Database.StringGetAsync(keys.Session(key));
        return payload.IsNullOrEmpty ? null : ReadTicket(payload);
    }

    public async Task RemoveAsync(string key)
    {
        await RemoveCoreAsync(Database, key);
    }

    /// <summary>Deletes a session and unlists it.</summary>
    /// <returns>Whether a session actually existed.</returns>
    private async Task<bool> RemoveCoreAsync(IDatabase database, string key)
    {
        var payload = await database.StringGetDeleteAsync(keys.Session(key));

        if (payload.IsNullOrEmpty)
        {
            return false;
        }

        // the sid index is left alone: deleting it could strip a newer session's entry
        var sub = ReadTicket(payload)?.Principal.FindFirst("sub")?.Value;

        if (string.IsNullOrEmpty(sub))
        {
            return true;
        }

        var userSessions = keys.UserSessions(sub);
        await database.SortedSetRemoveAsync(userSessions, key);

        // scored from now, so members that expired unpruned do not keep the tokens alive
        var live = await database.SortedSetLengthAsync(userSessions, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());

        if (live == 0)
        {
            await database.KeyDeleteAsync(keys.UserTokens(sub));
        }

        return true;
    }

    /// <summary>Lists the session under its subject and, when the ticket carries one, under its Keycloak sid.</summary>
    private async Task IndexAsync(IDatabase database, string sub, string? sid, string sessionKey,
        DateTimeOffset now, TimeSpan timeToLive)
    {
        await TrackUserSessionAsync(database, sub, sessionKey, now, timeToLive);

        if (!string.IsNullOrEmpty(sid))
        {
            await database.StringSetAsync(keys.SessionIdIndex(sid), sessionKey, timeToLive);
        }
    }

    private async Task TrackUserSessionAsync(IDatabase database, string sub, string sessionKey, DateTimeOffset now,
        TimeSpan timeToLive)
    {
        var userSessions = keys.UserSessions(sub);
        var batch = database.CreateBatch();

        var add = batch.SortedSetAddAsync(userSessions, sessionKey, (now + timeToLive).ToUnixTimeMilliseconds());
        var prune = batch.SortedSetRemoveRangeByScoreAsync(userSessions, double.NegativeInfinity,
            now.ToUnixTimeMilliseconds());

        // HasNoExpiry creates the ttl, GreaterThanCurrentExpiry extends it without shortening it, so the index
        // always outlives its newest member without needing a branch
        var create = batch.KeyExpireAsync(userSessions, timeToLive, ExpireWhen.HasNoExpiry);
        var extend = batch.KeyExpireAsync(userSessions, timeToLive, ExpireWhen.GreaterThanCurrentExpiry);

        batch.Execute();
        await Task.WhenAll(add, prune, create, extend);
    }

    private RedisValue Protect(AuthenticationTicket ticket)
    {
        return _protector.Protect(TicketSerializer.Default.Serialize(ticket));
    }

    private AuthenticationTicket? ReadTicket(RedisValue payload)
    {
        try
        {
            return TicketSerializer.Default.Deserialize(_protector.Unprotect((byte[])payload!));
        }
        catch (Exception e)
        {
            // usually a rotated key ring; the session is unusable and expires on its own
            logger.LogWarning(e, "Failed to read a stored session");
            return null;
        }
    }

    /// <summary>
    /// Taken from the ticket so session and cookie expire together. A ticket with no expiry left to run is a session
    /// cookie, and falls back to <see cref="ValkeyOptions.SessionTimeToLive" />.
    /// </summary>
    private TimeSpan GetTimeToLive(AuthenticationTicket ticket, DateTimeOffset now)
    {
        var remaining = ticket.Properties.ExpiresUtc - now;

        return remaining > TimeSpan.Zero
            ? remaining.Value + ValkeyOptions.ExpirationGracePeriod
            : options.SessionTimeToLive;
    }
}