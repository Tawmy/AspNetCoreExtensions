using StackExchange.Redis;

namespace AspNetCoreExtensions.Keycloak.Internal.Valkey;

/// <summary>
/// Key naming for everything this library stores in Valkey.
/// </summary>
internal sealed class ValkeyKeys(string prefix)
{
    /// <summary>The one key with no TTL.</summary>
    public string DataProtectionKeys => $"{prefix}:data-protection-keys";

    public RedisKey Session(string sessionKey)
    {
        return $"{prefix}:session:{sessionKey}";
    }

    public RedisKey SessionIdIndex(string sid)
    {
        return $"{prefix}:sid:{sid}";
    }

    public RedisKey UserSessions(string sub)
    {
        return $"{prefix}:user:{sub}";
    }

    public RedisKey UserTokens(string sub)
    {
        return $"{prefix}:token:{sub}";
    }
}