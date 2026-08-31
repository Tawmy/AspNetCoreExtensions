using StackExchange.Redis;

namespace AspNetCoreExtensions.Keycloak.Options;

/// <summary>Configuration for the Valkey backed stores: sessions, user tokens and data protection keys.</summary>
public record ValkeyOptions
{
    /// <summary>Padding against clock skew between instances, so an entry cannot expire before what it belongs to.</summary>
    internal static readonly TimeSpan ExpirationGracePeriod = TimeSpan.FromMinutes(1);

    /// <summary>Valkey host name.</summary>
    public required string Host { get; init; }

    /// <summary>Valkey port.</summary>
    public int Port { get; init; } = 6379;

    /// <summary>Valkey ACL username.</summary>
    public string? Username { get; init; }

    /// <summary>Valkey password. Load this safely.</summary>
    public string? Password { get; init; }

    /// <summary>Connect over TLS.</summary>
    public bool UseSsl { get; init; }

    /// <summary>Prefix for every key written. Give each application its own, or they overwrite each other.</summary>
    public string KeyPrefix { get; init; } = "keycloak";

    /// <summary>
    /// Data protection application name, defaulting to <see cref="KeyPrefix" />.
    /// </summary>
    /// <remarks>
    /// Anything sharing this name can decrypt the cookies: required between instances of one application,
    /// a security hole between different ones.
    /// </remarks>
    public string? ApplicationName { get; init; }

    internal string EffectiveApplicationName => ApplicationName ?? KeyPrefix;

    /// <summary>Fallback session lifetime, used only when a ticket carries no expiry of its own.</summary>
    public TimeSpan SessionTimeToLive { get; init; } = TimeSpan.FromMinutes(30);

    /// <summary>
    /// Fallback token lifetime, used only when a refresh token carries no expiry of its own.
    /// </summary>
    /// <remarks>
    /// Relevant for offline tokens as they do not have an 'exp' claim. Raise this when raising the Keycloak default.
    /// </remarks>
    public TimeSpan OfflineTokenTimeToLive { get; init; } = TimeSpan.FromDays(30);

    /// <summary>Everything else stays at its StackExchange.Redis default.</summary>
    internal ConfigurationOptions BuildConfiguration()
    {
        var configuration = new ConfigurationOptions
        {
            EndPoints = { { Host, Port } },
            User = Username,
            Password = Password,
            Ssl = UseSsl,
            ClientName = EffectiveApplicationName
        };

        return configuration;
    }
}