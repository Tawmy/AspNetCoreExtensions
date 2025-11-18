namespace AspNetCoreExtensions.Keycloak;

public record KeycloakConfiguration
{
    private KeycloakConfiguration(string authority, string clientId)
    {
        Authority = authority;
        ClientId = clientId;
    }

    public string Authority { get; private init; }
    public string ClientId { get; private init; }
    public string? ClientSecret { get; private init; }
    public string? PrivateKeyPath { get; private init; }

    /// <summary>
    ///     Configuration for secret-based client authentication with Keycloak.
    /// </summary>
    /// <param name="authority">OpenID Connect Authority (realm URL)</param>
    /// <param name="clientId">OpenID Connect Client ID</param>
    /// <param name="clientSecret">OpenID Connect Client Secret</param>
    public static KeycloakConfiguration WithClientSecret(string authority, string clientId, string clientSecret)
    {
        return new KeycloakConfiguration(authority, clientId) { ClientSecret = clientSecret };
    }

    /// <summary>
    ///     Configuration for Signed JWT client authentication with Keycloak.
    /// </summary>
    /// <param name="authority">OpenID Connect Authority (realm URL)</param>
    /// <param name="clientId">OpenID Connect Client ID</param>
    /// <param name="privateKeyPath">Path to PEM-formatted private key to use for Signed JWT client authentication.</param>
    public static KeycloakConfiguration WithSignedJwt(string authority, string clientId, string privateKeyPath)
    {
        return new KeycloakConfiguration(authority, clientId) { PrivateKeyPath = privateKeyPath };
    }
}