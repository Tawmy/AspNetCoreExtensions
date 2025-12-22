namespace AspNetCoreExtensions.Keycloak.Options;

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
    public IEnumerable<string> Scopes { get; private init; } = [];
    public string? CertificatePath { get; private init; }
    public string? PrivateKeyPath { get; private init; }

    /// <summary>
    ///     Configuration for secret-based client authentication with Keycloak.
    /// </summary>
    /// <param name="authority">OpenID Connect Authority (realm URL)</param>
    /// <param name="clientId">OpenID Connect Client ID</param>
    /// <param name="clientSecret">OpenID Connect Client Secret</param>
    /// <param name="scopes">Optional list of scopes to submit to Keycloak</param>
    public static KeycloakConfiguration WithClientSecret(string authority, string clientId, string clientSecret,
        params IEnumerable<string> scopes)
    {
        return new KeycloakConfiguration(authority, clientId)
        {
            ClientSecret = clientSecret,
            Scopes = scopes
        };
    }

    /// <summary>
    ///     Configuration for Signed JWT client authentication with Keycloak.
    /// </summary>
    /// <param name="authority">OpenID Connect Authority (realm URL)</param>
    /// <param name="clientId">OpenID Connect Client ID</param>
    /// <param name="certificatePath">Path to PEM-formatted certificate to use for JWKS endpoint</param>
    /// <param name="privateKeyPath">Path to PEM-formatted private key to use for Signed JWT client authentication</param>
    /// <param name="scopes">Optional list of scopes to submit to Keycloak</param>
    public static KeycloakConfiguration WithSignedJwt(string authority, string clientId, string certificatePath,
        string privateKeyPath, params IEnumerable<string> scopes)
    {
        return new KeycloakConfiguration(authority, clientId)
        {
            CertificatePath = certificatePath,
            PrivateKeyPath = privateKeyPath,
            Scopes = scopes
        };
    }
}