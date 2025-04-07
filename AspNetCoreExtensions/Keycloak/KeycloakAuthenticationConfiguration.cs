namespace AspNetCoreExtensions.Keycloak;

public record KeycloakAuthenticationConfiguration
{
    public required string OidcAuthority { get; init; }
    public required string OidcClientId { get; init; }
    public required string OidcClientSecret { get; init; }
}