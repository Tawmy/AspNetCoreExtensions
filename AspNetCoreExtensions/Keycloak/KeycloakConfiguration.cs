namespace AspNetCoreExtensions.Keycloak;

public record KeycloakConfiguration
{
    public required string Authority { get; init; }
    public required string ClientId { get; init; }
    public required string ClientSecret { get; init; }
}