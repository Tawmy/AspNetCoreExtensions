namespace AspNetCoreExtensions.Keycloak;

public record KeycloakAuthenticationOptions
{
    public string AuthenticationScheme { get; set; } = "Keycloak";
    public string NameClaimType { get; set; } = "preferred_username";
}