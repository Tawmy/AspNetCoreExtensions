using Microsoft.AspNetCore.Authentication.Cookies;

namespace AspNetCoreExtensions.OpenIdConnect.Keycloak;

public record StartupConfiguration
{
    public readonly DatabaseOptions? DatabaseOptions;
    public readonly KeycloakConfiguration KeycloakConfiguration;
    public readonly ITicketStore SessionStore;

    internal StartupConfiguration(KeycloakConfiguration keycloakConfiguration, ITicketStore sessionStore,
        DatabaseOptions? databaseOptions)
    {
        KeycloakConfiguration = keycloakConfiguration;
        SessionStore = sessionStore;
        DatabaseOptions = databaseOptions;
    }
}