namespace AspNetCoreExtensions.Keycloak;

public record StartupConfiguration
{
    public readonly DatabaseOptions? DatabaseOptions;
    public readonly KeycloakConfiguration KeycloakConfiguration;

    internal StartupConfiguration(KeycloakConfiguration keycloakConfiguration, DatabaseOptions? databaseOptions)
    {
        KeycloakConfiguration = keycloakConfiguration;
        DatabaseOptions = databaseOptions;
    }
}