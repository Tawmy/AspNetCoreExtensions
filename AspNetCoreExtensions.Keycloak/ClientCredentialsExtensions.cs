using AspNetCoreExtensions.OpenIdConnect.Keycloak;
using Duende.AccessTokenManagement;
using Microsoft.Extensions.DependencyInjection;

namespace AspNetCoreExtensions.OpenIdConnect;

public static class ClientCredentialsExtensions
{
    extension(IServiceCollection services)
    {
        public void AddKeycloakClientCredentials(KeycloakConfiguration idp)
        {
            services.AddSingleton<ClientAssertionService>(_ =>
                new ClientAssertionService(idp.Authority, idp.ClientId,
                    idp.CertificatePath, idp.PrivateKeyPath));

            services.AddClientCredentialsTokenManagement()
                .AddClient(ClientCredentialsClientName.Parse(idp.ClientId), x =>
                {
                    // TODO is there a way to do this without querying the authority URL?
                    x.TokenEndpoint = new Uri($"{idp.Authority}/protocol/openid-connect/token");

                    x.ClientId = ClientId.Parse(idp.ClientId);
                    x.Scope = Scope.Parse(string.Join(' ', idp.Scopes));

                    if (idp.ClientSecret is not null)
                    {
                        x.ClientSecret = ClientSecret.Parse(idp.ClientSecret);
                    }
                });

            if (idp.CertificatePath is not null)
            {
                services.AddSingleton<ITokenRequestCustomizer, SignedJwtRequestCustomizer>();
            }
        }
    }
}