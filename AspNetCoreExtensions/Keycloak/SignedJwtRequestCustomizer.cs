using Duende.AccessTokenManagement;

namespace AspNetCoreExtensions.Keycloak;

internal class SignedJwtRequestCustomizer(ClientAssertionService assertionService) : ITokenRequestCustomizer
{
    public Task<TokenRequestParameters> Customize(HttpRequestContext httpRequest, TokenRequestParameters baseParameters,
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult(baseParameters with
        {
            Assertion = assertionService.CreateSignedJwtAssertion()
        });
    }
}