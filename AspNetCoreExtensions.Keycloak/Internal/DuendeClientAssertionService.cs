using Duende.AccessTokenManagement;
using Duende.IdentityModel.Client;

namespace AspNetCoreExtensions.Keycloak.Internal;

/// <summary>
/// Supplies the signed JWT client assertion on the token-endpoint calls Duende makes itself.
/// </summary>
/// <remarks>
/// <see cref="OidcEvents" /> covers only what the ASP.NET Core handler sends — pushed authorization and the initial
/// code exchange. A refresh is made by Duende's own token endpoint client, which never passes through those events,
/// so without this Keycloak answers <c>invalid_client</c> and the session stops sliding.
/// </remarks>
internal sealed class DuendeClientAssertionService(ClientAssertionService assertions) : IClientAssertionService
{
    public Task<ClientAssertion?> GetClientAssertionAsync(ClientCredentialsClientName? clientName = null,
        TokenRequestParameters? parameters = null, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(assertions.UseSignedJwtClientAuthentication()
            ? assertions.CreateSignedJwtAssertion()
            : null);
    }
}