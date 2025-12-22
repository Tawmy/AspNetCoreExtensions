using Duende.AccessTokenManagement;
using Duende.AccessTokenManagement.OpenIdConnect;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols;

namespace AspNetCoreExtensions.Keycloak.Internal;

internal class OidcEvents(IUserTokenStore store, ClientAssertionService clientAssertionService) : OpenIdConnectEvents
{
    public override async Task TokenValidated(TokenValidatedContext context)
    {
        var exp = DateTimeOffset.UtcNow.AddSeconds(double.Parse(context.TokenEndpointResponse!.ExpiresIn));

        await store.StoreTokenAsync(context.Principal!, new UserToken
        {
            ClientId = ClientId.Parse(context.Options.ClientId!),
            AccessToken = AccessToken.Parse(context.TokenEndpointResponse.AccessToken),
            AccessTokenType = AccessTokenType.Parse(context.TokenEndpointResponse.TokenType),
            Expiration = exp,
            RefreshToken = RefreshToken.Parse(context.TokenEndpointResponse.RefreshToken),
            Scope = Scope.Parse(context.TokenEndpointResponse.Scope)
        });

        await base.TokenValidated(context);
    }

    public override Task PushAuthorization(PushedAuthorizationContext context)
    {
        if (clientAssertionService.UseSignedJwtClientAuthentication())
        {
            AddAssertion(context.ProtocolMessage);
        }

        return base.PushAuthorization(context);
    }

    public override Task AuthorizationCodeReceived(AuthorizationCodeReceivedContext context)
    {
        if (context.TokenEndpointRequest is not null && clientAssertionService.UseSignedJwtClientAuthentication())
        {
            AddAssertion(context.TokenEndpointRequest);
        }

        return base.AuthorizationCodeReceived(context);
    }

    private void AddAssertion(AuthenticationProtocolMessage message)
    {
        var assertion = clientAssertionService.CreateSignedJwtAssertion();
        message.SetParameter("client_assertion_type", assertion.Type);
        message.SetParameter("client_assertion", assertion.Value);
    }
}