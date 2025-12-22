using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.OAuth.Claims;

namespace AspNetCoreExtensions.Keycloak.Internal;

internal class KeycloakClientRolesClaimAction()
    : JsonKeyClaimAction(ClaimTypes.Role, ClaimValueTypes.String, "resource_access")
{
    public override void Run(JsonElement userData, ClaimsIdentity identity, string issuer)
    {
        if (!userData.TryGetProperty(JsonKey, out var resourceAccess))
        {
            return;
        }

        var parser = new KeycloakRolesParser(ClaimType);
        identity.AddClaims(parser.ParseClientRoles(resourceAccess));
    }
}