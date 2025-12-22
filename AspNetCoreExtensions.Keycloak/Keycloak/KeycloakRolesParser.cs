using System.Security.Claims;
using System.Text.Json;

namespace AspNetCoreExtensions.OpenIdConnect.Keycloak;

/// <summary>
///     Depending on whether we use OpenID Connect (Blazor app) or Jwt Authorization (APIs), claims need to be parsed
///     differently.
///     For the Blazor app, we retrieve roles in the ID token or from the userinfo endpoint. We then use claim actions to
///     map
///     realm and client roles.
///     Since realm roles are a simple structure, they can be mapped using MapJsonSubKey. This means only
///     <see cref="ParseClientRoles" /> is used for OpenID Connect.
///     When using Jwt Authorization, claims are mapped using the OnTokenValidated event. Both realm and client roles need
///     to
///     be mapped using <see cref="ParseRoles" />.
/// </summary>
/// <param name="targetClaimType"></param>
internal class KeycloakRolesParser(string targetClaimType)
{
    private const string ClientRoleClaim = "resource_access";
    private const string RealmRoleClaim = "realm_access";
    private const string RolesClaim = "roles";

    /// <summary>
    ///     Parse client roles from the resource_access claim.
    /// </summary>
    /// <remarks>
    ///     While the claim is called "resource_access", the Keycloak and OAuth terms are "client"
    /// </remarks>
    /// <param name="resourceAccessClaim">Resource access claim</param>
    /// <returns>Enumerable of Claims in the format clientName.roleName</returns>
    public IEnumerable<Claim> ParseClientRoles(JsonElement resourceAccessClaim)
    {
        foreach (var client in resourceAccessClaim.EnumerateObject())
        {
            if (!client.Value.TryGetProperty(RolesClaim, out var roles))
            {
                continue;
            }

            foreach (var role in roles.EnumerateArray())
            {
                yield return new Claim(targetClaimType, $"{client.Name}.{role}");
            }
        }
    }

    /// <summary>
    ///     Parse client and realm roles from the ClaimsIdentity.
    /// </summary>
    /// <param name="identity">ClaimsIdentity object from Jwt Authorization events.</param>
    /// <remarks>
    ///     Do not use this for OIDC with Blazor. Newly added claims do not appear in user object on Blazor pages. Use
    ///     ClaimsActions instead.
    /// </remarks>
    /// <returns>Enumerable of Claims, with client roles in the format clientName.roleName</returns>
    public IEnumerable<Claim> ParseRoles(ClaimsIdentity identity)
    {
        foreach (var clientRole in ParseClientRoles(identity))
        {
            yield return clientRole;
        }

        foreach (var realmRole in ParseRealmRoles(identity))
        {
            yield return realmRole;
        }
    }

    private IEnumerable<Claim> ParseClientRoles(ClaimsIdentity identity)
    {
        if (identity.Claims.FirstOrDefault(x => x.Type.Equals(ClientRoleClaim, StringComparison.OrdinalIgnoreCase))
            is not { } clientRolesClaim)
        {
            yield break;
        }

        using var json = JsonDocument.Parse(clientRolesClaim.Value);
        foreach (var clientRole in ParseClientRoles(json.RootElement))
        {
            yield return clientRole;
        }
    }

    private IEnumerable<Claim> ParseRealmRoles(ClaimsIdentity identity)
    {
        if (identity.Claims.FirstOrDefault(x => x.Type.Equals(RealmRoleClaim, StringComparison.OrdinalIgnoreCase))
            is not { } realmRolesClaim)
        {
            yield break;
        }

        using var json = JsonDocument.Parse(realmRolesClaim.Value);
        if (!json.RootElement.TryGetProperty(RolesClaim, out var roles))
        {
            yield break;
        }

        foreach (var role in roles.EnumerateArray())
        {
            yield return new Claim(targetClaimType, role.ToString());
        }
    }
}