using System.Security.Claims;

namespace AspNetCoreExtensions.Keycloak.Internal;

internal static class ClaimsExtensions
{
    extension(ClaimsPrincipal principal)
    {
        internal string GetRequiredClaim(string claimType)
        {
            return principal.FindFirst(claimType)?.Value ?? throw MissingClaim(claimType);
        }
    }

    extension(ClaimsIdentity identity)
    {
        internal string GetRequiredClaim(string claimType)
        {
            return identity.FindFirst(claimType)?.Value ?? throw MissingClaim(claimType);
        }
    }

    private static InvalidOperationException MissingClaim(string claimType)
    {
        return new InvalidOperationException($"no {claimType} claim");
    }
}