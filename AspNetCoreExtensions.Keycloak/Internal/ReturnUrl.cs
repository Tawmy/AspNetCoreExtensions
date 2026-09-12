using Microsoft.AspNetCore.Authentication;

namespace AspNetCoreExtensions.Keycloak.Internal;

internal static class ReturnUrl
{
    /// <summary>
    /// Turn a caller-supplied return URL into authentication properties, reducing anything absolute to its path so it
    /// cannot be used as an open redirect.
    /// </summary>
    internal static AuthenticationProperties ToAuthProperties(string? returnUrl)
    {
        // TODO: Use HttpContext.Request.PathBase instead.
        const string pathBase = "/";

        // Prevent open redirects.
        if (string.IsNullOrEmpty(returnUrl))
        {
            returnUrl = pathBase;
        }
        else if (!Uri.IsWellFormedUriString(returnUrl, UriKind.Relative))
        {
            returnUrl = new Uri(returnUrl, UriKind.Absolute).PathAndQuery;
        }
        else if (returnUrl[0] != '/')
        {
            returnUrl = $"{pathBase}{returnUrl}";
        }

        return new AuthenticationProperties { RedirectUri = returnUrl };
    }
}