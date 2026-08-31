using Duende.AccessTokenManagement.OpenIdConnect;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Logging;

namespace AspNetCoreExtensions.Keycloak.Internal;

/// <summary>
/// Ties the local session to the Keycloak one: the cookie is extended only while Keycloak still honours the refresh
/// token, and refreshing it resets Keycloak's idle timer in the same step.
/// </summary>
internal sealed class CookieEvents(IUserTokenManager tokens, ILogger<CookieEvents> logger) : CookieAuthenticationEvents
{
    /// <summary>
    /// Bound on how long a request waits for Keycloak, matching the StackExchange.Redis timeouts the rest of the
    /// request already lives with.
    /// </summary>
    private static readonly TimeSpan KeepAliveTimeout = TimeSpan.FromSeconds(5);

    public override async Task CheckSlidingExpiration(CookieSlidingExpirationContext context)
    {
        // the handler extends once half the cookie lifetime has passed; before that there is nothing to confirm
        if (!context.ShouldRenew || context.Principal is null)
        {
            return;
        }

        context.ShouldRenew = await KeepAliveAsync(context);
    }

    /// <summary>
    /// Refreshes the token set whether or not the access token has expired, which is what keeps the Keycloak session
    /// from idling out under a user who is active but makes no API calls.
    /// </summary>
    /// <returns>Whether Keycloak still accepts the refresh token.</returns>
    private async Task<bool> KeepAliveAsync(CookieSlidingExpirationContext context)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(context.HttpContext.RequestAborted);
        timeout.CancelAfter(KeepAliveTimeout);

        try
        {
            var result = await tokens.GetAccessTokenAsync(context.Principal!,
                new UserTokenRequestParameters { ForceTokenRenewal = true }, timeout.Token);

            if (!result.Succeeded)
            {
                logger.LogInformation("Not extending the session, Keycloak refused the refresh: {Failure}",
                    result.FailedResult);
            }

            return result.Succeeded;
        }
        catch (OperationCanceledException)
        {
            // a slow Keycloak must not hold up the request any further. The session keeps the expiry it already has,
            // and the next request tries again
            logger.LogWarning("Not extending the session, the refresh did not finish within {Timeout}",
                KeepAliveTimeout);
            return false;
        }
    }
}