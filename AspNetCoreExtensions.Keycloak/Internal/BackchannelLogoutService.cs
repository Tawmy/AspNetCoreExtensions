using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace AspNetCoreExtensions.Keycloak.Internal;

/// <summary>
///     This class is heavily inspired by Duende's projects. Check out their work, it is fantasic.
/// </summary>
internal class BackchannelLogoutService(
    IAuthenticationSchemeProvider authenticationSchemeProvider,
    IOptionsMonitor<OpenIdConnectOptions> optionsMonitor)
{
    public async Task<ClaimsIdentity?> ValidateLogoutTokenAsync(string token,
        CancellationToken cancellationToken = default)
    {
        var claims = await ValidateJwtAsync(token, cancellationToken);

        // Logout token must include sub claim
        if (claims?.FindFirst("sub") is null)
        {
            return null;
        }

        // Logout token must NOT include nonce
        var nonce = claims.FindFirst("nonce")?.Value;
        if (!string.IsNullOrWhiteSpace(nonce))
        {
            return null;
        }

        // Logout token must events claim, and a backchannel logout event inside
        var eventsJson = claims.FindFirst("events")?.Value;
        if (string.IsNullOrWhiteSpace(eventsJson))
        {
            return null;
        }

        try
        {
            var events = JsonDocument.Parse(eventsJson);
            if (!events.RootElement.TryGetProperty("http://schemas.openid.net/event/backchannel-logout", out _))
            {
                return null;
            }
        }
        catch (JsonException)
        {
            return null;
        }

        return claims;
    }

    private async Task<ClaimsIdentity?> ValidateJwtAsync(string jwt, CancellationToken cancellationToken)
    {
        var handler = new JsonWebTokenHandler();
        var parameters = await GetTokenValidationParametersAsync(cancellationToken);

        var result = await handler.ValidateTokenAsync(jwt, parameters);
        return result.IsValid ? result.ClaimsIdentity : null;
    }

    private async Task<TokenValidationParameters> GetTokenValidationParametersAsync(CancellationToken cancellationToken)
    {
        if (await authenticationSchemeProvider.GetDefaultChallengeSchemeAsync() is not { } challengeScheme)
        {
            throw new InvalidOperationException("Failed to get default challenge scheme");
        }


        if (optionsMonitor.Get(challengeScheme.Name) is not { } oidcOptions)
        {
            throw new InvalidOperationException("Failed to get oidc options for challenge scheme");
        }

        var oidcConfiguration = oidcOptions.Configuration
                                ?? (oidcOptions.ConfigurationManager is not null
                                    ? await oidcOptions.ConfigurationManager.GetConfigurationAsync(cancellationToken)
                                    : null);

        if (oidcConfiguration is null)
        {
            throw new InvalidOperationException("Failed to get oidc configuration");
        }

        var parameters = new TokenValidationParameters
        {
            ValidIssuer = oidcConfiguration.Issuer,
            ValidAudience = oidcOptions.ClientId,
            IssuerSigningKeys = oidcConfiguration.SigningKeys
        };

        return parameters;
    }
}