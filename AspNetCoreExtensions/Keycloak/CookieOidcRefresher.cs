using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace AspNetCoreExtensions.Keycloak;

// https://github.com/dotnet/aspnetcore/issues/8175
internal sealed class CookieOidcRefresher(IOptionsMonitor<OpenIdConnectOptions> oidcOptionsMonitor)
{
    private readonly OpenIdConnectProtocolValidator _oidcTokenValidator = new()
    {
        // We no longer have the original nonce cookie which is deleted at the end of the authorization code flow having served its purpose.
        // Even if we had the nonce, it's likely expired. It's not intended for refresh requests. Otherwise, we'd use oidcOptions.ProtocolValidator.
        RequireNonce = false
    };

    public async Task ValidateOrRefreshCookieAsync(CookieValidatePrincipalContext validateContext, string oidcScheme)
    {
        var accessTokenExpirationText = validateContext.Properties.GetTokenValue("expires_at");
        if (!DateTimeOffset.TryParse(accessTokenExpirationText, out var accessTokenExpiration))
        {
            return;
        }

        var oidcOptions = oidcOptionsMonitor.Get(oidcScheme);
        var now = oidcOptions.TimeProvider!.GetUtcNow();
        if (now + TimeSpan.FromMinutes(1) < accessTokenExpiration)
        {
            return;
        }

        var oidcConfiguration =
            await oidcOptions.ConfigurationManager!.GetConfigurationAsync(validateContext.HttpContext.RequestAborted);
        var tokenEndpoint = oidcConfiguration.TokenEndpoint ??
                            throw new InvalidOperationException("Cannot refresh cookie. TokenEndpoint missing!");

        using var refreshResponse = await oidcOptions.Backchannel.PostAsync(tokenEndpoint,
            new FormUrlEncodedContent(new Dictionary<string, string?>
            {
                ["grant_type"] = "refresh_token",
                ["client_id"] = oidcOptions.ClientId,
                ["client_secret"] = oidcOptions.ClientSecret,
                ["scope"] = string.Join(" ", oidcOptions.Scope),
                ["refresh_token"] = validateContext.Properties.GetTokenValue("refresh_token")
            }));

        if (!refreshResponse.IsSuccessStatusCode)
        {
            validateContext.RejectPrincipal();
            return;
        }

        var refreshJson = await refreshResponse.Content.ReadAsStringAsync();
        var message = new OpenIdConnectMessage(refreshJson);

        var validationParameters = oidcOptions.TokenValidationParameters.Clone();
        if (oidcOptions.ConfigurationManager is BaseConfigurationManager baseConfigurationManager)
        {
            validationParameters.ConfigurationManager = baseConfigurationManager;
        }
        else
        {
            validationParameters.ValidIssuer = oidcConfiguration.Issuer;
            validationParameters.IssuerSigningKeys = oidcConfiguration.SigningKeys;
        }

        var validationResult = await oidcOptions.TokenHandler.ValidateTokenAsync(message.IdToken, validationParameters);

        if (!validationResult.IsValid)
        {
            validateContext.RejectPrincipal();
            return;
        }

        var validatedIdToken = JwtSecurityTokenConverter.Convert(validationResult.SecurityToken as JsonWebToken);
        validatedIdToken.Payload["nonce"] = null;
        _oidcTokenValidator.ValidateTokenResponse(new OpenIdConnectProtocolValidationContext
        {
            ProtocolMessage = message,
            ClientId = oidcOptions.ClientId,
            ValidatedIdToken = validatedIdToken
        });

        if (oidcOptions.GetClaimsFromUserInfoEndpoint && !string.IsNullOrEmpty(oidcConfiguration.UserInfoEndpoint))
        {
            await AddClaimsFromUserInfoEndpointAsync(oidcConfiguration.UserInfoEndpoint, message.AccessToken,
                oidcScheme,
                validatedIdToken, validationResult.ClaimsIdentity, oidcOptions,
                validateContext.HttpContext.RequestAborted);
        }

        validateContext.ShouldRenew = true;
        validateContext.ReplacePrincipal(new ClaimsPrincipal(validationResult.ClaimsIdentity));

        var expiresIn = int.Parse(message.ExpiresIn, NumberStyles.Integer, CultureInfo.InvariantCulture);
        var expiresAt = now + TimeSpan.FromSeconds(expiresIn);
        validateContext.Properties.StoreTokens([
            new AuthenticationToken { Name = "access_token", Value = message.AccessToken },
            new AuthenticationToken { Name = "id_token", Value = message.IdToken },
            new AuthenticationToken { Name = "refresh_token", Value = message.RefreshToken },
            new AuthenticationToken { Name = "token_type", Value = message.TokenType },
            new AuthenticationToken
                { Name = "expires_at", Value = expiresAt.ToString("o", CultureInfo.InvariantCulture) }
        ]);
    }

    // https://github.com/dotnet/aspnetcore/issues/58826#issuecomment-2492738142
    private static async Task AddClaimsFromUserInfoEndpointAsync(string userInfoEndpoint, string accessToken,
        string oidcScheme, JwtSecurityToken validatedIdToken, ClaimsIdentity identity, OpenIdConnectOptions options,
        CancellationToken cancellationToken)
    {
        var requestMessage = new HttpRequestMessage(HttpMethod.Get, userInfoEndpoint);
        requestMessage.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        requestMessage.Version = options.Backchannel.DefaultRequestVersion;
        var responseMessage = await options.Backchannel.SendAsync(requestMessage, cancellationToken);
        responseMessage.EnsureSuccessStatusCode();
        var userInfoResponse = await responseMessage.Content.ReadAsStringAsync(cancellationToken);

        string userInfoJson;
        var contentType = responseMessage.Content.Headers.ContentType;
        if (contentType?.MediaType?.Equals("application/json", StringComparison.OrdinalIgnoreCase) ?? false)
        {
            userInfoJson = userInfoResponse;
        }
        else if (contentType?.MediaType?.Equals("application/jwt", StringComparison.OrdinalIgnoreCase) ?? false)
        {
            var userInfoEndpointJwt = new JwtSecurityToken(userInfoResponse);
            userInfoJson = userInfoEndpointJwt.Payload.SerializeToJson();
        }
        else
        {
            return;
        }

        using var user = JsonDocument.Parse(userInfoJson);
        options.ProtocolValidator.ValidateUserInfoResponse(new OpenIdConnectProtocolValidationContext
        {
            UserInfoEndpointResponse = userInfoResponse,
            ValidatedIdToken = validatedIdToken
        });

        foreach (var action in options.ClaimActions)
        {
            action.Run(user.RootElement, identity, options.ClaimsIssuer ?? oidcScheme);
        }
    }
}