using System.Security.Claims;
using AspNetCoreExtensions.Keycloak;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace AspNetCoreExtensions;

public static class OpenIdConnectExtensions
{
    public static AuthenticationBuilder AddKeycloakAuthentication(this IServiceCollection services,
        KeycloakAuthenticationConfiguration config, Action<KeycloakAuthenticationOptions> configureOptions)
    {
        var options = new KeycloakAuthenticationOptions();
        configureOptions(options);

        return services.AddAuthentication(options.AuthenticationScheme)
            .AddOpenIdConnect(options.AuthenticationScheme, x =>
            {
                // use cookie authentication scheme to persist user credentials across requests
                x.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;

                // use default openid and profile scopes, feel free to add any others that are necessary in client
                x.Scope.Add(OpenIdConnectScope.OpenIdProfile);

                // using authority automatically sets endpoints like auth, token, and userinfo
                x.Authority = config.OidcAuthority;

                // use client id and secret as backend can save secret safely.
                // pkce is enabled by default (force in keycloak client for double security)
                x.ClientId = config.OidcClientId;
                x.ClientSecret = config.OidcClientSecret;

                // Use code for auth code flow, avoid implicit flow (less secure, will be omitted from OAuth 2.1 spec)
                x.ResponseType = OpenIdConnectResponseType.Code;

                // do not map claims based on SOAP/WS-Fed defaults, doesn't match Keycloak
                x.MapInboundClaims = false;

                // Keycloak uses preferred_username as default, feel free to use any other claim
                x.TokenValidationParameters.NameClaimType = "preferred_username";

                // certain claims like roles are not part of ID token to keep its size in check
                x.GetClaimsFromUserInfoEndpoint = true;

                // map Keycloak realm roles
                x.ClaimActions.MapJsonSubKey(ClaimTypes.Role, "realm_access", "roles");

                // map Keycloak client roles. They will be available using clientName.roleName (eg. blazor-sample.read-users)
                x.ClaimActions.Add(new KeycloakClientRolesClaimAction());

                // .NET 9 added pushed authorization requests, avoids OIDC request using GET query parameters
                // https://oauth.net/2/pushed-authorization-requests/ <- linked resource has great visualisation
                x.PushedAuthorizationBehavior = PushedAuthorizationBehavior.Require;
            })
            .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, x =>
            {
                // https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#session-expiration
                x.Cookie.MaxAge = TimeSpan.FromMinutes(30); // cookie is valid for 30 mins as per owasp recommendation
                x.Cookie.HttpOnly = true; // http-only cookie for increased security (no js access to cookie)
                x.Cookie.IsEssential = true; // session id is considered essential, does not require user consent in EU
                x.Cookie.SecurePolicy = CookieSecurePolicy.Always; // always require https

                x.ExpireTimeSpan = TimeSpan.FromMinutes(30); // cookie is valid for 30 mins as per owasp recommendation
                x.SlidingExpiration = true; // if half of cookie lifetime expired, a new one is issued
            });
    }

    /// <summary>
    ///     Add OAuth refresh token support
    /// </summary>
    public static void ConfigureCookieOidcRefresh(this IServiceCollection services, string cookieScheme,
        string oidcScheme)
    {
        // ASP.NET Core does currently not support OAuth refresh tokens
        // Support is planned for .NET 10: https://github.com/dotnet/aspnetcore/issues/8175
        services.AddSingleton<CookieOidcRefresher>();
        services.AddOptions<CookieAuthenticationOptions>(cookieScheme)
            .Configure<CookieOidcRefresher>((cookieOptions, refresher) =>
            {
                cookieOptions.Events.OnValidatePrincipal =
                    context => refresher.ValidateOrRefreshCookieAsync(context, oidcScheme);
            });
        services.AddOptions<OpenIdConnectOptions>(oidcScheme).Configure(oidcOptions =>
        {
            // request offline_acccess scope to retrieve a refresh token without expiry
            oidcOptions.Scope.Add(OpenIdConnectScope.OfflineAccess);
            // ASP.NET Core does not save access and refresh tokens by default, but we need to store the refresh token
            oidcOptions.SaveTokens = true;
        });
    }
}