using System.Security.Claims;
using AspNetCoreExtensions.Keycloak;
using Duende.AccessTokenManagement.OpenIdConnect;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace AspNetCoreExtensions;

public static class OpenIdConnectExtensions
{
    private static readonly SessionStore SessionStore = new();

    private static void ValidateConfiguration(KeycloakConfiguration idp)
    {
        if (string.IsNullOrWhiteSpace(idp.ClientSecret) && (idp.PrivateKeyPath is null || idp.CertificatePath is null))
        {
            throw new InvalidOperationException("Either client secret or both certificate uris must be set.");
        }
    }

    /// <param name="services">Service collection.</param>
    extension(IServiceCollection services)
    {
        /// <summary>
        ///     Add Keycloak based authentication. Realm and client roles are mapped.
        /// </summary>
        /// <param name="idp">Identity Provider configuration. Load this safely.</param>
        /// <param name="configureOptions">Optional config and overrides for authentication configuration.</param>
        /// <param name="configureOpenIdConnect">ASP.NET Core OpenIdConnectOptions that go beyond basic configuration.</param>
        public void AddKeycloakAuthentication(KeycloakConfiguration idp,
            Action<KeycloakAuthenticationOptions>? configureOptions = null,
            Action<OpenIdConnectOptions>? configureOpenIdConnect = null)
        {
            var options = new KeycloakAuthenticationOptions();
            configureOptions?.Invoke(options);

            ValidateConfiguration(idp);

            services.AddSingleton<ClientAssertionService>(_ =>
                new ClientAssertionService(idp.Authority, idp.ClientId, idp.CertificatePath, idp.PrivateKeyPath));
            services.AddTransient<OidcEvents>();
            services.AddTransient<BackchannelLogoutService>();

            if (idp.CertificatePath is not null)
            {
                services.AddSingleton<JwksProvider>(_ => new JwksProvider(idp.CertificatePath));
            }

            services.AddAuthentication(x =>
                {
                    x.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    x.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    x.DefaultChallengeScheme = options.AuthenticationScheme;
                })
                .AddOpenIdConnect(options.AuthenticationScheme, x =>
                {
                    // ASP.NET Core adds default scopes, remove them to avoid conflicts
                    x.Scope.Clear();

                    configureOpenIdConnect?.Invoke(x);

                    // use cookie authentication scheme to persist user credentials across requests
                    x.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;

                    // add openid scope to trigger OpenID Connect flow
                    x.Scope.Add(OpenIdConnectScope.OpenId);

                    // using authority automatically sets endpoints like auth, token, and userinfo
                    x.Authority = idp.Authority;

                    // use client id and secret as backend can save secret safely.
                    // pkce is enabled by default (force in keycloak client for double security)
                    x.ClientId = idp.ClientId;

                    if (idp.ClientSecret is not null)
                    {
                        x.ClientSecret = idp.ClientSecret;
                    }

                    // Use code for auth code flow, avoid implicit flow (less secure, will be omitted from OAuth 2.1 spec)
                    x.ResponseType = OpenIdConnectResponseType.Code;

                    // do not map claims based on SOAP/WS-Fed defaults, doesn't match Keycloak
                    x.MapInboundClaims = false;

                    // Keycloak uses preferred_username as default, feel free to use any other claim
                    x.TokenValidationParameters.NameClaimType = options.NameClaimType;

                    // certain claims like roles are not part of ID token to keep its size in check
                    x.GetClaimsFromUserInfoEndpoint = true;

                    // map Keycloak realm roles
                    x.ClaimActions.MapJsonSubKey(ClaimTypes.Role, "realm_access", "roles");

                    // map Keycloak client roles. They will be available using clientName.roleName (eg. blazor-sample.read-users)
                    x.ClaimActions.Add(new KeycloakClientRolesClaimAction());

                    // .NET 9 added pushed authorization requests, avoids OIDC request using GET query parameters
                    // https://oauth.net/2/pushed-authorization-requests/ <- linked resource has great visualisation
                    x.PushedAuthorizationBehavior = PushedAuthorizationBehavior.Require;

                    // Save tokens so we can use refresh tokens and use ID tokens for logout
                    x.SaveTokens = true;

                    x.EventsType = typeof(OidcEvents);
                })
                .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, x =>
                {
                    // https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#session-expiration

                    // cookie is valid for 30 mins as per owasp recommendation
                    x.Cookie.MaxAge = TimeSpan.FromMinutes(30);

                    // http-only cookie for increased security (no js access to cookie)
                    x.Cookie.HttpOnly = true;

                    // session id is considered essential, does not require user consent in EU
                    x.Cookie.IsEssential = true;

                    // always require https
                    x.Cookie.SecurePolicy = CookieSecurePolicy.Always;

                    // cookie is valid for 30 mins as per owasp recommendation
                    x.ExpireTimeSpan = TimeSpan.FromMinutes(30);

                    // if half of cookie lifetime expired, a new one is issued
                    x.SlidingExpiration = true;

                    // Custom session store reduces cookie size and allows for better session management
                    x.SessionStore = SessionStore;

                    // TODO refresh token if session extended -> keep Keycloak session alive
                });

            services.AddOpenIdConnectAccessTokenManagement()
                .AddBlazorServerAccessTokenManagement<ServerSideTokenStore>();
        }
    }

    extension(WebApplication app)
    {
        public void UseKeycloakAuthentication(KeycloakConfiguration idp)
        {
            ValidateConfiguration(idp);

            if (idp.CertificatePath is not null)
            {
                app.MapGet("/.well-known/jwks", (JwksProvider jwks) => TypedResults.Ok(jwks.GetJwksResponse()))
                    .AllowAnonymous().Produces<JwksResponse>();
            }

            app.MapBackchannelLogoutEndpoint();
        }

        private void MapBackchannelLogoutEndpoint()
        {
            app.MapPost("/signout-backchannel-oidc",
                async ([FromForm(Name = "logout_token")] string token, BackchannelLogoutService bls,
                    CancellationToken cancellationToken) =>
                {
                    if (string.IsNullOrWhiteSpace(token))
                    {
                        return Results.BadRequest("Logout token is required.");
                    }

                    var identity = await bls.ValidateLogoutTokenAsync(token, cancellationToken);

                    if (identity is null)
                    {
                        return Results.BadRequest("Invalid logout token.");
                    }

                    await SessionStore.RemoveAsync(identity.FindFirst("sid")?.Value
                                                   ?? throw new InvalidOperationException("no sid claim"));
                    return Results.Ok();
                }).AllowAnonymous().DisableAntiforgery().Accepts<string>("application/x-www-form-urlencoded");
        }
    }
}