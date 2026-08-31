using System.Security.Claims;
using AspNetCoreExtensions.Keycloak.Internal;
using AspNetCoreExtensions.Keycloak.Internal.Valkey;
using AspNetCoreExtensions.Keycloak.Options;
using Duende.AccessTokenManagement;
using Duende.AccessTokenManagement.OpenIdConnect;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using StackExchange.Redis;

namespace AspNetCoreExtensions.Keycloak;

public static class OpenIdConnectExtensions
{
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
        /// Add Keycloak based authentication. Realm and client roles are mapped.
        /// </summary>
        /// <param name="idp">Identity Provider configuration. Load this safely.</param>
        /// <param name="valkeyOptions">
        /// Valkey configuration. Sessions, user tokens and data protection keys are persisted to Valkey, so they
        /// survive a restart and the application can be scaled out.
        /// </param>
        /// <param name="configureOptions">Optional config and overrides for authentication configuration.</param>
        /// <param name="configureOpenIdConnect">ASP.NET Core OpenIdConnectOptions that go beyond basic configuration.</param>
        public void AddKeycloakAuthentication(KeycloakConfiguration idp,
            ValkeyOptions valkeyOptions,
            Action<KeycloakAuthenticationOptions>? configureOptions = null,
            Action<OpenIdConnectOptions>? configureOpenIdConnect = null)
        {
            var options = new KeycloakAuthenticationOptions();
            configureOptions?.Invoke(options);

            ValidateConfiguration(idp);

            services.AddSingleton<ClientAssertionService>(_ =>
                new ClientAssertionService(idp.Authority, idp.ClientId, idp.CertificatePath, idp.PrivateKeyPath));
            services.AddTransient<OidcEvents>();
            services.AddTransient<CookieEvents>();
            services.AddTransient<BackchannelLogoutService>();

            if (idp.CertificatePath is not null)
            {
                services.AddSingleton<JwksProvider>(_ => new JwksProvider(idp.CertificatePath));
                services.AddSingleton<ITokenRequestCustomizer, SignedJwtRequestCustomizer>();
            }

            services.AddStores(valkeyOptions);

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

                    // add additional scopes from IdP configuration
                    foreach (var scope in idp.Scopes)
                    {
                        x.Scope.Add(scope);
                    }

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

                    x.EventsType = typeof(CookieEvents);
                });

            // attached here rather than in AddCookie, which has no service provider to resolve the store from
            services.AddOptions<CookieAuthenticationOptions>(CookieAuthenticationDefaults.AuthenticationScheme)
                .Configure<ITicketStore>((cookieOptions, store) => cookieOptions.SessionStore = store);

            services.AddOpenIdConnectAccessTokenManagement();
        }

        /// <summary>
        /// Register the session, token and data protection key stores, all backed by Valkey.
        /// </summary>
        private void AddStores(ValkeyOptions valkeyOptions)
        {
            var keys = new ValkeyKeys(valkeyOptions.KeyPrefix);

            // lazy so nothing dials Valkey while services are still being registered, and so data protection and
            // the stores end up on the same connection
            var connection = new Lazy<IConnectionMultiplexer>(() =>
                ConnectionMultiplexer.Connect(valkeyOptions.BuildConfiguration()));

            services.AddSingleton(valkeyOptions);
            services.AddSingleton(keys);
            services.AddSingleton(_ => connection.Value);

            // one instance behind both interfaces, so revocation and the cookie handler share the same store
            services.AddSingleton<SessionStoreDistributed>();
            services.AddSingleton<ITicketStore>(x => x.GetRequiredService<SessionStoreDistributed>());
            services.AddSingleton<ISessionRevocationStore>(x => x.GetRequiredService<SessionStoreDistributed>());

            services.AddBlazorServerAccessTokenManagement<TokenStoreDistributed>();

            services.AddDataProtection()
                .SetApplicationName(valkeyOptions.EffectiveApplicationName)
                .PersistKeysToStackExchangeRedis(() => connection.Value.GetDatabase(), keys.DataProtectionKeys);
        }
    }

    extension(WebApplication app)
    {
        /// <summary>
        /// Map the back-channel logout endpoint, and the JWKS endpoint when signed JWT client authentication is
        /// configured. Call after <see cref="AddKeycloakAuthentication" />.
        /// </summary>
        public void UseKeycloakAuthentication()
        {
            // resolving it here also surfaces an unreadable certificate at startup rather than on first request
            if (app.Services.GetService<JwksProvider>() is not null)
            {
                app.MapJwksEndpoint();
            }

            app.MapBackchannelLogoutEndpoint();
        }

        /// <summary>
        /// Map JWKS endpoint for public key discovery. Do not use this if signed JWT authentication isn't used!
        /// </summary>
        private void MapJwksEndpoint()
        {
            app.MapGet("/.well-known/jwks", (JwksProvider jwks) => TypedResults.Ok(jwks.GetJwksResponse()))
                .AllowAnonymous().Produces<JwksResponse>();
        }

        private void MapBackchannelLogoutEndpoint()
        {
            app.MapPost("/signout-backchannel-oidc",
                async ([FromForm(Name = "logout_token")] string token, BackchannelLogoutService bls,
                    ISessionRevocationStore sessions, CancellationToken cancellationToken) =>
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

                    var sub = identity.GetRequiredClaim("sub");
                    var sid = identity.FindFirst("sid")?.Value;

                    if (sid is null)
                    {
                        await sessions.RevokeUserSessionsAsync(sub, cancellationToken);
                    }
                    else
                    {
                        await sessions.RevokeSessionAsync(sid, cancellationToken);
                    }

                    return Results.Ok();
                }).AllowAnonymous().DisableAntiforgery().Accepts<string>("application/x-www-form-urlencoded");
        }
    }
}