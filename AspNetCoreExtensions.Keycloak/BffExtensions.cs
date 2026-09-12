using System.Net.Http.Headers;
using System.Security.Claims;
using AspNetCoreExtensions.Keycloak.Internal;
using Duende.AccessTokenManagement.OpenIdConnect;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Yarp.ReverseProxy.Transforms;

namespace AspNetCoreExtensions.Keycloak;

public static class BffExtensions
{
    internal const string Prefix = "/bff";

    /// <param name="app">WebApplication instance. Must already have been built.</param>
    extension(WebApplication app)
    {
        /// <summary>
        /// Map the endpoints a single-page client calls directly: <c>/bff/user</c> and <c>/bff/logout</c>.
        /// </summary>
        /// <param name="oidcScheme">OpenID Connect scheme to sign out of alongside the cookie.</param>
        public IEndpointConventionBuilder MapBffEndpoints(string oidcScheme)
        {
            var group = app.MapGroup(Prefix);

            group.MapGet("/user", (ClaimsPrincipal user) => user.Identity?.IsAuthenticated is true
                    ? Results.Ok(user.Claims.Select(x => new UserClaim(x.Type, x.Value)))
                    : Results.Unauthorized())
                .AllowAnonymous().Produces<IEnumerable<UserClaim>>().Produces(StatusCodes.Status401Unauthorized);

            group.MapPost("/logout", (string? returnUrl) => TypedResults.SignOut(
                    ReturnUrl.ToAuthProperties(returnUrl),
                    [CookieAuthenticationDefaults.AuthenticationScheme, oidcScheme]))
                .AllowAnonymous().DisableAntiforgery();

            return group;
        }

        /// <summary>
        /// Map BFF endpoints for simple forwarding using YARP. The endpoints will be mapped to /bff/{prefix}.
        /// </summary>
        /// <param name="endpoints">
        /// One or multiple endpoints to map. Consists of prefix and destination URI.
        /// Exmaple: new BffEndpoint("keycloak", "https://ffxiv.id/admin/realms/eorzea")
        /// </param>
        /// <returns>The group every forwarder was mapped into, for applying conventions.</returns>
        public IEndpointConventionBuilder MapBffForwarders(params IEnumerable<BffEndpoint> endpoints)
        {
            var group = app.MapGroup(Prefix);

            foreach (var endpoint in endpoints)
            {
                group.MapBffForwarder(endpoint.Prefix, endpoint.DestinationUri);
            }

            return group;
        }
    }

    extension(IEndpointRouteBuilder endpoints)
    {
        /// <summary>
        /// Map BFF endpoints for simple forwarding using YARP.
        /// </summary>
        /// <remarks>
        /// No resilience as HttpClient in Client project already uses it. This needs to do nothing but forward requests.
        /// </remarks>
        /// <param name="bffPrefix">Path to map. It will always begin with bff/{bffPrefix}.</param>
        /// <param name="destinationUri">Destination after <see cref="bffPrefix" />: bff/{bffPrefix}/{destinationUrl}.</param>
        private void MapBffForwarder(string bffPrefix, string destinationUri)
        {
            endpoints.MapForwarder($"{bffPrefix}/{{**catch-all}}", destinationUri, transformBuilder =>
            {
                transformBuilder.AddPathRemovePrefix($"{Prefix}/{bffPrefix}");
                transformBuilder.AddRequestTransform(async transformContext =>
                {
                    var tokenResult = await transformContext.HttpContext.GetUserAccessTokenAsync();

                    if (tokenResult.Token?.AccessToken.ToString() is { } accessToken)
                    {
                        transformContext.ProxyRequest.Headers.Authorization =
                            new AuthenticationHeaderValue("Bearer", accessToken);
                    }
                });
            }).RequireAuthorization(x => x
                // name scheme to prevent automatic redirect if unauthenticated -> would break Blazor WASM standalone
                .AddAuthenticationSchemes(CookieAuthenticationDefaults.AuthenticationScheme)
                .RequireAuthenticatedUser());
        }
    }
}

public record BffEndpoint(string Prefix, string DestinationUri);

/// <summary>One claim of the signed-in user, as <c>/bff/user</c> returns it.</summary>
/// <remarks>Every claim on the cookie principal is visible to the browser, so do not map secrets into it.</remarks>
public record UserClaim(string Type, string Value);