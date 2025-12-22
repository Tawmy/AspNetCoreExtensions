using System.Net.Http.Headers;
using Duende.AccessTokenManagement.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Yarp.ReverseProxy.Transforms;

namespace AspNetCoreExtensions.OpenIdConnect;

internal static class BffExtensions
{
    private const string Prefix = "bff";

    /// <param name="app">WebApplication instance. Must already have been built.</param>
    extension(WebApplication app)
    {
        /// <summary>
        ///     Map BFF endpoints for simple forwarding using YARP. The endpoints will be mapped to /bff/{prefix}.
        /// </summary>
        /// <param name="endpoints">
        ///     One or multiple endpoints to map. Consists of prefix and destination URI.
        ///     Exmaple: new BffEndpoint("keycloak", "https://ffxiv.id/admin/realms/eorzea")
        /// </param>
        public void MapBffForwarders(params IEnumerable<BffEndpoint> endpoints)
        {
            foreach (var endpoint in endpoints)
            {
                app.MapBffForwarder(endpoint.Prefix, endpoint.DestinationUri);
            }
        }

        /// <summary>
        ///     Map BFF endpoints for simple forwarding using YARP.
        /// </summary>
        /// <remarks>
        ///     No resilience as HttpClient in Client project already uses it. This needs to do nothing but forward requests.
        /// </remarks>
        /// <param name="bffPrefix">Path to map. It will always begin with bff/{bffPrefix}.</param>
        /// <param name="destinationUri">Destination after <see cref="bffPrefix" />: bff/{bffPrefix}/{destinationUrl}.</param>
        private void MapBffForwarder(string bffPrefix, string destinationUri)
        {
            var prefix = $"{Prefix}/{bffPrefix}";

            app.MapForwarder($"{prefix}/{{**catch-all}}", destinationUri, transformBuilder =>
            {
                transformBuilder.AddPathRemovePrefix($"/{prefix}");
                transformBuilder.AddRequestTransform(async transformContext =>
                {
                    var tokenResult = await transformContext.HttpContext.GetUserAccessTokenAsync();

                    if (tokenResult.Token?.AccessToken.ToString() is { } accessToken)
                    {
                        transformContext.ProxyRequest.Headers.Authorization =
                            new AuthenticationHeaderValue("Bearer", accessToken);
                    }
                });
            }).RequireAuthorization();
        }
    }
}

public record BffEndpoint(string Prefix, string DestinationUri);