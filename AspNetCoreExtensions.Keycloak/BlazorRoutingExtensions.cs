using AspNetCoreExtensions.Keycloak.Internal;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;

namespace AspNetCoreExtensions.Keycloak;

public static class BlazorRoutingExtensions
{
    // https://github.com/dotnet/blazor-samples/blob/main/9.0/BlazorWebAppOidcBff/BlazorWebAppOidc/LoginLogoutEndpointRouteBuilderExtensions.cs
    extension(IEndpointRouteBuilder endpoints)
    {
        /// <summary>
        /// Map the browser-facing sign-in and sign-out endpoints. Both are document navigations; see
        /// <see cref="BffExtensions.MapBffEndpoints" /> for the <c>fetch</c>-callable counterpart.
        /// </summary>
        public IEndpointConventionBuilder MapLoginAndLogout(string oidcScheme)
        {
            var group = endpoints.MapGroup("");

            group.MapGet("/login", (string? returnUrl) =>
                TypedResults.Challenge(ReturnUrl.ToAuthProperties(returnUrl))).AllowAnonymous();

            // Sign out of the Cookie and OIDC handlers. If you do not sign out with the OIDC handler,
            // the user will automatically be signed back in the next time they visit a page that requires authentication
            // without being able to choose another account.
            group.MapPost("/logout", ([FromForm] string? returnUrl) => TypedResults.SignOut(
                ReturnUrl.ToAuthProperties(returnUrl),
                [CookieAuthenticationDefaults.AuthenticationScheme, oidcScheme]));

            return group;
        }
    }
}