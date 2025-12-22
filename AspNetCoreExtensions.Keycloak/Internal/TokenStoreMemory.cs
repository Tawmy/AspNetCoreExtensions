using System.Collections.Concurrent;
using System.Security.Claims;
using Duende.AccessTokenManagement;
using Duende.AccessTokenManagement.OpenIdConnect;

namespace AspNetCoreExtensions.Keycloak.Internal;

internal class TokenStoreMemory : IUserTokenStore
{
    private static readonly ConcurrentDictionary<string, TokenForParameters> Tokens = new();

    public Task<TokenResult<TokenForParameters>> GetTokenAsync(ClaimsPrincipal user,
        UserTokenRequestParameters? parameters = null,
        CancellationToken cancellationToken = default)
    {
        var sub = user.FindFirst("sub")?.Value
                  ?? throw new InvalidOperationException("User is missing sub claim");

        return Tokens.TryGetValue(sub, out var value)
            ? Task.FromResult(TokenResult.Success(value))
            : Task.FromResult((TokenResult<TokenForParameters>)TokenResult.Failure("Token not found"));
    }

    public Task StoreTokenAsync(ClaimsPrincipal user, UserToken token, UserTokenRequestParameters? parameters = null,
        CancellationToken cancellationToken = default)
    {
        var sub = user.FindFirst("sub")?.Value ?? throw new InvalidOperationException("User is missing sub claim");
        Tokens[sub] = new TokenForParameters(token, token.RefreshToken is not null
            ? new UserRefreshToken(token.RefreshToken.Value, token.DPoPJsonWebKey)
            : null);

        return Task.CompletedTask;
    }

    public Task ClearTokenAsync(ClaimsPrincipal user, UserTokenRequestParameters? parameters = null,
        CancellationToken cancellationToken = default)
    {
        var sub = user.FindFirst("sub")?.Value ?? throw new InvalidOperationException("User is missing sub claim");

        Tokens.TryRemove(sub, out _);
        return Task.CompletedTask;
    }
}