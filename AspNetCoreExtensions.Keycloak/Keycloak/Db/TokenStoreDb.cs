using System.Globalization;
using System.Security.Claims;
using Duende.AccessTokenManagement;
using Duende.AccessTokenManagement.OpenIdConnect;
using Microsoft.EntityFrameworkCore;

namespace AspNetCoreExtensions.OpenIdConnect.Keycloak.Db;

internal class TokenStoreDb(IDbContextFactory<DatabaseContext> dbContextFactory) : IUserTokenStore
{
    public async Task StoreTokenAsync(ClaimsPrincipal user, UserToken token,
        UserTokenRequestParameters? parameters = null,
        CancellationToken cancellationToken = default)
    {
        var subStr = user.FindFirst("sub")?.Value
                     ?? throw new InvalidOperationException("User is missing sub claim");
        var sub = Guid.Parse(subStr, CultureInfo.InvariantCulture);

        await using var context = await dbContextFactory.CreateDbContextAsync(cancellationToken);

        var existingToken = await context.UserTokens.FirstOrDefaultAsync(x => x.Sub == sub, cancellationToken);

        if (existingToken is not null)
        {
            existingToken.AccessToken = token.AccessToken;
            existingToken.DPoPJsonWebKey = token.DPoPJsonWebKey;
            existingToken.Expiration = token.Expiration;
            existingToken.Scope = token.Scope;
            existingToken.ClientId = token.ClientId;
            existingToken.AccessTokenType = token.AccessTokenType;
            existingToken.RefreshToken = token.RefreshToken;
            existingToken.IdentityToken = token.IdentityToken;
        }
        else
        {
            await context.UserTokens.AddAsync(new Models.UserToken
            {
                Sub = sub,
                AccessToken = token.AccessToken,
                DPoPJsonWebKey = token.DPoPJsonWebKey,
                Expiration = token.Expiration,
                Scope = token.Scope,
                ClientId = token.ClientId,
                AccessTokenType = token.AccessTokenType,
                RefreshToken = token.RefreshToken,
                IdentityToken = token.IdentityToken
            }, cancellationToken);
        }

        try
        {
            await context.SaveChangesAsync(cancellationToken);
        }
        catch (Exception e)
        {
            throw new DbUpdateException($"Failed to save tokens for {sub} to the database.", e);
        }
    }

    public async Task<TokenResult<TokenForParameters>> GetTokenAsync(ClaimsPrincipal user,
        UserTokenRequestParameters? parameters = null, CancellationToken cancellationToken = default)
    {
        var subStr = user.FindFirst("sub")?.Value
                     ?? throw new InvalidOperationException("User is missing sub claim");
        var sub = Guid.Parse(subStr, CultureInfo.InvariantCulture);

        await using var context = await dbContextFactory.CreateDbContextAsync(cancellationToken);

        var token = await context.UserTokens.FirstOrDefaultAsync(x => x.Sub == sub, cancellationToken);

        if (token is null)
        {
            return TokenResult.Failure("Token not found");
        }

        var userToken = new UserToken
        {
            AccessToken = token.AccessToken,
            DPoPJsonWebKey = token.DPoPJsonWebKey,
            Expiration = token.Expiration,
            Scope = token.Scope,
            ClientId = token.ClientId,
            AccessTokenType = token.AccessTokenType,
            RefreshToken = token.RefreshToken,
            IdentityToken = token.IdentityToken
        };

        if (token.RefreshToken is null)
        {
            return new TokenForParameters(userToken, null);
        }

        var refreshToken = new UserRefreshToken(token.RefreshToken.Value, token.DPoPJsonWebKey);
        return new TokenForParameters(userToken, refreshToken);
    }

    public async Task ClearTokenAsync(ClaimsPrincipal user, UserTokenRequestParameters? parameters = null,
        CancellationToken cancellationToken = default)
    {
        var subStr = user.FindFirst("sub")?.Value
                     ?? throw new InvalidOperationException("User is missing sub claim");
        var sub = Guid.Parse(subStr, CultureInfo.InvariantCulture);

        await using var context = await dbContextFactory.CreateDbContextAsync(cancellationToken);

        context.UserTokens.RemoveRange(context.UserTokens.Where(x => x.Sub == sub));
        await context.SaveChangesAsync(cancellationToken);
    }
}