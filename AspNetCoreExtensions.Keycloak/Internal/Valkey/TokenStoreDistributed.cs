using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Serialization;
using AspNetCoreExtensions.Keycloak.Options;
using Duende.AccessTokenManagement;
using Duende.AccessTokenManagement.DPoP;
using Duende.AccessTokenManagement.OpenIdConnect;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using StackExchange.Redis;

namespace AspNetCoreExtensions.Keycloak.Internal.Valkey;

/// <summary>
/// Duende access token store backed by Valkey, so a refresh token issued on one instance is usable on all of them.
/// </summary>
internal sealed class TokenStoreDistributed(
    IConnectionMultiplexer connection,
    ValkeyKeys keys,
    ValkeyOptions options,
    IDataProtectionProvider dataProtectionProvider,
    ILogger<TokenStoreDistributed> logger) : IUserTokenStore
{
    private readonly IDataProtector _protector =
        dataProtectionProvider.CreateProtector("AspNetCoreExtensions.Keycloak.TokenStore.v1");

    private IDatabase Database => connection.GetDatabase();

    public async Task StoreTokenAsync(ClaimsPrincipal user, UserToken token,
        UserTokenRequestParameters? parameters = null, CancellationToken cancellationToken = default)
    {
        var sub = user.GetRequiredClaim("sub");

        var stored = new StoredUserToken
        {
            AccessToken = token.AccessToken.ToString(),
            AccessTokenType = token.AccessTokenType?.ToString(),
            DPoPJsonWebKey = token.DPoPJsonWebKey?.ToString(),
            Expiration = token.Expiration,
            Scope = token.Scope?.ToString(),
            ClientId = token.ClientId.ToString(),
            RefreshToken = token.RefreshToken?.ToString(),
            IdentityToken = token.IdentityToken?.ToString()
        };

        var payload = _protector.Protect(JsonSerializer.SerializeToUtf8Bytes(stored,
            TokenStoreJsonContext.Default.StoredUserToken));

        await Database.StringSetAsync(keys.UserTokens(sub), payload, GetTimeToLive(stored, DateTimeOffset.UtcNow));
    }

    public async Task<TokenResult<TokenForParameters>> GetTokenAsync(ClaimsPrincipal user,
        UserTokenRequestParameters? parameters = null, CancellationToken cancellationToken = default)
    {
        var sub = user.GetRequiredClaim("sub");
        var database = Database;

        var payload = await database.StringGetAsync(keys.UserTokens(sub));

        if (payload.IsNullOrEmpty)
        {
            return TokenResult.Failure("Token not found");
        }

        StoredUserToken? stored;

        try
        {
            stored = JsonSerializer.Deserialize(_protector.Unprotect((byte[])payload!),
                TokenStoreJsonContext.Default.StoredUserToken);
        }
        catch (Exception e)
        {
            // usually a rotated key ring; leaving it would fail every request until it expires
            logger.LogWarning(e, "Failed to read stored tokens, removing them");
            await database.KeyDeleteAsync(keys.UserTokens(sub));
            return TokenResult.Failure("Token could not be read");
        }

        if (stored is null)
        {
            return TokenResult.Failure("Token not found");
        }

        var userToken = new UserToken
        {
            AccessToken = AccessToken.Parse(stored.AccessToken),
            AccessTokenType = stored.AccessTokenType is not null
                ? AccessTokenType.Parse(stored.AccessTokenType)
                : null,
            DPoPJsonWebKey = stored.DPoPJsonWebKey is not null ? DPoPProofKey.Parse(stored.DPoPJsonWebKey) : null,
            Expiration = stored.Expiration,
            Scope = stored.Scope is not null ? Scope.Parse(stored.Scope) : null,
            ClientId = ClientId.Parse(stored.ClientId),
            RefreshToken = stored.RefreshToken is not null ? RefreshToken.Parse(stored.RefreshToken) : null,
            IdentityToken = stored.IdentityToken is not null ? IdentityToken.Parse(stored.IdentityToken) : null
        };

        return new TokenForParameters(userToken, userToken.RefreshToken is not null
            ? new UserRefreshToken(userToken.RefreshToken.Value, userToken.DPoPJsonWebKey)
            : null);
    }

    public async Task ClearTokenAsync(ClaimsPrincipal user, UserTokenRequestParameters? parameters = null,
        CancellationToken cancellationToken = default)
    {
        await Database.KeyDeleteAsync(keys.UserTokens(user.GetRequiredClaim("sub")));
    }

    /// <summary>
    /// Taken from the refresh token, which is what the entry exists for, falling back to the access token when
    /// there is none. Offline tokens carry no expiry and land on
    /// <see cref="ValkeyOptions.OfflineTokenTimeToLive" />, which tracks Keycloak's own idle window and so is padded
    /// like a real expiry.
    /// </summary>
    private TimeSpan GetTimeToLive(StoredUserToken stored, DateTimeOffset now)
    {
        var expiration = stored.RefreshToken is null
            ? stored.Expiration
            : GetExpiration(stored.RefreshToken);

        var remaining = expiration - now;

        return remaining > TimeSpan.Zero
            ? remaining.Value + ValkeyOptions.ExpirationGracePeriod
            : options.OfflineTokenTimeToLive + ValkeyOptions.ExpirationGracePeriod;
    }

    private DateTimeOffset? GetExpiration(string refreshToken)
    {
        if (!new JsonWebTokenHandler().CanReadToken(refreshToken))
        {
            logger.LogDebug("Refresh token is not a JWT, falling back to the configured lifetime");
            return null;
        }

        try
        {
            // absent when the token is an offline token, where it reads as the epoch or as MinValue
            return new JsonWebToken(refreshToken).ValidTo;
        }
        catch (SecurityTokenMalformedException e)
        {
            logger.LogDebug(e, "Failed to read the refresh token expiry, falling back to the configured lifetime");
            return null;
        }
    }
}

/// <summary>
/// Wire format for a stored token set. Duende's typed token values are kept as strings so a package upgrade
/// cannot silently change what is already in Valkey.
/// </summary>
internal sealed record StoredUserToken
{
    public required string AccessToken { get; init; }
    public required DateTimeOffset Expiration { get; init; }
    public required string ClientId { get; init; }
    public string? AccessTokenType { get; init; }
    public string? DPoPJsonWebKey { get; init; }
    public string? Scope { get; init; }
    public string? RefreshToken { get; init; }
    public string? IdentityToken { get; init; }
}

[JsonSourceGenerationOptions(DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(StoredUserToken))]
internal partial class TokenStoreJsonContext : JsonSerializerContext;