// Copyright (c) Duende Software. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.Concurrent;
using System.Security.Claims;
using Duende.AccessTokenManagement;
using Duende.AccessTokenManagement.OpenIdConnect;

namespace AspNetCoreExtensions.Keycloak;

/// <summary>
///     Simplified implementation of a server-side token store.
///     Probably want something more robust IRL
/// </summary>
internal class ServerSideTokenStore : IUserTokenStore
{
    private static readonly ConcurrentDictionary<string, TokenForParameters> Tokens = new();

    public Task<TokenResult<TokenForParameters>> GetTokenAsync(ClaimsPrincipal user,
        UserTokenRequestParameters? parameters = null,
        CancellationToken cancellationToken = default)
    {
        var sub = user.FindFirst("sub")?.Value ?? throw new InvalidOperationException("no sub claim");

        if (Tokens.TryGetValue(sub, out var value))
        {
            return Task.FromResult(TokenResult.Success(value));
        }

        return Task.FromResult((TokenResult<TokenForParameters>)TokenResult.Failure("not found"));
    }

    public Task StoreTokenAsync(ClaimsPrincipal user, UserToken token, UserTokenRequestParameters? parameters = null,
        CancellationToken ct = default)
    {
        var sub = user.FindFirst("sub")?.Value ?? throw new InvalidOperationException("no sub claim");
        Tokens[sub] = new TokenForParameters(token,
            token.RefreshToken == null
                ? null
                : new UserRefreshToken(token.RefreshToken.Value, token.DPoPJsonWebKey));

        return Task.CompletedTask;
    }

    public Task ClearTokenAsync(ClaimsPrincipal user, UserTokenRequestParameters? parameters = null,
        CancellationToken ct = default)
    {
        var sub = user.FindFirst("sub")?.Value ?? throw new InvalidOperationException("no sub claim");

        Tokens.TryRemove(sub, out _);
        return Task.CompletedTask;
    }
}