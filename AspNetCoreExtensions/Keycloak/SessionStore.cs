using System.Collections.Concurrent;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace AspNetCoreExtensions.Keycloak;

/// <summary>
///     Simple session store implementation.
/// </summary>
internal class SessionStore : ITicketStore
{
    private readonly ConcurrentDictionary<string, AuthenticationTicket> _authTickets = [];

    public Task<string> StoreAsync(AuthenticationTicket ticket)
    {
        var key = ticket.Principal.FindFirst("sid")?.Value ?? throw new InvalidOperationException("no sid claim");
        var result = _authTickets.TryAdd(key, ticket);

        return result
            ? Task.FromResult(key)
            : throw new Exception("Failed to add entry to the session store.");
    }

    public Task RenewAsync(string key, AuthenticationTicket ticket)
    {
        if (!_authTickets.ContainsKey(key))
        {
            throw new InvalidOperationException("Session not found, renewal failed.");
        }

        _authTickets[key] = ticket;

        return Task.CompletedTask;
    }

    public Task<AuthenticationTicket?> RetrieveAsync(string key)
    {
        return Task.FromResult(_authTickets.GetValueOrDefault(key));
    }

    public Task RemoveAsync(string key)
    {
        _authTickets.TryRemove(key, out _); // if session does not exist, ignore
        return Task.CompletedTask;
    }
}