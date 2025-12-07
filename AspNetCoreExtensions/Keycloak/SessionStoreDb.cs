using System.Globalization;
using AspNetCoreExtensions.Keycloak.Db;
using AspNetCoreExtensions.Keycloak.Db.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;

namespace AspNetCoreExtensions.Keycloak;

/// <summary>
///     Simple session store implementation that persists sessions in a database.
/// </summary>
public class SessionStoreDb(DatabaseOptions options) : ITicketStore
{
    private readonly PooledDbContextFactory<DatabaseContext> _dbContextFactory =
        new(new DbContextOptionsBuilder<DatabaseContext>().UseNpgsql(options.ConnectionString)
            .UseSnakeCaseNamingConvention().Options);

    private readonly SessionStoreMemory _sessionStoreMemory = new();

    public async Task<string> StoreAsync(AuthenticationTicket ticket)
    {
        var sid = ticket.Principal.FindFirst("sid")?.Value ?? throw new InvalidOperationException("no sid claim");
        await using var context = await _dbContextFactory.CreateDbContextAsync();

        await context.UserSessions.AddAsync(new UserSession
        {
            Sid = Guid.Parse(sid, CultureInfo.InvariantCulture),
            Principal = ticket.Principal,
            Properties = ticket.Properties,
            AuthenticationScheme = ticket.AuthenticationScheme
        });

        try
        {
            await context.SaveChangesAsync();
        }
        catch (Exception e)
        {
            throw new DbUpdateException($"Failed to save session {sid} to the database.", e);
        }

        await _sessionStoreMemory.StoreAsync(ticket);

        return sid;
    }

    public async Task RenewAsync(string key, AuthenticationTicket ticket)
    {
        await using var context = await _dbContextFactory.CreateDbContextAsync();
        var sid = Guid.Parse(key, CultureInfo.InvariantCulture);

        var session = await context.UserSessions.FirstOrDefaultAsync(x => x.Sid == sid);

        if (session is null)
        {
            throw new InvalidOperationException("Session not found, renewal failed.");
        }

        session.Principal = ticket.Principal;
        session.Properties = ticket.Properties;
        session.AuthenticationScheme = ticket.AuthenticationScheme;

        try
        {
            await context.SaveChangesAsync();
            await _sessionStoreMemory.RenewAsync(key, ticket);
        }
        catch (Exception e)
        {
            await _sessionStoreMemory.RemoveAsync(key); // remove from memory since db renewal failed
            throw new DbUpdateException($"Failed to renew user session {key}.", e);
        }
    }

    public async Task<AuthenticationTicket?> RetrieveAsync(string key)
    {
        await using var context = await _dbContextFactory.CreateDbContextAsync();
        var sid = Guid.Parse(key, CultureInfo.InvariantCulture);

        var ticketMemory = await _sessionStoreMemory.RetrieveAsync(key);

        if (ticketMemory is not null)
        {
            // try to return from memory before querying db
            return ticketMemory;
        }

        var session = await context.UserSessions.FirstOrDefaultAsync(x => x.Sid == sid);

        return session is not null
            ? new AuthenticationTicket(session.Principal, session.Properties, session.AuthenticationScheme)
            : null;
    }

    public async Task RemoveAsync(string key)
    {
        await using var context = await _dbContextFactory.CreateDbContextAsync();
        var sid = Guid.Parse(key, CultureInfo.InvariantCulture);

        var session = await context.UserSessions.FirstOrDefaultAsync(x => x.Sid == sid);

        if (session is null)
        {
            return;
        }

        context.UserSessions.Remove(session);

        try
        {
            await context.SaveChangesAsync();
        }
        catch (Exception e)
        {
            throw new DbUpdateException($"Failed to remove session {sid} from database.", e);
        }
        finally
        {
            await _sessionStoreMemory.RemoveAsync(key);
        }
    }
}