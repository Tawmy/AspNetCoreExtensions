using AspNetCoreExtensions.Keycloak.Internal.Db.Models;
using Microsoft.EntityFrameworkCore;

namespace AspNetCoreExtensions.Keycloak.Internal.Db;

internal class DatabaseContext : DataProtectionKeyContext
{
    public DatabaseContext(DbContextOptions<DatabaseContext> options) : base(options)
    {
    }

    /// <summary>
    ///     Empty constructor for EF core command line tools.
    /// </summary>
    public DatabaseContext()
    {
    }

    public DbSet<UserSession> UserSessions => Set<UserSession>();
    public DbSet<UserToken> UserTokens => Set<UserToken>();
}