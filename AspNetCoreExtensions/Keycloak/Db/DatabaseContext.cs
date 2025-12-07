using AspNetCoreExtensions.Keycloak.Db.Models;
using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AspNetCoreExtensions.Keycloak.Db;

internal class DatabaseContext : DbContext, IDataProtectionKeyContext
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

    // ASP.NET Core data protection keys, otherwise we lose encryption keys after every restart.
    public DbSet<DataProtectionKey> DataProtectionKeys => Set<DataProtectionKey>();

    /// <summary>
    ///     Context is usually configured in <see cref="OpenIdConnectExtensions" />,
    ///     EF command line tools need this override./>
    /// </summary>
    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        if (!optionsBuilder.IsConfigured)
        {
            optionsBuilder.UseNpgsql().UseSnakeCaseNamingConvention();
        }

        base.OnConfiguring(optionsBuilder);
    }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        builder.ApplyConfigurationsFromAssembly(typeof(DatabaseContext).Assembly);

        // always generate identity column, do not allow user values unless explicitly configured
        builder.UseIdentityAlwaysColumns();
    }
}