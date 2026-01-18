using AspNetCoreExtensions.Keycloak.Options;
using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AspNetCoreExtensions.Keycloak.Internal.Db;

public class DataProtectionKeyContext : DbContext, IDataProtectionKeyContext
{
    internal DataProtectionKeyContext(DbContextOptions<DatabaseContext> options) : base(options)
    {
    }

    internal DataProtectionKeyContext()
    {
    }

    #region DbSets

    // ASP.NET Core data protection keys, otherwise we lose encryption keys after every restart.
    public DbSet<DataProtectionKey> DataProtectionKeys => Set<DataProtectionKey>();

    #endregion

    /// <summary>
    ///     Context is usually configured in <see cref="OpenIdConnectExtensions" />,
    ///     EF command line tools need this override./>
    /// </summary>
    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        if (!optionsBuilder.IsConfigured)
        {
            optionsBuilder.ConfigureDbContextOptions(null);
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

internal static class DbContextOptionsExtensions
{
    extension(DbContextOptionsBuilder builder)
    {
        public void ConfigureDbContextOptions(DatabaseOptions? dbOptions)
        {
            builder.UseNpgsql(dbOptions?.ConnectionString).UseSnakeCaseNamingConvention();
        }
    }
}