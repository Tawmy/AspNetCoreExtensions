using System.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace AspNetCoreExtensions;

public static class EfCoreExtensions
{
    extension(IServiceProvider serviceProvider)
    {
        public async Task MigrateDatabaseAsync<T>(CancellationToken cancellationToken = default) where T : DbContext
        {
            using var scope = serviceProvider.CreateScope();

            var dbContext = scope.ServiceProvider.GetRequiredService<T>();

            await dbContext.Database.MigrateAsync(cancellationToken);

            // Reload Npgsql types
            // https://github.com/npgsql/efcore.pg/issues/292#issuecomment-1829713529
            if (dbContext.Database.GetDbConnection() is NpgsqlConnection npgsqlConnection)
            {
                if (npgsqlConnection.State != ConnectionState.Open)
                {
                    await npgsqlConnection.OpenAsync(cancellationToken);
                }

                try
                {
                    await npgsqlConnection.ReloadTypesAsync(cancellationToken);
                }
                finally
                {
                    await npgsqlConnection.CloseAsync();
                }
            }
        }
    }
}