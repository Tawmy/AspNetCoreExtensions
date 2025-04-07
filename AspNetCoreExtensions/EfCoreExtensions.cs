using System.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace AspNetCoreExtensions;

public static class EfCoreExtensions
{
    public static async Task MigrateDatabaseAsync<T>(this IServiceProvider serviceProvider) where T : DbContext
    {
        using var scope = serviceProvider.CreateScope();

        var dbContext = scope.ServiceProvider.GetRequiredService<T>();

        await dbContext.Database.MigrateAsync();

        // Reload Npgsql types
        // https://github.com/npgsql/efcore.pg/issues/292#issuecomment-1829713529
        if (dbContext.Database.GetDbConnection() is NpgsqlConnection npgsqlConnection)
        {
            if (npgsqlConnection.State != ConnectionState.Open)
            {
                await npgsqlConnection.OpenAsync();
            }

            try
            {
                await npgsqlConnection.ReloadTypesAsync();
            }
            finally
            {
                await npgsqlConnection.CloseAsync();
            }
        }
    }
}