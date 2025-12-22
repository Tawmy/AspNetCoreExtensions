using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AspNetCoreExtensions.OpenIdConnect.Keycloak.Db.Models;

internal class UserSession
{
    public required Guid Sid { get; set; }
    public required ClaimsPrincipal Principal { get; set; }
    public required AuthenticationProperties? Properties { get; set; }
    public required string AuthenticationScheme { get; set; }
}

internal class UserSessionConfiguration : IEntityTypeConfiguration<UserSession>
{
    public void Configure(EntityTypeBuilder<UserSession> builder)
    {
        builder.HasKey(x => x.Sid);
        builder.Property(x => x.Sid).ValueGeneratedNever();

        builder.Property(x => x.Principal)
            .HasMaxLength(4096)
            .HasConversion(x => PrincipalToDb(x), x => PrincipalFromDb(x));

        builder.Property(x => x.Properties)
            .HasMaxLength(20000)
            .HasConversion(x => PropertiesToDb(x), x => PropertiesFromDb(x));

        builder.Property(x => x.AuthenticationScheme).HasMaxLength(255);
    }

    private static string PrincipalToDb(ClaimsPrincipal claimsPrincipal)
    {
        using MemoryStream memoryStream = new();
        using var writer = new BinaryWriter(memoryStream);
        claimsPrincipal.WriteTo(writer);
        return Convert.ToBase64String(memoryStream.ToArray());
    }

    private static ClaimsPrincipal PrincipalFromDb(string claimsPrincipal)
    {
        var bytes = Convert.FromBase64String(claimsPrincipal);
        using MemoryStream memoryStream = new(bytes);
        using var reader = new BinaryReader(memoryStream);
        return new ClaimsPrincipal(reader);
    }

    private static string? PropertiesToDb(AuthenticationProperties? properties)
    {
        return properties is not null
            ? Convert.ToBase64String(PropertiesSerializer.Default.Serialize(properties))
            : null;
    }

    private static AuthenticationProperties? PropertiesFromDb(string? properties)
    {
        return properties is not null
            ? PropertiesSerializer.Default.Deserialize(Convert.FromBase64String(properties))
            : null;
    }
}