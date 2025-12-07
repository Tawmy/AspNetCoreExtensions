using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AspNetCoreExtensions.Keycloak.Db.Models;

public class UserSession
{
    public required Guid Sid { get; set; }
    public required string Principal { get; set; }
    public required string? Properties { get; set; }
    public required string AuthenticationScheme { get; set; }
}

public class UserSessionConfiguration : IEntityTypeConfiguration<UserSession>
{
    public void Configure(EntityTypeBuilder<UserSession> builder)
    {
        builder.HasKey(x => x.Sid);
        builder.Property(x => x.Sid).ValueGeneratedNever();

        builder.Property(x => x.Principal).HasMaxLength(4096);
        builder.Property(x => x.Properties).HasMaxLength(20000);
        builder.Property(x => x.AuthenticationScheme).HasMaxLength(255);
    }
}