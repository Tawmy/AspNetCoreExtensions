using Duende.AccessTokenManagement;
using Duende.AccessTokenManagement.DPoP;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AspNetCoreExtensions.OpenIdConnect.Keycloak.Db.Models;

internal class UserToken
{
    public required Guid Sub { get; set; }
    public required AccessToken AccessToken { get; set; }
    public required DPoPProofKey? DPoPJsonWebKey { get; set; }
    public required DateTimeOffset Expiration { get; set; }
    public required Scope? Scope { get; set; }
    public required ClientId ClientId { get; set; }
    public required AccessTokenType? AccessTokenType { get; set; }
    public required RefreshToken? RefreshToken { get; set; }
    public required IdentityToken? IdentityToken { get; set; }
}

internal class UserTokenConfiguration : IEntityTypeConfiguration<UserToken>
{
    public void Configure(EntityTypeBuilder<UserToken> builder)
    {
        builder.HasKey(x => x.Sub);
        builder.Property(x => x.Sub).ValueGeneratedNever();

        builder.Property(x => x.AccessToken)
            .HasMaxLength(1 << 15)
            .HasConversion(x => x.ToString(), x => AccessToken.Parse(x));

        builder.Property(x => x.DPoPJsonWebKey)
            .HasMaxLength(1 << 15)
            .HasConversion(x => x != null ? x.ToString() : null,
                x => x != null ? DPoPProofKey.Parse(x) : null);

        builder.Property(x => x.Scope)
            .HasMaxLength(255)
            .HasConversion(x => x != null ? x.ToString() : null,
                x => x != null ? Scope.Parse(x) : null);

        builder.Property(x => x.ClientId)
            .HasMaxLength(255)
            .HasConversion(x => x.ToString(), x => ClientId.Parse(x));

        builder.Property(x => x.AccessTokenType)
            .HasMaxLength(255)
            .HasConversion(x => x != null ? x.ToString() : null,
                x => x != null ? AccessTokenType.Parse(x) : null);

        builder.Property(x => x.RefreshToken)
            .HasMaxLength(1 << 15)
            .HasConversion(x => x != null ? x.ToString() : null,
                x => x != null ? RefreshToken.Parse(x) : null);

        builder.Property(x => x.IdentityToken)
            .HasMaxLength(1 << 15)
            .HasConversion(x => x != null ? x.ToString() : null,
                x => x != null ? IdentityToken.Parse(x) : null);
    }
}