using Humanizer;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using System.Reflection.Emit;

namespace MySolution.WebApi.Libraries.JwtToken
{
    public class JwtTokenConfiguration : IEntityTypeConfiguration<JwtToken>
    {
        public void Configure(EntityTypeBuilder<JwtToken> builder)
        {
            builder.ToTable(typeof(JwtToken).Name.Pluralize());
            builder.HasIndex(e => e.Subject);
            builder.HasIndex(e => e.AccessTokenHash);
            builder.HasIndex(e => e.RefreshTokenHash);
            builder.HasIndex(e => e.AccessTokenExpiresAt);
            builder.HasIndex(e => e.RefreshTokenExpiresAt);
        }
    }
}
