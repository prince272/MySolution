using Humanizer;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace MySolution.WebApi.Libraries.JwtTokenProvider
{
    public class JwtSecurityStampConfiguration : IEntityTypeConfiguration<JwtSecurityStamp>
    {
        public void Configure(EntityTypeBuilder<JwtSecurityStamp> builder)
        {
            builder.ToTable(typeof(JwtSecurityStamp).Name.Pluralize());
            builder.HasKey(x => x.Subject);
        }
    }
}
