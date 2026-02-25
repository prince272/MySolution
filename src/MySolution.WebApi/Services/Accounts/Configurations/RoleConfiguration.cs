using Humanizer;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using MySolution.WebApi.Services.Accounts.Entities;

namespace MySolution.WebApi.Services.Accounts.Configurations
{
    public class RoleConfiguration : IEntityTypeConfiguration<Role>
    {
        public void Configure(EntityTypeBuilder<Role> builder)
        {
            builder.ToTable(typeof(Role).Name.Pluralize());

            builder.HasIndex(r => r.Name).IsUnique();
        }
    }
}
