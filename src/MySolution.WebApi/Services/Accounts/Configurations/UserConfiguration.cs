using Humanizer;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using MySolution.WebApi.Services.Accounts.Entities;

namespace MySolution.WebApi.Services.Accounts.Configurations
{
    public class UserConfiguration : IEntityTypeConfiguration<User>
    {
        public void Configure(EntityTypeBuilder<User> builder)
        {
            builder.ToTable(typeof(User).Name.Pluralize());

            builder.HasIndex(u => u.UserName).IsUnique();
            builder.HasIndex(u => u.Email)
                   .IsUnique();
            //.HasFilter($"[{nameof(User.Email)}] IS NOT NULL");

            builder.HasIndex(u => u.PhoneNumber)
                   .IsUnique();
            //.HasFilter($"[{nameof(User.PhoneNumber)}] IS NOT NULL");

            builder.HasQueryFilter(u => u.DeletedAt == null);
        }
    }
}
