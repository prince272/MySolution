namespace MySolution.WebApi.Services.Accounts.Entities
{
    public class User
    {
        // Identity
        public Guid Id { get; set; }
        public string UserName { get; set; } = null!;
        public string? Email { get; set; }
        public bool EmailVerified { get; set; }
        public string? PhoneNumber { get; set; }
        public bool PhoneNumberVerified { get; set; }

        // Personal Info
        public string FirstName { get; set; } = null!;
        public string? LastName { get; set; }
        public string? FullName => string.IsNullOrWhiteSpace(LastName) ? FirstName : $"{FirstName} {LastName}".Trim();
        public string? Bio { get; set; }
        public DateOnly? DateOfBirth { get; set; }
        public Gender? Gender { get; set; }
        public string? PictureUrl { get; set; }
        public string? Country { get; set; }
        public string? Locale { get; set; }

        // Security
        public string? PasswordHash { get; set; }
        public bool HasPassword { get; set; }
        public DateTimeOffset? PasswordChangedAt { get; set; }
        public ICollection<Role> Roles { get; set; } = [];

        // Audit
        public DateTimeOffset CreatedAt { get; set; }
        public DateTimeOffset? UpdatedAt { get; set; }
        public DateTimeOffset? DeletedAt { get; set; }
        public DateTimeOffset LastActiveAt { get; set; }
    }

    public enum Gender
    {
        Male,
        Female,
        Other,
        PreferNotToSay
    }
}