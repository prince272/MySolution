namespace MySolution.WebApi.Services.Identity.Entities
{
    public class User
    {
        // Identity
        public string Id { get; set; } = null!;
        public string UserName { get; set; } = null!;
        public string? Email { get; set; }
        public bool EmailVerified { get; set; }
        public string? PhoneNumber { get; set; }
        public bool PhoneNumberVerified { get; set; }

        // Personal Info
        public string FirstName { get; set; } = null!;
        public string? LastName { get; set; }
        public string? FullName => string.IsNullOrEmpty(LastName) ? FirstName : $"{FirstName} {LastName}".Trim();
        public string? Bio { get; set; }
        public DateOnly? DateOfBirth { get; set; }
        public Gender? Gender { get; set; }
        public string? Country { get; set; }
        public string? Locale { get; set; }

        // Security
        public string? PasswordHash { get; set; }
        public bool HasPassword { get; set; }
        public string SecurityStamp { get; set; } = null!;
        public ICollection<Role> Roles { get; set; } = [];

        // Audit
        public DateTime CreatedAt { get; set; }
        public DateTime? UpdatedAt { get; set; }
        public DateTime? DeletedAt { get; set; }
    }

    public enum Gender
    {
        Male,
        Female,
        Other,
        PreferNotToSay
    }
}