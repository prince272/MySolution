using MySolution.WebApi.Libraries.JwtToken;
using MySolution.WebApi.Services.Identity.Entities;

namespace MySolution.WebApi.Services.Identity.Models
{
    public class AccountModel : JwtRawToken
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
        public string? FullName { get; set; }
        public string? Bio { get; set; }
        public DateOnly? DateOfBirth { get; set; }
        public Gender? Gender { get; set; }
        public string? Country { get; set; }
        public string? Locale { get; set; }
    }
}
