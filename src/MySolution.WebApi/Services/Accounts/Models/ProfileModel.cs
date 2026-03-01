using MySolution.WebApi.Services.Accounts.Entities;

namespace MySolution.WebApi.Services.Accounts.Models
{
    /// <summary>
    /// User profile details returned after authentication or profile retrieval.
    /// </summary>
    public class ProfileModel
    {
        // Identity
        /// <summary>
        /// Unique identifier for the user account.
        /// </summary>
        public string Id { get; set; } = null!;
        
        /// <summary>
        /// Username of the account.
        /// </summary>
        public string UserName { get; set; } = null!;
        
        /// <summary>
        /// Email address associated with the account.
        /// </summary>
        public string? Email { get; set; }
        
        /// <summary>
        /// Indicates whether the email address has been verified.
        /// </summary>
        public bool EmailVerified { get; set; }
        
        /// <summary>
        /// Phone number associated with the account.
        /// </summary>
        public string? PhoneNumber { get; set; }
        
        /// <summary>
        /// Indicates whether the phone number has been verified.
        /// </summary>
        public bool PhoneNumberVerified { get; set; }

        // Personal Info
        /// <summary>
        /// First name of the user.
        /// </summary>
        public string FirstName { get; set; } = null!;
        
        /// <summary>
        /// Last name of the user.
        /// </summary>
        public string? LastName { get; set; }
        
        /// <summary>
        /// Full name of the user.
        /// </summary>
        public string? FullName { get; set; }
        
        /// <summary>
        /// Biographical information about the user.
        /// </summary>
        public string? Bio { get; set; }
        
        /// <summary>
        /// Date of birth of the user.
        /// </summary>
        public DateOnly? DateOfBirth { get; set; }
        
        /// <summary>
        /// Gender of the user.
        /// </summary>
        public Gender? Gender { get; set; }
        
        /// <summary>
        /// Country of residence.
        /// </summary>
        public string? Country { get; set; }
        
        /// <summary>
        /// Locale preference for the user.
        /// </summary>
        public string? Locale { get; set; }
    }
}
