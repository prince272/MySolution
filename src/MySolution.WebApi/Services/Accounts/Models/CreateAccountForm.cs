using FluentValidation;
using MySolution.WebApi.Helpers;
using MySolution.WebApi.Libraries.Globalizer;
using MySolution.WebApi.Libraries.Validator;

namespace MySolution.WebApi.Services.Accounts.Models
{
    /// <summary>
    /// Form for creating a new user account.
    /// </summary>
    public record CreateAccountForm
    {
        /// <summary>
        /// First name of the user. Must be provided and cannot exceed 128 characters.
        /// </summary>
        public string FirstName { get; set; } = null!;
        
        /// <summary>
        /// Last name of the user. Optional and cannot exceed 128 characters.
        /// </summary>
        public string? LastName { get; set; }
        
        /// <summary>
        /// Unique username for the account. Must be provided and cannot exceed 128 characters.
        /// </summary>
        public string Username { get; set; } = null!;
        
        /// <summary>
        /// Password for the account. Must be provided and cannot exceed 128 characters.
        /// </summary>
        public string Password { get; set; } = null!;
        
        /// <summary>
        /// Confirmation of the password. Must match the password exactly and cannot exceed 128 characters.
        /// </summary>
        public string ConfirmPassword { get; set; } = null!;
    }

    public class CreateAccountFormValidator : AbstractValidator<CreateAccountForm>
    {
        public CreateAccountFormValidator(IGlobalizer globalizer)
        {
            var currentRegionCode = globalizer.Region.TwoLetterISORegionName.ToUpperInvariant();

            RuleFor(_ => _.FirstName).NotEmpty().MaximumLength(128);
            RuleFor(_ => _.LastName).MaximumLength(128);

            RuleFor(x => x.Username).NotEmpty().MaximumLength(128).Username(currentRegionCode);

            RuleFor(_ => _.Password).NotEmpty().MaximumLength(128).Password();
            RuleFor(_ => _.ConfirmPassword).NotEmpty().MaximumLength(128).Equal(_ => _.Password, StringComparer.Ordinal);
        }
    }
}