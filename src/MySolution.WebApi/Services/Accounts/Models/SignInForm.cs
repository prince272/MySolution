using FluentValidation;
using MySolution.WebApi.Helpers;
using MySolution.WebApi.Libraries.Globalizer;
using MySolution.WebApi.Libraries.Validator;

namespace MySolution.WebApi.Services.Accounts.Models
{
    /// <summary>
    /// Form for user authentication with username and password.
    /// </summary>
    public record SignInForm
    {
        /// <summary>
        /// Username of the account attempting to sign in. Must be provided and cannot exceed 128 characters.
        /// </summary>
        public string Username { get; set; } = null!;
        
        /// <summary>
        /// Password for the account. Must be provided and cannot exceed 128 characters.
        /// </summary>
        public string Password { get; set; } = null!;
    }

    public class SignInFormValidator : AbstractValidator<SignInForm>
    {
        public SignInFormValidator(IGlobalizer globalizer)
        {
            var currentRegionCode = globalizer.Region.TwoLetterISORegionName.ToUpperInvariant();

            RuleFor(_ => _.Username).NotEmpty().MaximumLength(128).Username(currentRegionCode);

            RuleFor(x => x.Password).NotEmpty().MaximumLength(128);
        }
    }
}