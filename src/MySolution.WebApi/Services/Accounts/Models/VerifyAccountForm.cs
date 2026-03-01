using FluentValidation;
using MySolution.WebApi.Libraries.Globalizer;
using MySolution.WebApi.Libraries.Validator;

namespace MySolution.WebApi.Services.Accounts.Models
{
    /// <summary>
    /// Form for verifying a user account with a verification code.
    /// </summary>
    public record VerifyAccountForm
    {
        /// <summary>
        /// Username of the account to verify. Must be provided and cannot exceed 128 characters.
        /// </summary>
        public string CurrentUsername { get; set; } = null!;
        
        /// <summary>
        /// 6-digit verification code sent to the user for account verification. Must be exactly 6 digits.
        /// </summary>
        public string Code { get; set; } = null!;
    }

    public class VerifyAccountFormValidator : AbstractValidator<VerifyAccountForm>
    {
        public VerifyAccountFormValidator(IGlobalizer globalizer)
        {
            var currentRegionCode = globalizer.Region.TwoLetterISORegionName.ToUpperInvariant();

            RuleFor(_ => _.CurrentUsername).NotEmpty().MaximumLength(128).Username(currentRegionCode);
            RuleFor(_ => _.Code).NotEmpty().Length(6).Matches(@"^\d{6}$").WithMessage("'Code' must be a 6-digit number.");
        }
    }
}
