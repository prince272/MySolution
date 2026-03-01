using FluentValidation;
using MySolution.WebApi.Libraries.Globalizer;
using MySolution.WebApi.Libraries.Validator;

namespace MySolution.WebApi.Services.Accounts.Models
{
    /// <summary>
    /// Form for changing a user's account username with verification code.
    /// </summary>
    public record ChangeAccountForm
    {
        /// <summary>
        /// Current username of the account requesting the change. Must be provided and cannot exceed 128 characters.
        /// </summary>
        public string CurrentUsername { get; set; } = null!;
        
        /// <summary>
        /// New username to set for the account. Must be provided, cannot exceed 128 characters, and must differ from current username.
        /// </summary>
        public string NewUsername { get; set; } = null!;
        
        /// <summary>
        /// 6-digit verification code sent to the user for identity verification. Must be exactly 6 digits.
        /// </summary>
        public string Code { get; set; } = null!;
    }

    public class ChangeAccountFormValidator : AbstractValidator<ChangeAccountForm>
    {
        public ChangeAccountFormValidator(IGlobalizer globalizer)
        {
            var currentRegionCode = globalizer.Region.TwoLetterISORegionName.ToUpperInvariant();

            RuleFor(_ => _.CurrentUsername).NotEmpty().MaximumLength(128).Username(currentRegionCode);

            RuleFor(_ => _.NewUsername).NotEmpty().MaximumLength(128).Username(currentRegionCode).NotEqual(_ => _.CurrentUsername, StringComparer.OrdinalIgnoreCase);

            RuleFor(_ => _.Code).NotEmpty().Length(6).Matches(@"^\d{6}$").WithMessage("'Code' must be a 6-digit number.");
        }
    }
}