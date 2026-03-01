using FluentValidation;
using MySolution.WebApi.Libraries.Globalizer;
using MySolution.WebApi.Libraries.Validator;

namespace MySolution.WebApi.Services.Accounts.Models
{
    /// <summary>
    /// Form for resetting a user's password with verification code.
    /// </summary>
    public record ResetPasswordForm
    {
        /// <summary>
        /// Current username of the account requesting password reset. Must be provided and cannot exceed 128 characters.
        /// </summary>
        public string CurrentUsername { get; set; } = null!;
        
        /// <summary>
        /// 6-digit verification code sent to the user for identity verification. Must be exactly 6 digits.
        /// </summary>
        public string Code { get; set; } = null!;
        
        /// <summary>
        /// New password to set for the account. Must be provided and cannot exceed 128 characters.
        /// </summary>
        public string NewPassword { get; set; } = null!;
        
        /// <summary>
        /// Confirmation of the new password. Must match the new password exactly and cannot exceed 128 characters.
        /// </summary>
        public string ConfirmPassword { get; set; } = null!;
    }

    public class ResetPasswordFormValidator : AbstractValidator<ResetPasswordForm>
    {
        public ResetPasswordFormValidator(IGlobalizer globalizer)
        {
            var currentRegionCode = globalizer.Region.TwoLetterISORegionName.ToUpperInvariant();

            RuleFor(_ => _.CurrentUsername).NotEmpty().MaximumLength(128).Username(currentRegionCode);
            RuleFor(_ => _.Code).NotEmpty().Length(6).Matches(@"^\d{6}$").WithMessage("'Code' must be a 6-digit number.");
            RuleFor(_ => _.NewPassword).NotEmpty().MaximumLength(128).Password();
            RuleFor(_ => _.ConfirmPassword).NotEmpty().MaximumLength(128).Equal(_ => _.NewPassword, StringComparer.Ordinal);
        }
    }
}
