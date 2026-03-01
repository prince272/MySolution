using FluentValidation;
using MySolution.WebApi.Libraries.Validator;

namespace MySolution.WebApi.Services.Accounts.Models
{
    /// <summary>
    /// Form for changing a user's password when already authenticated.
    /// </summary>
    public class ChangePasswordForm
    {
        /// <summary>
        /// Current password of the authenticated user. Must be provided and cannot exceed 128 characters.
        /// </summary>
        public string CurrentPassword { get; set; } = null!;
        
        /// <summary>
        /// New password to set for the account. Must be provided, cannot exceed 128 characters, and must differ from current password.
        /// </summary>
        public string NewPassword { get; set; } = null!;
        
        /// <summary>
        /// Confirmation of the new password. Must match the new password exactly and cannot exceed 128 characters.
        /// </summary>
        public string ConfirmPassword { get; set; } = null!;
    }

    public class ChangePasswordFormValidator : AbstractValidator<ChangePasswordForm>
    {
        public ChangePasswordFormValidator()
        {
            RuleFor(_ => _.CurrentPassword).NotEmpty().MaximumLength(128);

            RuleFor(_ => _.NewPassword).NotEmpty().MaximumLength(128).Password().NotEqual(_ => _.CurrentPassword, StringComparer.Ordinal);
            RuleFor(_ => _.ConfirmPassword).NotEmpty().MaximumLength(128).Equal(_ => _.NewPassword, StringComparer.Ordinal);
        }
    }
}
