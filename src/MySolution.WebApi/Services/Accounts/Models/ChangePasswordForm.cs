using FluentValidation;
using MySolution.WebApi.Libraries.Validator;

namespace MySolution.WebApi.Services.Accounts.Models
{
    public class ChangePasswordForm
    {
        public string CurrentPassword { get; set; } = null!;
        public string NewPassword { get; set; } = null!;
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
