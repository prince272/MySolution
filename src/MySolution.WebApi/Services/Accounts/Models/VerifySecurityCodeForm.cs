using FluentValidation;
using Humanizer;
using MySolution.WebApi.Helpers;
using MySolution.WebApi.Libraries.Globalizer;
using MySolution.WebApi.Libraries.Validator;
using MySolution.WebApi.Services.Accounts.Entities;
using MySolution.WebApi.Services.Accounts.Repositories;

namespace MySolution.WebApi.Services.Accounts.Models
{
    public class VerifySecurityCodeForm : SendSecurityCodeForm
    {
        public string Code { get; set; } = null!;
        public string? NewPassword { get; set; } = null!;
        public string? ConfirmPassword { get; set; } = null!;
    }

    public class VerifySecurityCodeFormValidator : SendSecurityCodeFormValidator<VerifySecurityCodeForm>
    {
        public VerifySecurityCodeFormValidator(IGlobalizer globalizer, IUserRepository userRepository) : base(globalizer, userRepository)
        {
            var currentRegionCode = globalizer.Region.TwoLetterISORegionName.ToUpperInvariant();

            RuleFor(_ => _.NewPassword)
                .NotEmpty()
                .MaximumLength(128)
                .Password()
                .When(x => x.Reason == SecurityReason.ResetPassword, ApplyConditionTo.AllValidators);

            RuleFor(_ => _.ConfirmPassword)
                .NotEmpty()
                .MaximumLength(128)
                .Equal(_ => _.NewPassword, StringComparer.Ordinal)
                .When(x => x.Reason == SecurityReason.ResetPassword, ApplyConditionTo.AllValidators);

            RuleFor(_ => _.Code)
                .NotEmpty()
                .Matches(@"^\d{6}$").WithMessage("'{PropertyName}' must be a 6-digit number.");
        }
    }
}
