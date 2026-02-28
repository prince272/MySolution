using FluentValidation;
using MySolution.WebApi.Libraries.Globalizer;
using MySolution.WebApi.Libraries.Validator;

namespace MySolution.WebApi.Services.Accounts.Models
{
    public record ChangeAccountForm
    {
        public string CurrentUsername { get; set; } = null!;
        public string NewUsername { get; set; } = null!;
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