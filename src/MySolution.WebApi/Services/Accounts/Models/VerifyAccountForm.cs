using FluentValidation;
using MySolution.WebApi.Libraries.Globalizer;
using MySolution.WebApi.Libraries.Validator;

namespace MySolution.WebApi.Services.Accounts.Models
{
    public record VerifyAccountForm
    {
        public string CurrentUsername { get; set; } = null!;
        
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
