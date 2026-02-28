using FluentValidation;
using MySolution.WebApi.Helpers;
using MySolution.WebApi.Libraries.Globalizer;
using MySolution.WebApi.Libraries.Validator;

namespace MySolution.WebApi.Services.Accounts.Models
{
    public record CreateAccountForm
    {
        public string FirstName { get; set; } = null!;
        public string? LastName { get; set; }
        public string Username { get; set; } = null!;
        public string Password { get; set; } = null!;
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