using FluentValidation;
using Humanizer;
using MySolution.WebApi.Helpers;
using MySolution.WebApi.Libraries.Globalizer;
using MySolution.WebApi.Libraries.Validator;
using MySolution.WebApi.Services.Accounts.Repositories;

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
        public CreateAccountFormValidator(IGlobalizer globalizer, IUserRepository userRepository)
        {
            var currentRegionCode = globalizer.Region.TwoLetterISORegionName.ToUpperInvariant();

            RuleFor(_ => _.FirstName).NotEmpty().MaximumLength(128);
            RuleFor(_ => _.LastName).MaximumLength(128);

            RuleFor(_ => _.Username)
                .NotEmpty()
                .MaximumLength(128)
                .Username(currentRegionCode)
                .CustomAsync(async (username, context, cancellationToken) =>
                {
                    var exists = await userRepository.ExistsByEmailOrPhoneAsync(username, cancellationToken);
                    if (exists)
                        context.AddFailure(context.PropertyPath, $"'{StringParser.ParseContactType(username).Humanize()}' already exists.");
                });

            RuleFor(_ => _.Password).NotEmpty().MaximumLength(128).Password();
            RuleFor(_ => _.ConfirmPassword).NotEmpty().MaximumLength(128).Equal(_ => _.Password, StringComparer.Ordinal);
        }
    }
}