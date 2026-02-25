using FluentValidation;
using MySolution.WebApi.Helpers;
using MySolution.WebApi.Libraries.Globalizer;

namespace MySolution.WebApi.Services.Accounts.Models
{
    public record SignInForm
    {
        public string Username { get; set; } = null!;
        public string Password { get; set; } = null!;
    }

    public class SignInFormValidator : AbstractValidator<SignInForm>
    {
        public SignInFormValidator(IGlobalizer globalizer)
        {
            var currentRegionCode = globalizer.Region.TwoLetterISORegionName.ToUpperInvariant();

            RuleFor(x => x.Username)
                .NotEmpty()
                .MaximumLength(128)
                .Custom((username, context) =>
                {
                    if (string.IsNullOrWhiteSpace(username)) return;

                    var type = ContactHelper.DetectContactType(username);

                    var isValid = type switch
                    {
                        ContactType.Email =>
                            ContactHelper.TryParseEmail(username, out _),

                        ContactType.PhoneNumber =>
                            ContactHelper.TryParsePhoneNumber(username, currentRegionCode, out _),

                        _ => false
                    };

                    if (!isValid)
                    {
                        context.AddFailure(
                            type?.ToString() ?? "Username",
                            $"'{type switch
                            {
                                ContactType.Email => "Email",
                                ContactType.PhoneNumber => "Phone number",
                                _ => "Username"
                            }}' is not valid.");
                    }
                });

            RuleFor(x => x.Password)
                .NotEmpty()
                .MaximumLength(128);
        }
    }
}