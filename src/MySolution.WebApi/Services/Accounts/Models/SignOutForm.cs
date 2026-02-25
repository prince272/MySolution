using FluentValidation;

namespace MySolution.WebApi.Services.Accounts.Models
{
    public class SignOutForm
    {
        public string? RefreshToken { get; set; }
        public bool RevokeAllTokens { get; set; }
    }

    public class SignOutFormValidator : AbstractValidator<SignOutForm>
    {
        public SignOutFormValidator()
        {
            RuleFor(x => x.RefreshToken)
                .NotEmpty()
                .When(x => !x.RevokeAllTokens);
        }
    }
}