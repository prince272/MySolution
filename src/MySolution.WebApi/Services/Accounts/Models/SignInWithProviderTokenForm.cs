using FluentValidation;
using MySolution.WebApi.Libraries.JwtTokenProvider;
using MySolution.WebApi.Services.Accounts.Repositories;

namespace MySolution.WebApi.Services.Accounts.Models
{
    public class SignInWithProviderTokenForm
    {
        public string Token { get; set; } = null!;
    }

    public class SignInWithProviderTokenFormValidator : AbstractValidator<SignInWithProviderTokenForm>
    {
        public SignInWithProviderTokenFormValidator()
        {
            RuleFor(_ => _.Token)
                .NotEmpty();
        }
    }
}
