using FluentValidation;

namespace MySolution.WebApi.Services.Accounts.Models
{
    public class SignInWithRefreshTokenForm
    {
        public string RefreshToken { get; set; } = null!;
    }

    public class SignInWithRefreshTokenFormValidator : AbstractValidator<SignInWithRefreshTokenForm>
    {
        public SignInWithRefreshTokenFormValidator()
        {
            RuleFor(x => x.RefreshToken).NotEmpty();
        }
    }
}
