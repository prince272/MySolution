using FluentValidation;
using System.Diagnostics.CodeAnalysis;

namespace MySolution.WebApi.Services.Accounts.Models
{
    public class SignOutForm
    {
        public string? RefreshToken { get; set; }

        [MemberNotNullWhen(false, nameof(RefreshToken))]
        public bool RevokeAllTokens { get; set; }
    }

    public class SignOutFormValidator : AbstractValidator<SignOutForm>
    {
        public SignOutFormValidator()
        {
            RuleFor(_ => _.RefreshToken).NotEmpty().When(_ => !_.RevokeAllTokens);
        }
    }
}