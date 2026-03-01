using FluentValidation;
using System.Diagnostics.CodeAnalysis;

namespace MySolution.WebApi.Services.Accounts.Models
{
    /// <summary>
    /// Form for signing out a user session with optional token revocation options.
    /// </summary>
    public class SignOutForm
    {
        /// <summary>
        /// Specific refresh token to revoke. Required when RevokeAllTokens is false.
        /// </summary>
        public string? RefreshToken { get; set; }

        /// <summary>
        /// Indicates whether to revoke all tokens for the user. When true, RefreshToken is not required.
        /// </summary>
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